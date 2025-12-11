package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"time"

	"archie-core-shopify-layer/graph"
	"archie-core-shopify-layer/graph/generated"
	"archie-core-shopify-layer/internal/application"
	"archie-core-shopify-layer/internal/application/webhook_handlers"
	"archie-core-shopify-layer/internal/domain"
	apiinfra "archie-core-shopify-layer/internal/infrastructure/api"
	"archie-core-shopify-layer/internal/infrastructure/encryption"
	"archie-core-shopify-layer/internal/infrastructure/pubsub"
	"archie-core-shopify-layer/internal/infrastructure/repository"
	shopifyinfra "archie-core-shopify-layer/internal/infrastructure/shopify"

	"github.com/99designs/gqlgen/graphql/handler"
	"github.com/99designs/gqlgen/graphql/playground"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"
	"github.com/joho/godotenv"
	"github.com/rs/zerolog"
	httpSwagger "github.com/swaggo/http-swagger"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"

	securitymiddleware "archie-core-shopify-layer/internal/infrastructure/middleware"
)

// contextKey is a type for context keys to avoid collisions
type contextKey string

const oauthSessionKey contextKey = "oauth_session"

func main() {
	// Initialize logger
	logger := zerolog.New(os.Stdout).With().Timestamp().Logger()
	if err := godotenv.Load(); err != nil {
		logger.Warn().Msg("⚠️  Warning: .env file not found")
	}

	// Get configuration from environment
	mongoURI := os.Getenv("MONGODB_URI")
	if mongoURI == "" {
		mongoURI = "mongodb://localhost:27017"
	}

	appURL := os.Getenv("APP_URL")
	if appURL == "" {
		appURL = "http://localhost:8080"
	}

	// Connect to MongoDB
	client, err := mongo.Connect(context.Background(), options.Client().ApplyURI(mongoURI))
	if err != nil {
		logger.Fatal().Err(err).Msg("Failed to connect to MongoDB")
	}
	defer client.Disconnect(context.Background())

	db := client.Database(os.Getenv("MONGODB_DATABASE"))

	// Get encryption key
	encryptionKey := os.Getenv("ENCRYPTION_KEY")
	if encryptionKey == "" {
		logger.Fatal().Msg("ENCRYPTION_KEY environment variable is required")
	}

	// Initialize infrastructure (implementations)
	encryptionService, err := encryption.NewService(encryptionKey)
	if err != nil {
		logger.Fatal().Err(err).Msg("Failed to initialize encryption service")
	}

	// Initialize repositories
	repo := repository.NewMongoRepository(db)
	sessionRepo := repository.NewSessionRepository(db)
	configRepo := repository.NewMongoShopifyConfigRepository(db)
	webhookSubscriptionRepo := repository.NewMongoWebhookSubscriptionRepository(db)
	integrationRepo := repository.NewMongoIntegrationRepository(db)

	// Initialize rate limiter and retry config for Shopify API
	rateLimiter := shopifyinfra.NewRateLimiter(logger)
	retryConfig := shopifyinfra.DefaultRetryConfig()

	// Initialize client pool with rate limiting and retry
	clientPool := shopifyinfra.NewClientPoolWithOptions(logger, rateLimiter, retryConfig)

	// Initialize application services
	shopifyService := application.NewShopifyService(
		repo,
		configRepo,
		encryptionService,
		clientPool,
		logger,
		appURL,
	)

	credentialsService := application.NewCredentialsService(
		configRepo,
		encryptionService,
		logger,
		appURL,
	)

	integrationService := application.NewIntegrationService(
		integrationRepo,
		logger,
	)

	webhookManager := application.NewWebhookManager(
		shopifyService,
		logger,
		appURL+"/webhooks/shopify",
	)

	// Initialize webhook dispatcher and register handlers
	webhookDispatcher := application.NewWebhookDispatcher(logger)
	webhookDispatcher.RegisterHandler(webhook_handlers.NewOrderHandler(logger))
	webhookDispatcher.RegisterHandler(webhook_handlers.NewProductHandler(logger))
	webhookDispatcher.RegisterHandler(webhook_handlers.NewCustomerHandler(logger))
	webhookDispatcher.RegisterHandler(webhook_handlers.NewAppUninstalledHandler(logger, repo, webhookSubscriptionRepo, shopifyService))

	// Initialize webhook pub/sub for GraphQL subscriptions
	webhookPubSub := pubsub.NewWebhookPubSub(logger)

	// Create GraphQL resolver
	resolver := graph.NewResolver(shopifyService, credentialsService, webhookPubSub, sessionRepo, integrationService)

	// Create GraphQL executable schema
	execSchema := generated.NewExecutableSchema(generated.Config{
		Resolvers: resolver,
	})

	// Create GraphQL handler
	srv := handler.NewDefaultServer(execSchema)

	// Setup router
	r := chi.NewRouter()

	// Middleware
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(securitymiddleware.SecurityHeadersMiddleware())
	r.Use(securitymiddleware.InputValidationMiddleware(logger))
	r.Use(securitymiddleware.AuditLoggingMiddleware(logger))
	r.Use(cors.Handler(cors.Options{
		AllowedOrigins:   []string{"*"},
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"*"},
		AllowCredentials: true,
	}))

	// Add tenant ID middleware (extracts project ID and environment from headers)
	// This middleware supports both X-Project-ID (existing) and X-Integration-Key (new) authentication
	// This middleware will skip public routes like /health and /swagger/*
	r.Use(createTenantIDMiddleware(integrationService, logger))

	// Public routes (no tenant ID required)
	// Health check - must be public for monitoring
	r.Get("/health", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	})

	// Swagger documentation - public
	r.Get("/swagger/*", httpSwagger.Handler(
		httpSwagger.URL("/swagger/doc.json"), // The URL pointing to API definition
	))
	r.Get("/swagger/doc.json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		http.ServeFile(w, r, "./docs/swagger.json")
	})

	// Routes requiring tenant ID
	r.Handle("/", playground.Handler("GraphQL playground", "/query"))
	r.Handle("/query", srv)

	// OAuth routes
	r.Get("/auth/shopify", oauthInitHandler(sessionRepo, shopifyService, appURL, logger))
	r.Get("/auth/callback", oauthCallbackHandler(sessionRepo, shopifyService, webhookManager, integrationService, logger))

	// Webhook endpoint: POST /webhooks/shopify/{projectId}/{environment}
	r.Post("/webhooks/shopify/{projectId}/{environment}", webhookHandler(shopifyService, webhookDispatcher, webhookPubSub, logger))

	// REST API Proxy: /api/v1/{project}/{environment}/shopify/*
	// Note: project and environment are extracted from headers by middleware
	restProxy := apiinfra.NewRESTProxy(shopifyService, logger)
	r.HandleFunc("/api/v1/{project}/{environment}/shopify/*", restProxy.HandleProxyRequest)
	r.HandleFunc("/api/v1/shopify/*", restProxy.HandleProxyRequest)

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	logger.Info().Str("port", port).Msg("Starting API server")
	logger.Info().Msg("GraphQL Playground available at http://localhost:" + port + "/")
	logger.Info().Msg("Swagger documentation available at http://localhost:" + port + "/swagger/index.html")
	if err := http.ListenAndServe(":"+port, r); err != nil {
		logger.Fatal().Err(err).Msg("Failed to start server")
	}
}

// oauthInitHandler initiates the OAuth flow
func oauthInitHandler(sessionRepo *repository.SessionRepository, shopifyService *application.ShopifyService, appURL string, logger zerolog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		shop := r.URL.Query().Get("shop")
		if shop == "" {
			http.Error(w, "shop parameter is required", http.StatusBadRequest)
			return
		}

		// Get config to retrieve API key
		config, err := shopifyService.GetConfig(ctx, "")
		if err != nil {
			logger.Error().Err(err).Msg("Failed to get Shopify config")
			http.Error(w, "Shopify not configured for this project", http.StatusNotFound)
			return
		}

		// Generate random state for CSRF protection
		stateBytes := make([]byte, 16)
		if _, err := rand.Read(stateBytes); err != nil {
			logger.Error().Err(err).Msg("Failed to generate state")
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}
		state := hex.EncodeToString(stateBytes)

		// Extract project ID and environment from context (set by middleware)
		projectID := domain.GetProjectIDFromContext(ctx)
		environment := domain.GetEnvironmentFromContext(ctx)
		if projectID == "" {
			projectID = "default-project" // Fallback
		}
		if environment == "" {
			environment = domain.DefaultEnvironment
		}

		// Get return URL from query parameter (default to frontend URL if not provided)
		returnURL := r.URL.Query().Get("return_url")
		if returnURL == "" {
			returnURL = "http://localhost:5173" // Default frontend URL
		}

		// Save session with project ID, environment, and return URL
		session := &domain.Session{
			Shop:        shop,
			State:       state,
			Scopes:      []string{"read_products", "write_products", "read_orders", "write_orders"},
			ProjectID:   projectID,
			Environment: environment,
			ReturnURL:   returnURL,
			ExpiresAt:   time.Now().Add(10 * time.Minute),
		}

		if err := sessionRepo.CreateSession(ctx, session); err != nil {
			logger.Error().Err(err).Msg("Failed to create session")
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		// Build authorization URL using API key from config
		scopes := "read_products,write_products,read_orders,write_orders"
		redirectURI := appURL + "/auth/callback"
		authURL := fmt.Sprintf(
			"https://%s/admin/oauth/authorize?client_id=%s&scope=%s&redirect_uri=%s&state=%s",
			shop,
			config.APIKey,
			url.QueryEscape(scopes),
			url.QueryEscape(redirectURI),
			state,
		)

		http.Redirect(w, r, authURL, http.StatusFound)
	}
}

// oauthCallbackHandler handles the OAuth callback
func oauthCallbackHandler(
	sessionRepo *repository.SessionRepository,
	shopifyService *application.ShopifyService,
	webhookManager *application.WebhookManager,
	integrationService *application.IntegrationService,
	logger zerolog.Logger,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		// Get parameters
		shop := r.URL.Query().Get("shop")
		code := r.URL.Query().Get("code")
		state := r.URL.Query().Get("state")

		if shop == "" || code == "" || state == "" {
			http.Error(w, "Missing required parameters", http.StatusBadRequest)
			return
		}

		// Verify state and get session first (before getting config)
		session, err := sessionRepo.GetSession(ctx, state)
		if err != nil {
			logger.Error().Err(err).Msg("Failed to get session")
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		if session == nil || session.Shop != shop {
			http.Error(w, "Invalid session", http.StatusUnauthorized)
			return
		}

		// Extract project ID and environment from session (set during OAuth initiation)
		projectID := session.ProjectID
		environment := session.Environment
		if projectID == "" {
			projectID = "default-project" // Fallback
		}
		if environment == "" {
			environment = domain.DefaultEnvironment
		}

		// Set project ID and environment in context for downstream handlers
		ctx = domain.WithProjectID(ctx, projectID)
		ctx = domain.WithEnvironment(ctx, environment)
		ctx = domain.WithTenantID(ctx, projectID)

		// Store session in context so ExchangeToken can access scopes
		ctx = context.WithValue(ctx, oauthSessionKey, session)

		// Verify HMAC using API secret from config
		// Note: We need to decrypt the secret for HMAC verification
		// For now, we'll skip HMAC verification in OAuth callback
		// In production, add a method to get decrypted secret from service
		// TODO: Implement proper HMAC verification with decrypted secret
		// Get config to retrieve API secret for HMAC verification (now with correct tenant ID)
		_, err = shopifyService.GetConfig(ctx, projectID)
		if err != nil {
			logger.Error().Err(err).Str("projectID", projectID).Msg("Failed to get Shopify config")
			http.Error(w, "Shopify not configured for this project", http.StatusNotFound)
			return
		}

		// Delete session (but keep it in context for ExchangeToken)
		sessionRepo.DeleteSession(ctx, state)

		// Log requested scopes for debugging
		logger.Info().
			Str("shop", shop).
			Strs("requested_scopes", session.Scopes).
			Msg("Exchanging OAuth token - requested scopes")

		// Exchange token
		shopDomain, err := shopifyService.ExchangeToken(ctx, shop, code)
		if err != nil {
			logger.Error().Err(err).Msg("Failed to exchange token")
			http.Error(w, "Failed to complete installation", http.StatusInternalServerError)
			return
		}

		// Log what scopes were stored (note: these are requested, not necessarily granted)
		logger.Info().
			Str("shop", shop).
			Strs("stored_scopes", shopDomain.Scopes).
			Msg("OAuth token exchange completed - scopes stored")

		// Subscribe to webhooks
		topics := webhookManager.GetDefaultTopics()
		// Note: We would need the access token here to subscribe to webhooks
		// This is a placeholder for now
		logger.Info().
			Str("shop", shop).
			Interface("topics", topics).
			Msg("Would subscribe to webhooks")

		// Redirect back to frontend with success status
		returnURL := session.ReturnURL
		if returnURL == "" {
			// Fallback to default frontend URL
			returnURL = "http://localhost:5173"
		}

		// Create integration key for this project/environment/shop combination
		integration, err := integrationService.CreateIntegration(ctx, application.CreateIntegrationInput{
			ProjectID:   projectID,
			Environment: environment,
			ShopDomain:  shopDomain.Domain,
		})
		if err != nil {
			logger.Error().Err(err).Msg("Failed to create integration after OAuth")
			// Don't fail the OAuth flow if integration creation fails
		} else {
			logger.Info().
				Str("projectID", projectID).
				Str("environment", environment).
				Str("shopDomain", shopDomain.Domain).
				Str("integrationKey", integration.Key).
				Msg("Created integration after successful OAuth")
		}

		// Add success parameters to return URL
		redirectURL := fmt.Sprintf("%s?shopify_oauth=success&shop=%s&domain=%s",
			returnURL,
			url.QueryEscape(shop),
			url.QueryEscape(shopDomain.Domain),
		)
		if integration != nil {
			redirectURL += "&integration_key=" + url.QueryEscape(integration.Key)
		}

		logger.Info().
			Str("shop", shop).
			Str("returnURL", redirectURL).
			Msg("Redirecting to frontend after successful OAuth")

		http.Redirect(w, r, redirectURL, http.StatusFound)
	}
}

// webhookHandler handles Shopify webhook requests
func webhookHandler(
	shopifyService *application.ShopifyService,
	webhookDispatcher *application.WebhookDispatcher,
	webhookPubSub *pubsub.WebhookPubSub,
	logger zerolog.Logger,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		// Extract project ID and environment from URL
		projectID := chi.URLParam(r, "projectId")
		environment := chi.URLParam(r, "environment")

		if projectID == "" {
			http.Error(w, "projectId is required", http.StatusBadRequest)
			return
		}
		if environment == "" {
			environment = domain.DefaultEnvironment // Default
		}

		// Add to context (type-safe)
		ctx = domain.WithProjectID(ctx, projectID)
		ctx = domain.WithEnvironment(ctx, environment)

		// Get Shopify configuration to retrieve webhook secret
		config, err := shopifyService.GetConfig(ctx, projectID)
		if err != nil {
			logger.Error().Err(err).Str("projectId", projectID).Msg("Failed to get Shopify config")
			http.Error(w, "Shopify not configured for this project", http.StatusNotFound)
			return
		}

		// Get webhook secret from config
		webhookSecret := config.WebhookSecret
		if webhookSecret == "" {
			logger.Warn().Str("projectId", projectID).Msg("Webhook secret not configured")
			http.Error(w, "Webhook secret not configured", http.StatusBadRequest)
			return
		}

		// Get webhook topic from header
		topic := r.Header.Get("X-Shopify-Topic")
		if topic == "" {
			logger.Warn().Msg("Missing X-Shopify-Topic header")
			http.Error(w, "Missing X-Shopify-Topic header", http.StatusBadRequest)
			return
		}

		// Read request body
		payload, err := io.ReadAll(r.Body)
		if err != nil {
			logger.Error().Err(err).Msg("Failed to read webhook payload")
			http.Error(w, "Failed to read request body", http.StatusBadRequest)
			return
		}
		defer r.Body.Close()

		// Verify webhook signature
		hmacHeader := r.Header.Get("X-Shopify-Hmac-SHA256")
		webhookVerifier := shopifyinfra.NewWebhookVerifier(webhookSecret)
		if err := webhookVerifier.Verify(payload, hmacHeader); err != nil {
			logger.Warn().Err(err).Str("projectId", projectID).Msg("Webhook signature verification failed")
			http.Error(w, "Invalid signature", http.StatusUnauthorized)
			return
		}

		// Extract shop domain from webhook payload
		var webhookData map[string]interface{}
		shop := ""
		if err := json.Unmarshal(payload, &webhookData); err == nil {
			if domain, ok := webhookData["domain"].(string); ok {
				shop = domain
			} else if shopData, ok := webhookData["shop_domain"].(string); ok {
				shop = shopData
			}
		}
		// Fallback: try to extract from X-Shopify-Shop-Domain header
		if shop == "" {
			shop = r.Header.Get("X-Shopify-Shop-Domain")
		}

		// Process webhook event using dispatcher
		event := &domain.WebhookEvent{
			Topic:    topic,
			Shop:     shop,
			Payload:  payload,
			Verified: true,
		}

		// Log webhook event first
		if err := shopifyService.ProcessWebhook(ctx, topic, shop, payload, true); err != nil {
			logger.Error().Err(err).Msg("Failed to log webhook event")
			// Continue processing even if logging fails
		}

		// Publish to pub/sub for GraphQL subscriptions
		webhookPubSub.Publish(event)

		// Dispatch to handlers
		if err := webhookDispatcher.Dispatch(ctx, event); err != nil {
			logger.Error().
				Err(err).
				Str("topic", topic).
				Str("projectId", projectID).
				Msg("Failed to dispatch webhook event")

			// Return 500 to trigger Shopify retry
			http.Error(w, "Failed to process webhook event", http.StatusInternalServerError)
			return
		}

		// Return success
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{
			"received": "true",
		})
	}
}

// createTenantIDMiddleware creates middleware that supports both X-Project-ID and X-Integration-Key authentication
func createTenantIDMiddleware(integrationService *application.IntegrationService, logger zerolog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Skip middleware for public routes and OAuth routes
			path := r.URL.Path
			if path == "/health" ||
				path == "/swagger/doc.json" ||
				path == "/auth/callback" ||
				(len(path) > 8 && path[:9] == "/swagger/") {
				next.ServeHTTP(w, r)
				return
			}

			ctx := r.Context()
			var projectID, environment string

			// Check for integration key first (new method)
			integrationKey := r.Header.Get("X-Integration-Key")
			if integrationKey != "" {
				integration, err := integrationService.GetIntegrationByKey(ctx, integrationKey)
				if err != nil {
					logger.Error().Err(err).Str("key", integrationKey).Msg("Failed to get integration by key")
					http.Error(w, "Invalid integration key", http.StatusUnauthorized)
					return
				}

				projectID = integration.ProjectID
				environment = integration.Environment

				logger.Debug().
					Str("integrationKey", integrationKey).
					Str("projectID", projectID).
					Str("environment", environment).
					Str("shopDomain", integration.ShopDomain).
					Msg("Authenticated using integration key")
			} else {
				// Fallback to X-Project-ID (existing method)
				projectID = r.Header.Get("X-Project-ID")
				if projectID == "" {
					http.Error(w, "X-Project-ID or X-Integration-Key header is required", http.StatusBadRequest)
					return
				}

				// Extract environment from header (defaults to "master" if not provided)
				environment = r.Header.Get("environment")
				if environment == "" {
					environment = domain.DefaultEnvironment // Default environment
				}
			}

			// Add to context (type-safe)
			ctx = domain.WithProjectID(ctx, projectID)
			ctx = domain.WithEnvironment(ctx, environment)
			// Keep tenantId for backward compatibility (using projectID)
			ctx = domain.WithTenantID(ctx, projectID)

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
