package application

import (
	"context"
	"fmt"
	"os"
	"strings"

	"archie-core-shopify-layer/internal/domain"
	"archie-core-shopify-layer/internal/ports"

	goshopify "github.com/bold-commerce/go-shopify/v4"
	"github.com/rs/zerolog"
)

// ShopifyService implements the application business logic
// It depends on ports (interfaces) not concrete implementations
type ShopifyService struct {
	repository     ports.Repository
	configRepo     ports.ShopifyConfigRepository
	encryptionSvc  ports.EncryptionService
	clientPool     ports.ShopifyClientPool
	logger         zerolog.Logger
	webhookBaseURL string
	validateTokens bool // Feature flag for token validation
}

// NewShopifyService creates a new Shopify application service
func NewShopifyService(
	repository ports.Repository,
	configRepo ports.ShopifyConfigRepository,
	encryptionSvc ports.EncryptionService,
	clientPool ports.ShopifyClientPool,
	logger zerolog.Logger,
	webhookBaseURL string,
) *ShopifyService {
	return &ShopifyService{
		repository:     repository,
		configRepo:     configRepo,
		encryptionSvc:  encryptionSvc,
		clientPool:     clientPool,
		logger:         logger,
		webhookBaseURL: webhookBaseURL,
		validateTokens: true, // Enable token validation by default
	}
}

// NewShopifyServiceWithOptions creates a new Shopify application service with options
func NewShopifyServiceWithOptions(
	repository ports.Repository,
	configRepo ports.ShopifyConfigRepository,
	encryptionSvc ports.EncryptionService,
	clientPool ports.ShopifyClientPool,
	logger zerolog.Logger,
	webhookBaseURL string,
	validateTokens bool,
) *ShopifyService {
	return &ShopifyService{
		repository:     repository,
		configRepo:     configRepo,
		encryptionSvc:  encryptionSvc,
		clientPool:     clientPool,
		logger:         logger,
		webhookBaseURL: webhookBaseURL,
		validateTokens: validateTokens,
	}
}

// GetClientForTenant retrieves a Shopify client for a project and environment
// tenantID is actually projectID in this context
func (s *ShopifyService) GetClientForTenant(ctx context.Context, tenantID string) (ports.ShopifyClient, error) {
	// Extract projectID and environment from context (type-safe)
	projectID := domain.GetProjectIDFromContext(ctx)
	environment := domain.GetEnvironmentFromContext(ctx)

	if projectID == "" {
		projectID = tenantID // Fallback
	}
	if environment == "" {
		environment = domain.DefaultEnvironment // Default
	}

	config, err := s.configRepo.GetByTenantID(ctx, projectID)
	if err != nil {
		return nil, err
	}
	if config == nil {
		return nil, fmt.Errorf("shopify not configured for project %s and environment %s", projectID, environment)
	}

	// Decrypt API secret
	apiSecret, err := s.encryptionSvc.Decrypt(config.EncryptedKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt API secret: %w", err)
	}

	// Get client from pool using projectID-environment as key
	return s.clientPool.GetClient(ctx, projectID+"-"+environment, config.APIKey, apiSecret)
}

// GetConfig retrieves the Shopify configuration for a project and environment
func (s *ShopifyService) GetConfig(ctx context.Context, tenantID string) (*domain.ShopifyConfig, error) {
	// Extract projectID and environment from context (type-safe)
	projectID := domain.GetProjectIDFromContext(ctx)
	environment := domain.GetEnvironmentFromContext(ctx)

	if projectID == "" {
		projectID = tenantID // Fallback
	}
	if environment == "" {
		environment = domain.DefaultEnvironment // Default
	}

	config, err := s.configRepo.GetByTenantID(ctx, projectID)
	if err != nil {
		return nil, err
	}
	if config == nil {
		return nil, fmt.Errorf("shopify not configured for project %s and environment %s", projectID, environment)
	}

	return config, nil
}

// GenerateAuthURL generates the OAuth authorization URL
// This method supports:
// 1. Provided credentials (apiKey/apiSecret parameters) - highest priority
// 2. Project-specific config from database
// 3. Global environment variables (SHOPIFY_API_KEY/SHOPIFY_API_SECRET) - fallback
func (s *ShopifyService) GenerateAuthURL(ctx context.Context, shop string, scopes []string, state string, apiKey, apiSecret *string) (string, error) {
	var client ports.ShopifyClient
	var err error

	// Priority 1: Use provided credentials if available (from archie-core-engine config)
	if apiKey != nil && apiSecret != nil && *apiKey != "" && *apiSecret != "" {
		s.logger.Info().
			Msg("Using provided API credentials for OAuth URL generation")
		client, err = s.clientPool.GetClient(ctx, "provided-oauth", *apiKey, *apiSecret)
		if err != nil {
			return "", fmt.Errorf("failed to create client with provided credentials: %w", err)
		}
	} else {
		// Priority 2: Try to get project-specific client from database
		client, err = s.GetClientForTenant(ctx, "")
		if err != nil {
			// Priority 3: Fall back to global environment variables
			s.logger.Info().
				Msg("No project-specific Shopify config found, falling back to global environment variables")

			globalAPIKey := os.Getenv("SHOPIFY_API_KEY")
			globalAPISecret := os.Getenv("SHOPIFY_API_SECRET")

			if globalAPIKey == "" || globalAPISecret == "" {
				return "", fmt.Errorf("shopify not configured: no project config, no provided credentials, and global SHOPIFY_API_KEY/SHOPIFY_API_SECRET not set")
			}

			// Create a temporary client with global credentials for OAuth URL generation
			client, err = s.clientPool.GetClient(ctx, "global-oauth", globalAPIKey, globalAPISecret)
			if err != nil {
				return "", fmt.Errorf("failed to create client with global credentials: %w", err)
			}

			s.logger.Info().
				Msg("Using global Shopify API credentials for OAuth URL generation")
		} else {
			s.logger.Info().
				Msg("Using project-specific Shopify config for OAuth URL generation")
		}
	}

	// Log requested scopes
	s.logger.Info().
		Str("shop", shop).
		Strs("requested_scopes", scopes).
		Msg("Generating OAuth URL with scopes")

	// Construct redirect URI from webhookBaseURL (which is APP_URL)
	// Remove /webhooks/shopify suffix if present
	appURL := strings.TrimSuffix(s.webhookBaseURL, "/webhooks/shopify")
	redirectURI := appURL + "/auth/callback"

	authURL, err := client.GenerateAuthURL(shop, scopes, redirectURI, state)
	if err != nil {
		s.logger.Error().Err(err).Str("shop", shop).Msg("Failed to generate auth URL")
		return "", fmt.Errorf("failed to generate auth URL: %w", err)
	}

	s.logger.Info().
		Str("shop", shop).
		Str("auth_url", authURL).
		Msg("Generated OAuth authorization URL")

	return authURL, nil
}

// ExchangeToken exchanges the authorization code for an access token
// This method supports:
// 1. Provided credentials (apiKey/apiSecret parameters) - highest priority
// 2. Project-specific config from database
// 3. Global environment variables (SHOPIFY_API_KEY/SHOPIFY_API_SECRET) - fallback
func (s *ShopifyService) ExchangeToken(ctx context.Context, shop string, code string, apiKey, apiSecret *string) (*domain.Shop, error) {
	var client ports.ShopifyClient
	var err error

	// Priority 1: Use provided credentials if available (from archie-core-engine config)
	if apiKey != nil && apiSecret != nil && *apiKey != "" && *apiSecret != "" {
		s.logger.Info().
			Msg("Using provided API credentials for token exchange")
		client, err = s.clientPool.GetClient(ctx, "provided-oauth", *apiKey, *apiSecret)
		if err != nil {
			return nil, fmt.Errorf("failed to create client with provided credentials: %w", err)
		}
	} else {
		// Priority 2: Try to get project-specific client from database
		client, err = s.GetClientForTenant(ctx, "")
		if err != nil {
			// Priority 3: Fall back to global environment variables
			s.logger.Info().
				Msg("No project-specific Shopify config found for token exchange, falling back to global environment variables")

			globalAPIKey := os.Getenv("SHOPIFY_API_KEY")
			globalAPISecret := os.Getenv("SHOPIFY_API_SECRET")

			if globalAPIKey == "" || globalAPISecret == "" {
				return nil, fmt.Errorf("shopify not configured: no project config, no provided credentials, and global SHOPIFY_API_KEY/SHOPIFY_API_SECRET not set")
			}

			// Create a temporary client with global credentials for token exchange
			client, err = s.clientPool.GetClient(ctx, "global-oauth", globalAPIKey, globalAPISecret)
			if err != nil {
				return nil, fmt.Errorf("failed to create client with global credentials: %w", err)
			}

			s.logger.Info().
				Msg("Using global Shopify API credentials for token exchange")
		} else {
			s.logger.Info().
				Msg("Using project-specific Shopify config for token exchange")
		}
	}

	// Exchange code for access token
	accessToken, err := client.ExchangeToken(ctx, shop, code)
	if err != nil {
		s.logger.Error().Err(err).Str("shop", shop).Msg("Failed to exchange token")
		return nil, fmt.Errorf("failed to exchange token: %w", err)
	}

	// Get shop information
	shopInfo, err := client.GetShop(ctx, shop, accessToken)
	if err != nil {
		s.logger.Error().Err(err).Str("shop", shop).Msg("Failed to get shop info")
		return nil, fmt.Errorf("failed to get shop info: %w", err)
	}

	// Encrypt access token before storage
	encryptedToken, err := s.encryptionSvc.Encrypt(accessToken)
	if err != nil {
		s.logger.Error().Err(err).Str("shop", shop).Msg("Failed to encrypt access token")
		return nil, fmt.Errorf("failed to encrypt access token: %w", err)
	}

	// Get scopes from session (they were stored during OAuth initiation)
	// Note: We use a type assertion with a custom type to avoid context key collisions
	type oauthSessionKeyType string
	const oauthSessionKey oauthSessionKeyType = "oauth_session"

	scopes := []string{}
	if session := ctx.Value(oauthSessionKey); session != nil {
		if s, ok := session.(*domain.Session); ok {
			scopes = s.Scopes
		}
	}

	// Create domain shop entity
	domainShop := &domain.Shop{
		Domain:      shopInfo.Domain,
		AccessToken: encryptedToken, // Store encrypted token
		Scopes:      scopes,         // Store scopes from OAuth session
	}

	// Save shop to repository
	if err := s.repository.SaveShop(ctx, domainShop); err != nil {
		s.logger.Error().Err(err).Str("shop", shop).Msg("Failed to save shop")
		return nil, fmt.Errorf("failed to save shop: %w", err)
	}

	return domainShop, nil
}

// GetShop retrieves shop information
func (s *ShopifyService) GetShop(ctx context.Context, domain string) (*domain.Shop, error) {
	shop, err := s.repository.GetShop(ctx, domain)
	if err != nil {
		s.logger.Error().Err(err).Str("domain", domain).Msg("Failed to get shop")
		return nil, fmt.Errorf("failed to get shop: %w", err)
	}

	if shop == nil {
		return nil, nil
	}

	// Decrypt access token
	if shop.AccessToken != "" {
		decryptedToken, err := s.encryptionSvc.Decrypt(shop.AccessToken)
		if err != nil {
			s.logger.Error().Err(err).Str("domain", domain).Msg("Failed to decrypt access token")
			return nil, fmt.Errorf("failed to decrypt access token: %w", err)
		}

		// Validate token if validation is enabled
		if s.validateTokens {
			if err := s.validateAccessToken(ctx, decryptedToken, domain); err != nil {
				s.logger.Warn().
					Err(err).
					Str("domain", domain).
					Msg("Access token validation failed")
				// Don't fail the request, but log the warning
				// The token might be temporarily invalid or there might be network issues
			}
		}

		// Return shop with decrypted token (for internal use only)
		// Note: This is a copy, the domain entity still has encrypted token
		shop.AccessToken = decryptedToken
	}

	return shop, nil
}

// ListShops retrieves all connected shops
func (s *ShopifyService) ListShops(ctx context.Context) ([]*domain.Shop, error) {
	shops, err := s.repository.ListShops(ctx)
	if err != nil {
		s.logger.Error().Err(err).Msg("Failed to list shops")
		return nil, fmt.Errorf("failed to list shops: %w", err)
	}

	// Decrypt access tokens for all shops (but don't return them in the response)
	// We decrypt to validate tokens, but the domain entities still have encrypted tokens
	for _, shop := range shops {
		if shop.AccessToken != "" {
			decryptedToken, err := s.encryptionSvc.Decrypt(shop.AccessToken)
			if err != nil {
				s.logger.Warn().Err(err).Str("domain", shop.Domain).Msg("Failed to decrypt access token for shop")
				continue
			}
			// Don't store decrypted token back - keep it encrypted in the entity
			// But we can validate it if needed
			if s.validateTokens {
				if err := s.validateAccessToken(ctx, decryptedToken, shop.Domain); err != nil {
					s.logger.Warn().
						Err(err).
						Str("domain", shop.Domain).
						Msg("Access token validation failed for shop")
				}
			}
		}
	}

	return shops, nil
}

// validateAccessToken validates an access token by making a lightweight API call to Shopify
func (s *ShopifyService) validateAccessToken(ctx context.Context, token string, shopDomain string) error {
	// Get client for tenant to make validation call
	client, err := s.GetClientForTenant(ctx, "")
	if err != nil {
		// If we can't get a client, skip validation (might be configuration issue)
		s.logger.Debug().
			Err(err).
			Str("shop", shopDomain).
			Msg("Skipping token validation: failed to get client")
		return nil
	}

	// Make a lightweight API call to verify token
	_, err = client.GetShop(ctx, shopDomain, token)
	if err != nil {
		// Check if error is authentication-related
		errStr := fmt.Sprintf("%v", err)
		if containsAny(errStr, []string{"401", "unauthorized", "authentication", "invalid token", "forbidden"}) {
			return fmt.Errorf("token validation failed: token is invalid or revoked: %w", err)
		}
		// Other errors (network, timeout) - log but don't fail
		s.logger.Debug().
			Err(err).
			Str("shop", shopDomain).
			Msg("Token validation encountered non-auth error (assuming token is valid)")
		return nil
	}

	// Token is valid
	return nil
}

// containsAny checks if a string contains any of the substrings (case-insensitive)
func containsAny(s string, substrings []string) bool {
	sLower := strings.ToLower(s)
	for _, substr := range substrings {
		if strings.Contains(sLower, strings.ToLower(substr)) {
			return true
		}
	}
	return false
}

// getDecryptedAccessToken retrieves and decrypts the access token for a shop
func (s *ShopifyService) getDecryptedAccessToken(ctx context.Context, domain string) (string, error) {
	shop, err := s.repository.GetShop(ctx, domain)
	if err != nil {
		return "", fmt.Errorf("failed to get shop: %w", err)
	}

	if shop == nil {
		return "", fmt.Errorf("shop not found: %s", domain)
	}

	if shop.AccessToken == "" {
		return "", fmt.Errorf("shop has no access token: %s", domain)
	}

	// Decrypt access token
	decryptedToken, err := s.encryptionSvc.Decrypt(shop.AccessToken)
	if err != nil {
		s.logger.Error().Err(err).Str("domain", domain).Msg("Failed to decrypt access token")
		return "", fmt.Errorf("failed to decrypt access token: %w", err)
	}

	return decryptedToken, nil
}

// GetProducts retrieves products for a shop
func (s *ShopifyService) GetProducts(ctx context.Context, domain string) ([]goshopify.Product, error) {
	// Get and decrypt access token
	accessToken, err := s.getDecryptedAccessToken(ctx, domain)
	if err != nil {
		return nil, err
	}

	// Get client for tenant
	client, err := s.GetClientForTenant(ctx, "")
	if err != nil {
		return nil, fmt.Errorf("failed to get client: %w", err)
	}

	// Get products from Shopify API
	products, err := client.GetProducts(ctx, domain, accessToken, nil)
	if err != nil {
		s.logger.Error().Err(err).Str("domain", domain).Msg("Failed to get products")
		return nil, fmt.Errorf("failed to get products: %w", err)
	}

	return products, nil
}

// GetProduct retrieves a single product by ID
func (s *ShopifyService) GetProduct(ctx context.Context, domain string, productID int64) (*goshopify.Product, error) {
	// Get and decrypt access token
	accessToken, err := s.getDecryptedAccessToken(ctx, domain)
	if err != nil {
		return nil, err
	}

	client, err := s.GetClientForTenant(ctx, "")
	if err != nil {
		return nil, fmt.Errorf("failed to get client: %w", err)
	}

	product, err := client.GetProduct(ctx, domain, accessToken, productID)
	if err != nil {
		s.logger.Error().Err(err).Str("domain", domain).Int64("productID", productID).Msg("Failed to get product")
		return nil, fmt.Errorf("failed to get product: %w", err)
	}

	return product, nil
}

// GetOrders retrieves orders for a shop
func (s *ShopifyService) GetOrders(ctx context.Context, domain string) ([]goshopify.Order, error) {
	// Get and decrypt access token
	accessToken, err := s.getDecryptedAccessToken(ctx, domain)
	if err != nil {
		return nil, err
	}

	client, err := s.GetClientForTenant(ctx, "")
	if err != nil {
		return nil, fmt.Errorf("failed to get client: %w", err)
	}

	orders, err := client.GetOrders(ctx, domain, accessToken, nil)
	if err != nil {
		s.logger.Error().Err(err).Str("domain", domain).Msg("Failed to get orders")
		return nil, fmt.Errorf("failed to get orders: %w", err)
	}

	return orders, nil
}

// GetOrder retrieves a single order by ID
func (s *ShopifyService) GetOrder(ctx context.Context, domain string, orderID int64) (*goshopify.Order, error) {
	// Get and decrypt access token
	accessToken, err := s.getDecryptedAccessToken(ctx, domain)
	if err != nil {
		return nil, err
	}

	client, err := s.GetClientForTenant(ctx, "")
	if err != nil {
		return nil, fmt.Errorf("failed to get client: %w", err)
	}

	order, err := client.GetOrder(ctx, domain, accessToken, orderID)
	if err != nil {
		s.logger.Error().Err(err).Str("domain", domain).Int64("orderID", orderID).Msg("Failed to get order")
		return nil, fmt.Errorf("failed to get order: %w", err)
	}

	return order, nil
}

// GetCustomers retrieves customers for a shop
func (s *ShopifyService) GetCustomers(ctx context.Context, domain string) ([]goshopify.Customer, error) {
	// Get and decrypt access token
	accessToken, err := s.getDecryptedAccessToken(ctx, domain)
	if err != nil {
		return nil, err
	}

	client, err := s.GetClientForTenant(ctx, "")
	if err != nil {
		return nil, fmt.Errorf("failed to get client: %w", err)
	}

	customers, err := client.GetCustomers(ctx, domain, accessToken, nil)
	if err != nil {
		s.logger.Error().Err(err).Str("domain", domain).Msg("Failed to get customers")
		return nil, fmt.Errorf("failed to get customers: %w", err)
	}

	return customers, nil
}

// GetCustomer retrieves a single customer by ID
func (s *ShopifyService) GetCustomer(ctx context.Context, domain string, customerID int64) (*goshopify.Customer, error) {
	// Get and decrypt access token
	accessToken, err := s.getDecryptedAccessToken(ctx, domain)
	if err != nil {
		return nil, err
	}

	client, err := s.GetClientForTenant(ctx, "")
	if err != nil {
		return nil, fmt.Errorf("failed to get client: %w", err)
	}

	customer, err := client.GetCustomer(ctx, domain, accessToken, customerID)
	if err != nil {
		s.logger.Error().Err(err).Str("domain", domain).Int64("customerID", customerID).Msg("Failed to get customer")
		return nil, fmt.Errorf("failed to get customer: %w", err)
	}

	return customer, nil
}

// SearchCustomers searches customers by query string
func (s *ShopifyService) SearchCustomers(ctx context.Context, domain string, query string) ([]goshopify.Customer, error) {
	// Get and decrypt access token
	accessToken, err := s.getDecryptedAccessToken(ctx, domain)
	if err != nil {
		return nil, err
	}

	client, err := s.GetClientForTenant(ctx, "")
	if err != nil {
		return nil, fmt.Errorf("failed to get client: %w", err)
	}

	customers, err := client.SearchCustomers(ctx, domain, accessToken, query)
	if err != nil {
		s.logger.Error().Err(err).Str("domain", domain).Str("query", query).Msg("Failed to search customers")
		return nil, fmt.Errorf("failed to search customers: %w", err)
	}

	return customers, nil
}

// GetInventoryLevels retrieves inventory levels for a shop
func (s *ShopifyService) GetInventoryLevels(ctx context.Context, domain string) ([]goshopify.InventoryLevel, error) {
	// Get and decrypt access token
	accessToken, err := s.getDecryptedAccessToken(ctx, domain)
	if err != nil {
		return nil, err
	}

	client, err := s.GetClientForTenant(ctx, "")
	if err != nil {
		return nil, fmt.Errorf("failed to get client: %w", err)
	}

	levels, err := client.GetInventoryLevels(ctx, domain, accessToken, nil)
	if err != nil {
		s.logger.Error().Err(err).Str("domain", domain).Msg("Failed to get inventory levels")
		return nil, fmt.Errorf("failed to get inventory levels: %w", err)
	}

	return levels, nil
}

// ProcessWebhook processes a Shopify webhook event
func (s *ShopifyService) ProcessWebhook(ctx context.Context, topic string, shop string, payload []byte, verified bool) error {
	// Create webhook event
	event := &domain.WebhookEvent{
		Topic:    topic,
		Shop:     shop,
		Payload:  payload,
		Verified: verified,
	}

	// Log webhook to repository
	if err := s.repository.LogWebhook(ctx, event); err != nil {
		s.logger.Error().Err(err).Str("topic", topic).Str("shop", shop).Msg("Failed to log webhook")
		return fmt.Errorf("failed to log webhook: %w", err)
	}

	s.logger.Info().Str("topic", topic).Str("shop", shop).Bool("verified", verified).Msg("Webhook processed")
	return nil
}
