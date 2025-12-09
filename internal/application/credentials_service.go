package application

import (
	"context"
	"fmt"

	"archie-core-shopify-layer/internal/domain"
	"archie-core-shopify-layer/internal/ports"

	"github.com/rs/zerolog"
)

// CredentialsService handles Shopify credentials management
type CredentialsService struct {
	configRepo     ports.ShopifyConfigRepository
	encryptionSvc  ports.EncryptionService
	logger         zerolog.Logger
	webhookBaseURL string
}

// NewCredentialsService creates a new credentials service
func NewCredentialsService(
	configRepo ports.ShopifyConfigRepository,
	encryptionService ports.EncryptionService,
	logger zerolog.Logger,
	webhookBaseURL string,
) *CredentialsService {
	return &CredentialsService{
		configRepo:     configRepo,
		encryptionSvc:  encryptionService,
		logger:         logger,
		webhookBaseURL: webhookBaseURL,
	}
}

// ConfigureShopifyInput represents the input for configuration
type ConfigureShopifyInput struct {
	APIKey        string
	APISecret     string
	WebhookSecret string
}

// ConfigureShopify configures Shopify for a project and environment
// tenantID is actually projectID in this context
func (s *CredentialsService) ConfigureShopify(ctx context.Context, tenantID string, input *ConfigureShopifyInput) (*domain.ShopifyConfig, error) {
	// Extract projectID and environment from context (type-safe)
	projectID := domain.GetProjectIDFromContext(ctx)
	environment := domain.GetEnvironmentFromContext(ctx)

	if projectID == "" {
		projectID = tenantID // Fallback
	}
	if environment == "" {
		environment = domain.DefaultEnvironment // Default
	}

	// Encrypt API secret
	encryptedSecret, err := s.encryptionSvc.Encrypt(input.APISecret)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt API secret: %w", err)
	}

	// Generate webhook URL
	webhookURL := fmt.Sprintf("%s/webhooks/shopify/%s/%s", s.webhookBaseURL, projectID, environment)

	// Check if config exists
	existing, err := s.configRepo.GetByTenantID(ctx, projectID)
	if err != nil {
		return nil, err
	}

	// Create configuration using domain constructor with validation
	config, err := domain.NewShopifyConfig(
		projectID,
		environment,
		encryptedSecret,
		input.APIKey,
		input.WebhookSecret,
		webhookURL,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create ShopifyConfig: %w", err)
	}

	if existing != nil {
		// Update existing
		config.ID = existing.ID
		config.CreatedAt = existing.CreatedAt
		if err := config.Update(encryptedSecret, input.APIKey, input.WebhookSecret, webhookURL); err != nil {
			return nil, fmt.Errorf("failed to update ShopifyConfig: %w", err)
		}
		if err := s.configRepo.Update(ctx, projectID, config); err != nil {
			return nil, err
		}
	} else {
		// Create new
		if err := s.configRepo.Create(ctx, config); err != nil {
			return nil, err
		}
	}

	s.logger.Info().Str("projectId", projectID).Str("environment", environment).Msg("Shopify configuration saved successfully")
	return config, nil
}

// GetConfig retrieves the Shopify configuration for a project and environment
func (s *CredentialsService) GetConfig(ctx context.Context, tenantID string) (*domain.ShopifyConfig, error) {
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

// SaveCredentials saves Shopify API credentials (deprecated - use ConfigureShopify instead)
func (s *CredentialsService) SaveCredentials(ctx context.Context, projectID string, environment string, apiKey string, apiSecret string) (*domain.ShopifyCredentials, error) {
	input := &ConfigureShopifyInput{
		APIKey:        apiKey,
		APISecret:     apiSecret,
		WebhookSecret: "",
	}

	config, err := s.ConfigureShopify(ctx, projectID, input)
	if err != nil {
		return nil, err
	}

	// Convert to legacy format for backward compatibility
	return &domain.ShopifyCredentials{
		ID:          config.ID,
		ProjectID:   config.ProjectID,
		Environment: config.Environment,
		APIKey:      config.APIKey,
		APISecret:   config.EncryptedKey, // Return encrypted version
		CreatedAt:   config.CreatedAt,
		UpdatedAt:   config.UpdatedAt,
	}, nil
}

// DeleteConfig deletes the Shopify configuration for a project and environment
func (s *CredentialsService) DeleteConfig(ctx context.Context, tenantID string) error {
	// Extract projectID and environment from context (type-safe)
	projectID := domain.GetProjectIDFromContext(ctx)
	environment := domain.GetEnvironmentFromContext(ctx)

	if projectID == "" {
		projectID = tenantID // Fallback
	}
	if environment == "" {
		environment = domain.DefaultEnvironment // Default
	}

	// Check if config exists
	config, err := s.configRepo.GetByTenantID(ctx, projectID)
	if err != nil {
		return err
	}
	if config == nil {
		return fmt.Errorf("shopify not configured for project %s and environment %s", projectID, environment)
	}

	// Delete configuration
	if err := s.configRepo.Delete(ctx, projectID); err != nil {
		s.logger.Error().Err(err).Str("projectId", projectID).Str("environment", environment).Msg("Failed to delete Shopify configuration")
		return fmt.Errorf("failed to delete Shopify configuration: %w", err)
	}

	s.logger.Info().Str("projectId", projectID).Str("environment", environment).Msg("Shopify configuration deleted successfully")
	return nil
}

// GetCredentials retrieves credentials (deprecated - use GetConfig instead)
func (s *CredentialsService) GetCredentials(ctx context.Context, projectID string, environment string) (*domain.ShopifyCredentials, error) {
	config, err := s.GetConfig(ctx, projectID)
	if err != nil {
		return nil, err
	}

	// Convert to legacy format
	return &domain.ShopifyCredentials{
		ID:          config.ID,
		ProjectID:   config.ProjectID,
		Environment: config.Environment,
		APIKey:      config.APIKey,
		APISecret:   config.EncryptedKey,
		CreatedAt:   config.CreatedAt,
		UpdatedAt:   config.UpdatedAt,
	}, nil
}
