package application

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"

	"archie-core-shopify-layer/internal/domain"
	"archie-core-shopify-layer/internal/ports"

	"github.com/rs/zerolog"
)

// IntegrationService handles integration key management
type IntegrationService struct {
	integrationRepo ports.IntegrationRepository
	logger          zerolog.Logger
}

// NewIntegrationService creates a new integration service
func NewIntegrationService(
	integrationRepo ports.IntegrationRepository,
	logger zerolog.Logger,
) *IntegrationService {
	return &IntegrationService{
		integrationRepo: integrationRepo,
		logger:          logger,
	}
}

// CreateIntegrationInput represents input for creating an integration
type CreateIntegrationInput struct {
	ProjectID   string
	Environment string
	ShopDomain  string
}

// CreateIntegration creates a new integration key for a project/environment/shop combination
func (s *IntegrationService) CreateIntegration(ctx context.Context, input CreateIntegrationInput) (*domain.Integration, error) {
	// Check if integration already exists
	existing, err := s.integrationRepo.GetByProjectAndShop(ctx, input.ProjectID, input.Environment, input.ShopDomain)
	if err != nil {
		return nil, fmt.Errorf("failed to check existing integration: %w", err)
	}

	if existing != nil {
		// Return existing integration
		s.logger.Info().
			Str("projectID", input.ProjectID).
			Str("environment", input.Environment).
			Str("shopDomain", input.ShopDomain).
			Str("key", existing.Key).
			Msg("Integration already exists, returning existing key")
		return existing, nil
	}

	// Generate unique integration key (32 bytes = 64 hex characters)
	keyBytes := make([]byte, 32)
	if _, err := rand.Read(keyBytes); err != nil {
		return nil, fmt.Errorf("failed to generate integration key: %w", err)
	}
	key := hex.EncodeToString(keyBytes)

	// Create integration
	integration := &domain.Integration{
		Key:         key,
		ProjectID:   input.ProjectID,
		Environment: input.Environment,
		ShopDomain:  input.ShopDomain,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}

	if err := s.integrationRepo.Create(ctx, integration); err != nil {
		s.logger.Error().Err(err).Msg("Failed to create integration")
		return nil, fmt.Errorf("failed to create integration: %w", err)
	}

	s.logger.Info().
		Str("projectID", input.ProjectID).
		Str("environment", input.Environment).
		Str("shopDomain", input.ShopDomain).
		Str("key", key).
		Msg("Created new integration")

	return integration, nil
}

// GetIntegrationByKey retrieves an integration by its key
func (s *IntegrationService) GetIntegrationByKey(ctx context.Context, key string) (*domain.Integration, error) {
	integration, err := s.integrationRepo.GetByKey(ctx, key)
	if err != nil {
		return nil, fmt.Errorf("failed to get integration: %w", err)
	}

	if integration == nil {
		return nil, fmt.Errorf("integration not found")
	}

	return integration, nil
}

// DeleteIntegration deletes an integration by key
func (s *IntegrationService) DeleteIntegration(ctx context.Context, key string) error {
	err := s.integrationRepo.Delete(ctx, key)
	if err != nil {
		return fmt.Errorf("failed to delete integration: %w", err)
	}

	s.logger.Info().Str("key", key).Msg("Deleted integration")
	return nil
}

