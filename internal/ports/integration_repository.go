package ports

import (
	"context"

	"archie-core-shopify-layer/internal/domain"
)

// IntegrationRepository defines the interface for integration persistence
type IntegrationRepository interface {
	// Create creates a new integration and returns it
	Create(ctx context.Context, integration *domain.Integration) error

	// GetByKey retrieves an integration by its key
	GetByKey(ctx context.Context, key string) (*domain.Integration, error)

	// GetByProjectAndShop retrieves an integration by project ID, environment, and shop domain
	GetByProjectAndShop(ctx context.Context, projectID, environment, shopDomain string) (*domain.Integration, error)

	// Delete deletes an integration by key
	Delete(ctx context.Context, key string) error
}

