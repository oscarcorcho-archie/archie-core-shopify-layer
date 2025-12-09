package ports

import (
	"context"

	"archie-core-shopify-layer/internal/domain"
)

// ShopifyConfigRepository defines the interface for Shopify configuration persistence
type ShopifyConfigRepository interface {
	GetByTenantID(ctx context.Context, tenantID string) (*domain.ShopifyConfig, error)
	Create(ctx context.Context, config *domain.ShopifyConfig) error
	Update(ctx context.Context, tenantID string, config *domain.ShopifyConfig) error
	Delete(ctx context.Context, tenantID string) error
}

// WebhookSubscriptionRepository defines the interface for webhook subscription persistence
type WebhookSubscriptionRepository interface {
	SaveWebhookSubscription(ctx context.Context, subscription *domain.WebhookSubscription) error
	GetWebhookSubscription(ctx context.Context, projectID string, environment string, shopDomain string, topic string) (*domain.WebhookSubscription, error)
	ListWebhookSubscriptions(ctx context.Context, projectID string, environment string, shopDomain string) ([]*domain.WebhookSubscription, error)
	DeleteWebhookSubscription(ctx context.Context, subscriptionID string) error
}

// Repository defines the interface for persistence
// This is kept for backward compatibility but ShopifyConfigRepository should be used instead
type Repository interface {
	// Shop operations
	SaveShop(ctx context.Context, shop *domain.Shop) error
	GetShop(ctx context.Context, domain string) (*domain.Shop, error)
	ListShops(ctx context.Context) ([]*domain.Shop, error)

	// Webhook operations
	LogWebhook(ctx context.Context, event *domain.WebhookEvent) error

	// Credentials operations (deprecated - use ShopifyConfigRepository instead)
	SaveCredentials(ctx context.Context, creds *domain.ShopifyCredentials) error
	GetCredentials(ctx context.Context, projectID string, environment string) (*domain.ShopifyCredentials, error)
	DeleteCredentials(ctx context.Context, projectID string, environment string) error
}
