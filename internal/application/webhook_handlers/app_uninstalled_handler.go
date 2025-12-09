package webhook_handlers

import (
	"context"
	"encoding/json"
	"fmt"

	"archie-core-shopify-layer/internal/application"
	"archie-core-shopify-layer/internal/domain"
	"archie-core-shopify-layer/internal/ports"
	"github.com/rs/zerolog"
)

// AppUninstalledHandler handles app uninstalled webhook events
type AppUninstalledHandler struct {
	logger                    zerolog.Logger
	repository                ports.Repository
	webhookSubscriptionRepo   ports.WebhookSubscriptionRepository
	shopifyService            *application.ShopifyService
}

// NewAppUninstalledHandler creates a new app uninstalled webhook handler
func NewAppUninstalledHandler(
	logger zerolog.Logger,
	repository ports.Repository,
	webhookSubscriptionRepo ports.WebhookSubscriptionRepository,
	shopifyService *application.ShopifyService,
) *AppUninstalledHandler {
	return &AppUninstalledHandler{
		logger:                  logger,
		repository:              repository,
		webhookSubscriptionRepo: webhookSubscriptionRepo,
		shopifyService:          shopifyService,
	}
}

// CanHandle returns true if this handler can process the given topic
func (h *AppUninstalledHandler) CanHandle(topic string) bool {
	return topic == "app/uninstalled"
}

// Handle processes an app uninstalled webhook event
func (h *AppUninstalledHandler) Handle(ctx context.Context, event *domain.WebhookEvent) error {
	// Parse shop data from payload
	var shopData map[string]interface{}
	if err := json.Unmarshal(event.Payload, &shopData); err != nil {
		return fmt.Errorf("failed to parse app uninstalled webhook payload: %w", err)
	}

	shopDomain := event.Shop
	if shopDomain == "" {
		if domain, ok := shopData["domain"].(string); ok {
			shopDomain = domain
		} else if myshopifyDomain, ok := shopData["myshopify_domain"].(string); ok {
			shopDomain = myshopifyDomain
		}
	}

	h.logger.Info().
		Str("topic", event.Topic).
		Str("shop", shopDomain).
		Interface("shop", shopData).
		Msg("Processing app uninstalled webhook event")

	// Extract projectID and environment from context
	projectID := domain.GetProjectIDFromContext(ctx)
	environment := domain.GetEnvironmentFromContext(ctx)
	if environment == "" {
		environment = domain.DefaultEnvironment
	}

	// Cleanup operations:
	// 1. Delete all webhook subscriptions for this shop
	if h.webhookSubscriptionRepo != nil && projectID != "" {
		subscriptions, err := h.webhookSubscriptionRepo.ListWebhookSubscriptions(ctx, projectID, environment, shopDomain)
		if err != nil {
			h.logger.Warn().Err(err).Str("shop", shopDomain).Msg("Failed to list webhook subscriptions for cleanup")
		} else {
			// Delete each webhook subscription from Shopify and our database
			for _, sub := range subscriptions {
				// Delete from Shopify (if we have access token)
				if h.shopifyService != nil {
					shop, err := h.shopifyService.GetShop(ctx, shopDomain)
					if err == nil && shop != nil && shop.AccessToken != "" {
						client, err := h.shopifyService.GetClientForTenant(ctx, "")
						if err == nil {
							_ = client.DeleteWebhook(ctx, shopDomain, shop.AccessToken, sub.WebhookID)
						}
					}
				}

				// Delete from our database
				if err := h.webhookSubscriptionRepo.DeleteWebhookSubscription(ctx, sub.ID); err != nil {
					h.logger.Warn().Err(err).Str("subscriptionId", sub.ID).Msg("Failed to delete webhook subscription")
				} else {
					h.logger.Info().Str("subscriptionId", sub.ID).Str("topic", sub.Topic).Msg("Deleted webhook subscription")
				}
			}
		}
	}

	// 2. Delete shop data (access tokens, etc.)
	// Note: We don't delete the shop record itself as it may be needed for audit purposes
	// Instead, we could mark it as uninstalled or delete sensitive data
	h.logger.Info().
		Str("shop", shopDomain).
		Str("projectId", projectID).
		Msg("App uninstalled - cleanup completed")

	// 3. Additional cleanup can be added here:
	//    - Send notification to administrators
	//    - Update analytics/metrics
	//    - Trigger external system cleanup
	//    - Archive shop data

	return nil
}

