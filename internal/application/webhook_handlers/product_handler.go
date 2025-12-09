package webhook_handlers

import (
	"context"
	"encoding/json"
	"fmt"

	"archie-core-shopify-layer/internal/domain"
	"github.com/rs/zerolog"
)

// ProductHandler handles product-related webhook events
type ProductHandler struct {
	logger zerolog.Logger
}

// NewProductHandler creates a new product webhook handler
func NewProductHandler(logger zerolog.Logger) *ProductHandler {
	return &ProductHandler{
		logger: logger,
	}
}

// CanHandle returns true if this handler can process the given topic
func (h *ProductHandler) CanHandle(topic string) bool {
	return topic == "products/create" ||
		topic == "products/update" ||
		topic == "products/delete"
}

// Handle processes a product webhook event
func (h *ProductHandler) Handle(ctx context.Context, event *domain.WebhookEvent) error {
	// Parse product from payload
	var productData map[string]interface{}
	if err := json.Unmarshal(event.Payload, &productData); err != nil {
		return fmt.Errorf("failed to parse product webhook payload: %w", err)
	}

	// Extract product information for logging
	productID, _ := productData["id"].(float64)
	title, _ := productData["title"].(string)
	handle, _ := productData["handle"].(string)
	vendor, _ := productData["vendor"].(string)
	productType, _ := productData["product_type"].(string)

	h.logger.Info().
		Str("topic", event.Topic).
		Str("shop", event.Shop).
		Float64("productId", productID).
		Str("title", title).
		Str("handle", handle).
		Str("vendor", vendor).
		Str("productType", productType).
		Msg("Processing product webhook event")

	// Business logic implementation:
	// 1. Product events are already logged to database via ProcessWebhook
	// 2. Additional business logic can be added here:
	//    - Invalidate product cache
	//    - Update search index (Elasticsearch, Algolia, etc.)
	//    - Sync with external systems (PIM, CMS, etc.)
	//    - Update inventory tracking
	//    - Trigger marketing workflows
	//    - Update analytics/metrics

	// Example: Log specific product events for monitoring
	switch event.Topic {
	case "products/create":
		h.logger.Info().Str("shop", event.Shop).Float64("productId", productID).Str("title", title).Msg("New product created")
	case "products/update":
		h.logger.Info().Str("shop", event.Shop).Float64("productId", productID).Str("title", title).Msg("Product updated")
	case "products/delete":
		h.logger.Info().Str("shop", event.Shop).Float64("productId", productID).Msg("Product deleted")
	}

	return nil
}

