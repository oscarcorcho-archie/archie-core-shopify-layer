package webhook_handlers

import (
	"context"
	"encoding/json"
	"fmt"

	"archie-core-shopify-layer/internal/domain"
	"github.com/rs/zerolog"
)

// OrderHandler handles order-related webhook events
type OrderHandler struct {
	logger zerolog.Logger
}

// NewOrderHandler creates a new order webhook handler
func NewOrderHandler(logger zerolog.Logger) *OrderHandler {
	return &OrderHandler{
		logger: logger,
	}
}

// CanHandle returns true if this handler can process the given topic
func (h *OrderHandler) CanHandle(topic string) bool {
	return topic == "orders/create" ||
		topic == "orders/updated" ||
		topic == "orders/cancelled" ||
		topic == "orders/paid" ||
		topic == "orders/fulfilled" ||
		topic == "orders/partially_fulfilled"
}

// Handle processes an order webhook event
func (h *OrderHandler) Handle(ctx context.Context, event *domain.WebhookEvent) error {
	// Parse order from payload
	var orderData map[string]interface{}
	if err := json.Unmarshal(event.Payload, &orderData); err != nil {
		return fmt.Errorf("failed to parse order webhook payload: %w", err)
	}

	// Extract order ID and number for logging
	orderID, _ := orderData["id"].(float64)
	orderNumber, _ := orderData["order_number"].(float64)
	email, _ := orderData["email"].(string)
	totalPrice, _ := orderData["total_price"].(string)
	financialStatus, _ := orderData["financial_status"].(string)
	fulfillmentStatus, _ := orderData["fulfillment_status"].(string)

	h.logger.Info().
		Str("topic", event.Topic).
		Str("shop", event.Shop).
		Float64("orderId", orderID).
		Float64("orderNumber", orderNumber).
		Str("email", email).
		Str("totalPrice", totalPrice).
		Str("financialStatus", financialStatus).
		Str("fulfillmentStatus", fulfillmentStatus).
		Msg("Processing order webhook event")

	// Business logic implementation:
	// 1. Order events are already logged to database via ProcessWebhook
	// 2. Additional business logic can be added here:
	//    - Update order status in local database
	//    - Trigger notifications (email, SMS, etc.)
	//    - Update inventory
	//    - Sync with external systems (ERP, CRM, etc.)
	//    - Trigger fulfillment workflows
	//    - Update analytics/metrics

	// Example: Log specific order events for monitoring
	switch event.Topic {
	case "orders/create":
		h.logger.Info().Str("shop", event.Shop).Float64("orderId", orderID).Msg("New order created")
	case "orders/paid":
		h.logger.Info().Str("shop", event.Shop).Float64("orderId", orderID).Msg("Order paid")
	case "orders/fulfilled":
		h.logger.Info().Str("shop", event.Shop).Float64("orderId", orderID).Msg("Order fulfilled")
	case "orders/cancelled":
		h.logger.Info().Str("shop", event.Shop).Float64("orderId", orderID).Msg("Order cancelled")
	}

	return nil
}

