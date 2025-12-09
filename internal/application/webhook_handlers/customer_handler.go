package webhook_handlers

import (
	"context"
	"encoding/json"
	"fmt"

	"archie-core-shopify-layer/internal/domain"
	"github.com/rs/zerolog"
)

// CustomerHandler handles customer-related webhook events
type CustomerHandler struct {
	logger zerolog.Logger
}

// NewCustomerHandler creates a new customer webhook handler
func NewCustomerHandler(logger zerolog.Logger) *CustomerHandler {
	return &CustomerHandler{
		logger: logger,
	}
}

// CanHandle returns true if this handler can process the given topic
func (h *CustomerHandler) CanHandle(topic string) bool {
	return topic == "customers/create" ||
		topic == "customers/update" ||
		topic == "customers/delete" ||
		topic == "customers/enable" ||
		topic == "customers/disable"
}

// Handle processes a customer webhook event
func (h *CustomerHandler) Handle(ctx context.Context, event *domain.WebhookEvent) error {
	// Parse customer from payload
	var customerData map[string]interface{}
	if err := json.Unmarshal(event.Payload, &customerData); err != nil {
		return fmt.Errorf("failed to parse customer webhook payload: %w", err)
	}

	// Extract customer information for logging
	customerID, _ := customerData["id"].(float64)
	email, _ := customerData["email"].(string)
	firstName, _ := customerData["first_name"].(string)
	lastName, _ := customerData["last_name"].(string)
	ordersCount, _ := customerData["orders_count"].(float64)
	totalSpent, _ := customerData["total_spent"].(string)

	h.logger.Info().
		Str("topic", event.Topic).
		Str("shop", event.Shop).
		Float64("customerId", customerID).
		Str("email", email).
		Str("firstName", firstName).
		Str("lastName", lastName).
		Float64("ordersCount", ordersCount).
		Str("totalSpent", totalSpent).
		Msg("Processing customer webhook event")

	// Business logic implementation:
	// 1. Customer events are already logged to database via ProcessWebhook
	// 2. Additional business logic can be added here:
	//    - Update customer database/CRM
	//    - Sync with marketing platforms (Mailchimp, Klaviyo, etc.)
	//    - Send welcome emails for new customers
	//    - Update customer segments
	//    - Trigger loyalty program updates
	//    - Update analytics/metrics

	// Example: Log specific customer events for monitoring
	switch event.Topic {
	case "customers/create":
		h.logger.Info().Str("shop", event.Shop).Float64("customerId", customerID).Str("email", email).Msg("New customer created")
	case "customers/update":
		h.logger.Info().Str("shop", event.Shop).Float64("customerId", customerID).Str("email", email).Msg("Customer updated")
	case "customers/delete":
		h.logger.Info().Str("shop", event.Shop).Float64("customerId", customerID).Msg("Customer deleted")
	case "customers/enable":
		h.logger.Info().Str("shop", event.Shop).Float64("customerId", customerID).Msg("Customer enabled")
	case "customers/disable":
		h.logger.Info().Str("shop", event.Shop).Float64("customerId", customerID).Msg("Customer disabled")
	}

	return nil
}

