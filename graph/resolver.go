package graph

import (
	"archie-core-shopify-layer/internal/application"
	"archie-core-shopify-layer/internal/infrastructure/pubsub"
	"archie-core-shopify-layer/internal/infrastructure/repository"
)

// This file will not be regenerated automatically.
//
// It serves as dependency injection for your app, add any dependencies you require here.

type Resolver struct {
	shopifyService     *application.ShopifyService
	credentialsService *application.CredentialsService
	webhookPubSub      *pubsub.WebhookPubSub
	sessionRepo        *repository.SessionRepository
}

// NewResolver creates a new GraphQL resolver
func NewResolver(
	shopifyService *application.ShopifyService,
	credentialsService *application.CredentialsService,
	webhookPubSub *pubsub.WebhookPubSub,
	sessionRepo *repository.SessionRepository,
) *Resolver {
	return &Resolver{
		shopifyService:     shopifyService,
		credentialsService: credentialsService,
		webhookPubSub:      webhookPubSub,
		sessionRepo:        sessionRepo,
	}
}
