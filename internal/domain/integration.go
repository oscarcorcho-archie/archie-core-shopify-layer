package domain

import "time"

// Integration represents a Shopify integration key that maps to a project/environment/shop combination
// This allows apps to authenticate using just an integration key instead of project ID + environment + shop
type Integration struct {
	ID          string    `json:"id" bson:"_id"`
	Key         string    `json:"key" bson:"key"`                   // Unique integration key (used for authentication)
	ProjectID   string    `json:"project_id" bson:"project_id"`   // Project this integration belongs to
	Environment string    `json:"environment" bson:"environment"`  // Environment (master, staging, etc.)
	ShopDomain  string    `json:"shop_domain" bson:"shop_domain"`  // Connected Shopify shop domain
	CreatedAt   time.Time `json:"created_at" bson:"created_at"`
	UpdatedAt   time.Time `json:"updated_at" bson:"updated_at"`
}

