package domain

import "time"

// Session represents an OAuth session
type Session struct {
	ID          string    `json:"id" bson:"_id"`
	Shop        string    `json:"shop" bson:"shop"`
	State       string    `json:"state" bson:"state"`
	Scopes      []string  `json:"scopes" bson:"scopes"`
	ProjectID   string    `json:"project_id" bson:"project_id"`
	Environment string    `json:"environment" bson:"environment"`
	ReturnURL   string    `json:"return_url" bson:"return_url"`
	ExpiresAt   time.Time `json:"expires_at" bson:"expires_at"`
	CreatedAt   time.Time `json:"created_at" bson:"created_at"`
}
