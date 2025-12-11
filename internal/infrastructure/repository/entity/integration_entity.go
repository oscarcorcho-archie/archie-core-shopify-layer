package entity

import (
	"time"

	"archie-core-shopify-layer/internal/domain"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

// MongoIntegrationDoc represents an integration in MongoDB
type MongoIntegrationDoc struct {
	ID          primitive.ObjectID `bson:"_id,omitempty"`
	Key         string            `bson:"key"`
	ProjectID   string            `bson:"projectId"`
	Environment string            `bson:"environment"`
	ShopDomain  string            `bson:"shopDomain"`
	CreatedAt   time.Time         `bson:"createdAt"`
	UpdatedAt   time.Time         `bson:"updatedAt"`
}

// ToDomain converts the MongoDB document to a domain entity
func (d *MongoIntegrationDoc) ToDomain() *domain.Integration {
	return &domain.Integration{
		ID:          d.ID.Hex(),
		Key:         d.Key,
		ProjectID:   d.ProjectID,
		Environment: d.Environment,
		ShopDomain:  d.ShopDomain,
		CreatedAt:   d.CreatedAt,
		UpdatedAt:   d.UpdatedAt,
	}
}

// MongoIntegrationDocFromDomain converts a domain entity to a MongoDB document
func MongoIntegrationDocFromDomain(integration *domain.Integration) *MongoIntegrationDoc {
	doc := &MongoIntegrationDoc{
		Key:         integration.Key,
		ProjectID:   integration.ProjectID,
		Environment: integration.Environment,
		ShopDomain:  integration.ShopDomain,
		CreatedAt:   integration.CreatedAt,
		UpdatedAt:   integration.UpdatedAt,
	}

	if integration.ID != "" {
		if objID, err := primitive.ObjectIDFromHex(integration.ID); err == nil {
			doc.ID = objID
		}
	}

	return doc
}

