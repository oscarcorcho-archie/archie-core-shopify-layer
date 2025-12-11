package repository

import (
	"context"
	"fmt"
	"time"

	"archie-core-shopify-layer/internal/domain"
	"archie-core-shopify-layer/internal/infrastructure/repository/entity"
	"archie-core-shopify-layer/internal/ports"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

// MongoIntegrationRepository implements IntegrationRepository using MongoDB
type MongoIntegrationRepository struct {
	collection *mongo.Collection
}

// NewMongoIntegrationRepository creates a new MongoDB integration repository
func NewMongoIntegrationRepository(db *mongo.Database) ports.IntegrationRepository {
	return &MongoIntegrationRepository{
		collection: db.Collection("integrations"),
	}
}

// Create creates a new integration
func (r *MongoIntegrationRepository) Create(ctx context.Context, integration *domain.Integration) error {
	doc := entity.MongoIntegrationDocFromDomain(integration)
	doc.UpdatedAt = time.Now()
	if doc.CreatedAt.IsZero() {
		doc.CreatedAt = time.Now()
	}

	// Create unique index on key if it doesn't exist
	indexModel := mongo.IndexModel{
		Keys:    bson.D{{Key: "key", Value: 1}},
		Options: options.Index().SetUnique(true),
	}
	_, _ = r.collection.Indexes().CreateOne(ctx, indexModel)

	_, err := r.collection.InsertOne(ctx, doc)
	if err != nil {
		return fmt.Errorf("failed to create integration: %w", err)
	}

	return nil
}

// GetByKey retrieves an integration by its key
func (r *MongoIntegrationRepository) GetByKey(ctx context.Context, key string) (*domain.Integration, error) {
	var doc entity.MongoIntegrationDoc
	filter := bson.M{"key": key}

	err := r.collection.FindOne(ctx, filter).Decode(&doc)
	if err == mongo.ErrNoDocuments {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get integration: %w", err)
	}

	return doc.ToDomain(), nil
}

// GetByProjectAndShop retrieves an integration by project ID, environment, and shop domain
func (r *MongoIntegrationRepository) GetByProjectAndShop(ctx context.Context, projectID, environment, shopDomain string) (*domain.Integration, error) {
	var doc entity.MongoIntegrationDoc
	filter := bson.M{
		"projectId":  projectID,
		"environment": environment,
		"shopDomain": shopDomain,
	}

	err := r.collection.FindOne(ctx, filter).Decode(&doc)
	if err == mongo.ErrNoDocuments {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get integration: %w", err)
	}

	return doc.ToDomain(), nil
}

// Delete deletes an integration by key
func (r *MongoIntegrationRepository) Delete(ctx context.Context, key string) error {
	filter := bson.M{"key": key}
	result, err := r.collection.DeleteOne(ctx, filter)
	if err != nil {
		return fmt.Errorf("failed to delete integration: %w", err)
	}
	if result.DeletedCount == 0 {
		return fmt.Errorf("integration not found")
	}
	return nil
}

