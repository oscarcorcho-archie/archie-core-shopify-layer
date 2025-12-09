package repository

import (
	"context"
	"fmt"
	"time"

	"archie-core-shopify-layer/internal/domain"
	"archie-core-shopify-layer/internal/infrastructure/repository/entity"
	"archie-core-shopify-layer/internal/ports"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

// MongoRepository implements Repository using MongoDB
type MongoRepository struct {
	shopsCollection       *mongo.Collection
	webhooksCollection    *mongo.Collection
	credentialsCollection *mongo.Collection
}

// NewMongoRepository creates a new MongoDB repository
func NewMongoRepository(db *mongo.Database) ports.Repository {
	return &MongoRepository{
		shopsCollection:       db.Collection("shops"),
		webhooksCollection:    db.Collection("webhook_events"),
		credentialsCollection: db.Collection("credentials"),
	}
}

// SaveShop saves or updates a shop
func (r *MongoRepository) SaveShop(ctx context.Context, shop *domain.Shop) error {
	doc := entity.MongoShopDocFromDomain(shop)
	doc.UpdatedAt = time.Now()
	if doc.CreatedAt.IsZero() {
		doc.CreatedAt = time.Now()
	}

	opts := options.Update().SetUpsert(true)
	filter := bson.M{"domain": shop.Domain}
	update := bson.M{"$set": doc}

	_, err := r.shopsCollection.UpdateOne(ctx, filter, update, opts)
	if err != nil {
		return fmt.Errorf("failed to save shop: %w", err)
	}

	return nil
}

// GetShop retrieves a shop by domain
func (r *MongoRepository) GetShop(ctx context.Context, shopDomain string) (*domain.Shop, error) {
	var doc entity.MongoShopDoc
	filter := bson.M{"domain": shopDomain}

	err := r.shopsCollection.FindOne(ctx, filter).Decode(&doc)
	if err == mongo.ErrNoDocuments {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get shop: %w", err)
	}

	return doc.ToDomain(), nil
}

// ListShops retrieves all shops
func (r *MongoRepository) ListShops(ctx context.Context) ([]*domain.Shop, error) {
	cursor, err := r.shopsCollection.Find(ctx, bson.M{})
	if err != nil {
		return nil, fmt.Errorf("failed to list shops: %w", err)
	}
	defer cursor.Close(ctx)

	var shops []*domain.Shop
	for cursor.Next(ctx) {
		var doc entity.MongoShopDoc
		if err := cursor.Decode(&doc); err != nil {
			return nil, fmt.Errorf("failed to decode shop: %w", err)
		}
		shops = append(shops, doc.ToDomain())
	}

	if err := cursor.Err(); err != nil {
		return nil, fmt.Errorf("cursor error: %w", err)
	}

	return shops, nil
}

// LogWebhook logs a webhook event
func (r *MongoRepository) LogWebhook(ctx context.Context, event *domain.WebhookEvent) error {
	doc := entity.MongoWebhookDocFromDomain(event)
	if doc.ID.IsZero() {
		doc.ID = primitive.NewObjectID()
	}
	if doc.CreatedAt.IsZero() {
		doc.CreatedAt = time.Now()
	}

	_, err := r.webhooksCollection.InsertOne(ctx, doc)
	if err != nil {
		return fmt.Errorf("failed to log webhook: %w", err)
	}

	return nil
}

// SaveCredentials saves or updates credentials
func (r *MongoRepository) SaveCredentials(ctx context.Context, creds *domain.ShopifyCredentials) error {
	doc := entity.MongoCredentialsDocFromDomain(creds)
	doc.UpdatedAt = time.Now()
	if doc.CreatedAt.IsZero() {
		doc.CreatedAt = time.Now()
	}

	opts := options.Update().SetUpsert(true)
	filter := bson.M{
		"projectId":   creds.ProjectID,
		"environment": creds.Environment,
	}
	update := bson.M{"$set": doc}

	_, err := r.credentialsCollection.UpdateOne(ctx, filter, update, opts)
	if err != nil {
		return fmt.Errorf("failed to save credentials: %w", err)
	}

	return nil
}

// GetCredentials retrieves credentials by project and environment
func (r *MongoRepository) GetCredentials(ctx context.Context, projectID string, environment string) (*domain.ShopifyCredentials, error) {
	var doc entity.MongoCredentialsDoc
	filter := bson.M{
		"projectId":   projectID,
		"environment": environment,
	}

	err := r.credentialsCollection.FindOne(ctx, filter).Decode(&doc)
	if err == mongo.ErrNoDocuments {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get credentials: %w", err)
	}

	return doc.ToDomain(), nil
}

// DeleteCredentials deletes credentials by project and environment
func (r *MongoRepository) DeleteCredentials(ctx context.Context, projectID string, environment string) error {
	filter := bson.M{
		"projectId":   projectID,
		"environment": environment,
	}

	_, err := r.credentialsCollection.DeleteOne(ctx, filter)
	if err != nil {
		return fmt.Errorf("failed to delete credentials: %w", err)
	}

	return nil
}
