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

// MongoShopifyConfigRepository implements ShopifyConfigRepository using MongoDB
// Works with the projects collection, storing shopify_configs in settings.shopify_configs[]
type MongoShopifyConfigRepository struct {
	collection *mongo.Collection // projects collection
}

// NewMongoShopifyConfigRepository creates a new MongoDB repository
func NewMongoShopifyConfigRepository(db *mongo.Database) ports.ShopifyConfigRepository {
	return &MongoShopifyConfigRepository{
		collection: db.Collection("projects"),
	}
}

// GetByTenantID retrieves Shopify configuration for a project and environment
// tenantID is actually projectID in this context
// NOTE: The extraction of projectID and environment from context should ideally be done in the application layer,
// but it's kept here for backward compatibility. In the future, these values should be passed as parameters.
func (r *MongoShopifyConfigRepository) GetByTenantID(ctx context.Context, tenantID string) (*domain.ShopifyConfig, error) {
	// Extract projectID and environment from context (type-safe)
	projectID := domain.GetProjectIDFromContext(ctx)
	environment := domain.GetEnvironmentFromContext(ctx)

	if projectID == "" {
		// Fallback to tenantID if projectID not in context (backward compatibility)
		projectID = tenantID
	}
	if environment == "" {
		environment = domain.DefaultEnvironment // Default environment
	}

	// Find project by projectId
	var project entity.MongoProjectDoc
	err := r.collection.FindOne(ctx, bson.M{"projectId": projectID}).Decode(&project)
	if err == mongo.ErrNoDocuments {
		return nil, nil // Project not found, return nil (not an error)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get project: %w", err)
	}

	// Find shopify_config within settings.shopify_configs[] matching the environment
	var shopifyConfig *entity.MongoShopifyConfigDoc
	for i := range project.Settings.ShopifyConfigs {
		if project.Settings.ShopifyConfigs[i].Env == environment {
			shopifyConfig = &project.Settings.ShopifyConfigs[i]
			break
		}
	}

	if shopifyConfig == nil {
		return nil, nil // Config doesn't exist for this environment
	}

	return shopifyConfig.ToDomain(projectID, environment), nil
}

// Create creates a new Shopify configuration within a project's settings.shopify_configs[]
func (r *MongoShopifyConfigRepository) Create(ctx context.Context, config *domain.ShopifyConfig) error {
	projectID := config.ProjectID
	environment := config.Environment

	// Find project or create if it doesn't exist
	var project entity.MongoProjectDoc
	err := r.collection.FindOne(ctx, bson.M{"projectId": projectID}).Decode(&project)
	if err == mongo.ErrNoDocuments {
		// Project doesn't exist, create it
		project = entity.MongoProjectDoc{
			ID:        primitive.NewObjectID(),
			ProjectID: projectID,
			Settings: entity.MongoProjectSettings{
				ShopifyConfigs: []entity.MongoShopifyConfigDoc{},
			},
			UpdatedAt: time.Now(),
		}
		_, err = r.collection.InsertOne(ctx, project)
		if err != nil {
			return fmt.Errorf("failed to create project: %w", err)
		}
	} else if err != nil {
		return fmt.Errorf("failed to get project: %w", err)
	}

	// Check if shopify_config already exists for this environment
	for _, existingConfig := range project.Settings.ShopifyConfigs {
		if existingConfig.Env == environment {
			return fmt.Errorf("shopify config already exists for project %s and environment %s", projectID, environment)
		}
	}

	// Create new shopify_config document
	shopifyConfigDoc := entity.MongoShopifyConfigDocFromDomain(config)
	shopifyConfigDoc.ID = primitive.NewObjectID()
	shopifyConfigDoc.CreatedAt = time.Now()
	shopifyConfigDoc.UpdatedAt = time.Now()

	// Add to shopify_configs array
	update := bson.M{
		"$push": bson.M{
			"settings.shopify_configs": shopifyConfigDoc,
		},
		"$set": bson.M{
			"updatedAt": time.Now(),
		},
	}

	_, err = r.collection.UpdateOne(
		ctx,
		bson.M{"projectId": projectID},
		update,
	)
	if err != nil {
		return fmt.Errorf("failed to create shopify config: %w", err)
	}

	config.ID = shopifyConfigDoc.ID.Hex()
	return nil
}

// Update updates an existing Shopify configuration within a project's settings.shopify_configs[]
func (r *MongoShopifyConfigRepository) Update(ctx context.Context, tenantID string, config *domain.ShopifyConfig) error {
	projectID := config.ProjectID
	environment := config.Environment

	if projectID == "" {
		projectID = tenantID // Fallback
	}
	if environment == "" {
		environment = domain.DefaultEnvironment // Default
	}

	objID, err := primitive.ObjectIDFromHex(config.ID)
	if err != nil {
		return fmt.Errorf("invalid config ID: %w", err)
	}

	// Update the specific shopify_config within the array
	update := bson.M{
		"$set": bson.M{
			"settings.shopify_configs.$[elem].encryptedKey":  config.EncryptedKey,
			"settings.shopify_configs.$[elem].apiKey":        config.APIKey,
			"settings.shopify_configs.$[elem].webhookSecret": config.WebhookSecret,
			"settings.shopify_configs.$[elem].webhookURL":    config.WebhookURL,
			"settings.shopify_configs.$[elem].updatedAt":     time.Now(),
			"updatedAt": time.Now(),
		},
	}

	arrayFilters := options.Update().SetArrayFilters(options.ArrayFilters{
		Filters: []interface{}{
			bson.M{
				"elem._id": objID,
				"elem.env": environment,
			},
		},
	})

	_, err = r.collection.UpdateOne(
		ctx,
		bson.M{"projectId": projectID},
		update,
		arrayFilters,
	)
	if err != nil {
		return fmt.Errorf("failed to update shopify config: %w", err)
	}
	return nil
}

// Delete deletes a Shopify configuration from a project's settings.shopify_configs[]
func (r *MongoShopifyConfigRepository) Delete(ctx context.Context, tenantID string) error {
	// Extract projectID and environment from context (type-safe)
	projectID := domain.GetProjectIDFromContext(ctx)
	environment := domain.GetEnvironmentFromContext(ctx)

	if projectID == "" {
		projectID = tenantID // Fallback
	}
	if environment == "" {
		environment = domain.DefaultEnvironment // Default
	}

	// Remove the shopify_config from the array
	update := bson.M{
		"$pull": bson.M{
			"settings.shopify_configs": bson.M{
				"env": environment,
			},
		},
		"$set": bson.M{
			"updatedAt": time.Now(),
		},
	}

	result, err := r.collection.UpdateOne(
		ctx,
		bson.M{"projectId": projectID},
		update,
	)
	if err != nil {
		return fmt.Errorf("failed to delete shopify config: %w", err)
	}

	if result.MatchedCount == 0 {
		return fmt.Errorf("project not found: %s", projectID)
	}

	if result.ModifiedCount == 0 {
		return fmt.Errorf("shopify config not found for project %s and environment %s", projectID, environment)
	}

	return nil
}
