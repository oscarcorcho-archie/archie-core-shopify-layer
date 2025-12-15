package ports

import (
	"context"

	shopify "github.com/bold-commerce/go-shopify/v4"
)

// ShopifyClient defines the interface for Shopify API operations
type ShopifyClient interface {
	// Authentication
	GenerateAuthURL(shop string, scopes []string, redirectURI string, state string) (string, error)
	ExchangeToken(ctx context.Context, shop string, code string, redirectURI string) (string, error)

	// Shop API
	GetShop(ctx context.Context, shop string, accessToken string) (*shopify.Shop, error)

	// Product API
	GetProducts(ctx context.Context, shop string, accessToken string, options interface{}) ([]shopify.Product, error)
	GetProduct(ctx context.Context, shop string, accessToken string, productID int64) (*shopify.Product, error)
	CreateProduct(ctx context.Context, shop string, accessToken string, product *shopify.Product) (*shopify.Product, error)
	UpdateProduct(ctx context.Context, shop string, accessToken string, product *shopify.Product) (*shopify.Product, error)
	DeleteProduct(ctx context.Context, shop string, accessToken string, productID int64) error

	// Order API
	GetOrders(ctx context.Context, shop string, accessToken string, options interface{}) ([]shopify.Order, error)
	GetOrder(ctx context.Context, shop string, accessToken string, orderID int64) (*shopify.Order, error)
	CreateOrder(ctx context.Context, shop string, accessToken string, order *shopify.Order) (*shopify.Order, error)
	UpdateOrder(ctx context.Context, shop string, accessToken string, order *shopify.Order) (*shopify.Order, error)
	CancelOrder(ctx context.Context, shop string, accessToken string, orderID int64) (*shopify.Order, error)

	// Customer API
	GetCustomers(ctx context.Context, shop string, accessToken string, options interface{}) ([]shopify.Customer, error)
	GetCustomer(ctx context.Context, shop string, accessToken string, customerID int64) (*shopify.Customer, error)
	CreateCustomer(ctx context.Context, shop string, accessToken string, customer *shopify.Customer) (*shopify.Customer, error)
	UpdateCustomer(ctx context.Context, shop string, accessToken string, customer *shopify.Customer) (*shopify.Customer, error)
	DeleteCustomer(ctx context.Context, shop string, accessToken string, customerID int64) error
	SearchCustomers(ctx context.Context, shop string, accessToken string, query string) ([]shopify.Customer, error)

	// Inventory API
	GetInventoryLevels(ctx context.Context, shop string, accessToken string, options interface{}) ([]shopify.InventoryLevel, error)
	UpdateInventoryLevel(ctx context.Context, shop string, accessToken string, inventoryLevel *shopify.InventoryLevel) (*shopify.InventoryLevel, error)

	// Webhook API
	CreateWebhook(ctx context.Context, shop string, accessToken string, topic string, address string) (*shopify.Webhook, error)
	GetWebhook(ctx context.Context, shop string, accessToken string, webhookID int64) (*shopify.Webhook, error)
	ListWebhooks(ctx context.Context, shop string, accessToken string, options interface{}) ([]shopify.Webhook, error)
	UpdateWebhook(ctx context.Context, shop string, accessToken string, webhookID int64, address string) (*shopify.Webhook, error)
	DeleteWebhook(ctx context.Context, shop string, accessToken string, webhookID int64) error

	// Collection API
	GetCollection(ctx context.Context, shop string, accessToken string, collectionID int64) (*shopify.Collection, error)
	ListCollectionProducts(ctx context.Context, shop string, accessToken string, collectionID int64, options interface{}) ([]shopify.Product, error)
	GetCustomCollection(ctx context.Context, shop string, accessToken string, collectionID int64) (*shopify.CustomCollection, error)
	ListCustomCollections(ctx context.Context, shop string, accessToken string, options interface{}) ([]shopify.CustomCollection, error)
	CreateCustomCollection(ctx context.Context, shop string, accessToken string, collection *shopify.CustomCollection) (*shopify.CustomCollection, error)
	UpdateCustomCollection(ctx context.Context, shop string, accessToken string, collection *shopify.CustomCollection) (*shopify.CustomCollection, error)
	DeleteCustomCollection(ctx context.Context, shop string, accessToken string, collectionID int64) error

	// Fulfillment API
	ListFulfillments(ctx context.Context, shop string, accessToken string, options interface{}) ([]shopify.Fulfillment, error)
	GetFulfillment(ctx context.Context, shop string, accessToken string, fulfillmentID int64) (*shopify.Fulfillment, error)
	CreateFulfillment(ctx context.Context, shop string, accessToken string, fulfillment *shopify.Fulfillment) (*shopify.Fulfillment, error)
	UpdateFulfillment(ctx context.Context, shop string, accessToken string, fulfillment *shopify.Fulfillment) (*shopify.Fulfillment, error)
	CompleteFulfillment(ctx context.Context, shop string, accessToken string, fulfillmentID int64) (*shopify.Fulfillment, error)
	CancelFulfillment(ctx context.Context, shop string, accessToken string, fulfillmentID int64) (*shopify.Fulfillment, error)

	// Discount Code API (requires PriceRule ID)
	ListDiscountCodes(ctx context.Context, shop string, accessToken string, priceRuleID int64) ([]shopify.PriceRuleDiscountCode, error)
	GetDiscountCode(ctx context.Context, shop string, accessToken string, priceRuleID int64, discountCodeID int64) (*shopify.PriceRuleDiscountCode, error)
	CreateDiscountCode(ctx context.Context, shop string, accessToken string, priceRuleID int64, discountCode *shopify.PriceRuleDiscountCode) (*shopify.PriceRuleDiscountCode, error)
	UpdateDiscountCode(ctx context.Context, shop string, accessToken string, priceRuleID int64, discountCode *shopify.PriceRuleDiscountCode) (*shopify.PriceRuleDiscountCode, error)
	DeleteDiscountCode(ctx context.Context, shop string, accessToken string, priceRuleID int64, discountCodeID int64) error
}
