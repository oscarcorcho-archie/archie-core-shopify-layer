package shopify

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"archie-core-shopify-layer/internal/ports"

	goshopify "github.com/bold-commerce/go-shopify/v4"
	"github.com/rs/zerolog"
)

type client struct {
	apiKey      string
	apiSecret   string
	app         goshopify.App
	rateLimiter *RateLimiter
	retryConfig RetryConfig
	logger      zerolog.Logger
}

// NewClient creates a new Shopify client adapter
func NewClient(apiKey, apiSecret string) ports.ShopifyClient {
	return NewClientWithOptions(apiKey, apiSecret, nil, DefaultRetryConfig(), zerolog.Nop())
}

// NewClientWithOptions creates a client with rate limiting and retry options
func NewClientWithOptions(
	apiKey, apiSecret string,
	rateLimiter *RateLimiter,
	retryConfig RetryConfig,
	logger zerolog.Logger,
) ports.ShopifyClient {
	app := goshopify.App{
		ApiKey:    apiKey,
		ApiSecret: apiSecret,
	}
	return &client{
		apiKey:      apiKey,
		apiSecret:   apiSecret,
		app:         app,
		rateLimiter: rateLimiter,
		retryConfig: retryConfig,
		logger:      logger,
	}
}

// createClient is a helper to create a goshopify client
func (c *client) createClient(shopDomain string, accessToken string) (*goshopify.Client, error) {
	client, err := goshopify.NewClient(c.app, shopDomain, accessToken)
	if err != nil {
		return nil, fmt.Errorf("failed to create client: %w", err)
	}
	return client, nil
}

// Authentication methods

func (c *client) GenerateAuthURL(shop string, scopes []string, redirectURI string, state string) (string, error) {
	// The go-shopify library's AuthorizeUrl doesn't accept redirect_uri directly
	// We need to manually construct the URL with redirect_uri and state parameters
	// Shopify expects scopes to be comma-separated (no spaces)
	scopesStr := strings.Join(scopes, ",")

	// Log scopes for debugging (use Info level so it's visible)
	c.logger.Info().
		Str("shop", shop).
		Strs("scopes", scopes).
		Str("scopes_string", scopesStr).
		Int("scope_count", len(scopes)).
		Msg("Generating OAuth authorization URL with scopes")

	authURL := fmt.Sprintf(
		"https://%s/admin/oauth/authorize?client_id=%s&scope=%s&redirect_uri=%s&state=%s",
		shop,
		c.apiKey,
		url.QueryEscape(scopesStr),
		url.QueryEscape(redirectURI),
		url.QueryEscape(state),
	)

	// Log the full URL (but mask sensitive parts)
	c.logger.Info().
		Str("shop", shop).
		Str("scopes_in_url", scopesStr).
		Str("auth_url_masked", fmt.Sprintf("https://%s/admin/oauth/authorize?client_id=%s&scope=%s&redirect_uri=...&state=...", shop, c.apiKey, scopesStr)).
		Msg("Generated OAuth authorization URL")

	return authURL, nil
}

func (c *client) ExchangeToken(ctx context.Context, shop string, code string, redirectURI string) (string, error) {
	// Shopify requires the redirect_uri parameter to match the one used in authorization
	// The go-shopify library's GetAccessToken doesn't expose redirect_uri, so we make a direct HTTP call
	if redirectURI != "" {
		// Make direct HTTP call to Shopify's token endpoint with redirect_uri
		tokenURL := fmt.Sprintf("https://%s/admin/oauth/access_token", shop)
		
		values := url.Values{}
		values.Set("client_id", c.apiKey)
		values.Set("client_secret", c.apiSecret)
		values.Set("code", code)
		values.Set("redirect_uri", redirectURI)
		
		req, err := http.NewRequestWithContext(ctx, "POST", tokenURL, strings.NewReader(values.Encode()))
		if err != nil {
			return "", fmt.Errorf("failed to create token request: %w", err)
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return "", fmt.Errorf("failed to exchange token: %w", err)
		}
		defer resp.Body.Close()
		
		if resp.StatusCode != http.StatusOK {
			bodyBytes, _ := io.ReadAll(resp.Body)
			return "", fmt.Errorf("failed to exchange token: status %d, body: %s", resp.StatusCode, string(bodyBytes))
		}
		
		var tokenResponse struct {
			AccessToken string `json:"access_token"`
			Scope       string `json:"scope"`
		}
		
		if err := json.NewDecoder(resp.Body).Decode(&tokenResponse); err != nil {
			return "", fmt.Errorf("failed to decode token response: %w", err)
		}
		
		return tokenResponse.AccessToken, nil
	}
	
	// Fallback to go-shopify library if redirectURI not provided (for backward compatibility)
	token, err := c.app.GetAccessToken(ctx, shop, code)
	if err != nil {
		return "", fmt.Errorf("failed to exchange token: %w", err)
	}
	return token, nil
}

// Shop API

func (c *client) GetShop(ctx context.Context, shopDomain string, accessToken string) (*goshopify.Shop, error) {
	client, err := c.createClient(shopDomain, accessToken)
	if err != nil {
		return nil, err
	}
	shop, err := client.Shop.Get(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get shop: %w", err)
	}
	return shop, nil
}

// Product API

func (c *client) GetProducts(ctx context.Context, shopDomain string, accessToken string, options interface{}) ([]goshopify.Product, error) {
	client, err := c.createClient(shopDomain, accessToken)
	if err != nil {
		return nil, err
	}
	products, err := client.Product.List(ctx, options)
	if err != nil {
		return nil, fmt.Errorf("failed to list products: %w", err)
	}
	return products, nil
}

func (c *client) GetProduct(ctx context.Context, shopDomain string, accessToken string, productID int64) (*goshopify.Product, error) {
	client, err := c.createClient(shopDomain, accessToken)
	if err != nil {
		return nil, err
	}
	product, err := client.Product.Get(ctx, uint64(productID), nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get product: %w", err)
	}
	return product, nil
}

func (c *client) CreateProduct(ctx context.Context, shopDomain string, accessToken string, product *goshopify.Product) (*goshopify.Product, error) {
	client, err := c.createClient(shopDomain, accessToken)
	if err != nil {
		return nil, err
	}
	created, err := client.Product.Create(ctx, *product)
	if err != nil {
		return nil, fmt.Errorf("failed to create product: %w", err)
	}
	return created, nil
}

func (c *client) UpdateProduct(ctx context.Context, shopDomain string, accessToken string, product *goshopify.Product) (*goshopify.Product, error) {
	client, err := c.createClient(shopDomain, accessToken)
	if err != nil {
		return nil, err
	}
	updated, err := client.Product.Update(ctx, *product)
	if err != nil {
		return nil, fmt.Errorf("failed to update product: %w", err)
	}
	return updated, nil
}

func (c *client) DeleteProduct(ctx context.Context, shopDomain string, accessToken string, productID int64) error {
	client, err := c.createClient(shopDomain, accessToken)
	if err != nil {
		return err
	}
	err = client.Product.Delete(ctx, uint64(productID))
	if err != nil {
		return fmt.Errorf("failed to delete product: %w", err)
	}
	return nil
}

// Order API

func (c *client) GetOrders(ctx context.Context, shopDomain string, accessToken string, options interface{}) ([]goshopify.Order, error) {
	client, err := c.createClient(shopDomain, accessToken)
	if err != nil {
		return nil, err
	}
	orders, err := client.Order.List(ctx, options)
	if err != nil {
		return nil, fmt.Errorf("failed to list orders: %w", err)
	}
	return orders, nil
}

func (c *client) GetOrder(ctx context.Context, shopDomain string, accessToken string, orderID int64) (*goshopify.Order, error) {
	client, err := c.createClient(shopDomain, accessToken)
	if err != nil {
		return nil, err
	}
	order, err := client.Order.Get(ctx, uint64(orderID), nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get order: %w", err)
	}
	return order, nil
}

func (c *client) CreateOrder(ctx context.Context, shopDomain string, accessToken string, order *goshopify.Order) (*goshopify.Order, error) {
	client, err := c.createClient(shopDomain, accessToken)
	if err != nil {
		return nil, err
	}
	created, err := client.Order.Create(ctx, *order)
	if err != nil {
		return nil, fmt.Errorf("failed to create order: %w", err)
	}
	return created, nil
}

func (c *client) UpdateOrder(ctx context.Context, shopDomain string, accessToken string, order *goshopify.Order) (*goshopify.Order, error) {
	client, err := c.createClient(shopDomain, accessToken)
	if err != nil {
		return nil, err
	}
	updated, err := client.Order.Update(ctx, *order)
	if err != nil {
		return nil, fmt.Errorf("failed to update order: %w", err)
	}
	return updated, nil
}

func (c *client) CancelOrder(ctx context.Context, shopDomain string, accessToken string, orderID int64) (*goshopify.Order, error) {
	client, err := c.createClient(shopDomain, accessToken)
	if err != nil {
		return nil, err
	}
	cancelled, err := client.Order.Cancel(ctx, uint64(orderID), nil)
	if err != nil {
		return nil, fmt.Errorf("failed to cancel order: %w", err)
	}
	return cancelled, nil
}

// Customer API

func (c *client) GetCustomers(ctx context.Context, shopDomain string, accessToken string, options interface{}) ([]goshopify.Customer, error) {
	client, err := c.createClient(shopDomain, accessToken)
	if err != nil {
		return nil, err
	}
	customers, err := client.Customer.List(ctx, options)
	if err != nil {
		return nil, fmt.Errorf("failed to list customers: %w", err)
	}
	return customers, nil
}

func (c *client) GetCustomer(ctx context.Context, shopDomain string, accessToken string, customerID int64) (*goshopify.Customer, error) {
	client, err := c.createClient(shopDomain, accessToken)
	if err != nil {
		return nil, err
	}
	customer, err := client.Customer.Get(ctx, uint64(customerID), nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get customer: %w", err)
	}
	return customer, nil
}

func (c *client) CreateCustomer(ctx context.Context, shopDomain string, accessToken string, customer *goshopify.Customer) (*goshopify.Customer, error) {
	client, err := c.createClient(shopDomain, accessToken)
	if err != nil {
		return nil, err
	}
	created, err := client.Customer.Create(ctx, *customer)
	if err != nil {
		return nil, fmt.Errorf("failed to create customer: %w", err)
	}
	return created, nil
}

func (c *client) UpdateCustomer(ctx context.Context, shopDomain string, accessToken string, customer *goshopify.Customer) (*goshopify.Customer, error) {
	client, err := c.createClient(shopDomain, accessToken)
	if err != nil {
		return nil, err
	}
	updated, err := client.Customer.Update(ctx, *customer)
	if err != nil {
		return nil, fmt.Errorf("failed to update customer: %w", err)
	}
	return updated, nil
}

func (c *client) DeleteCustomer(ctx context.Context, shopDomain string, accessToken string, customerID int64) error {
	client, err := c.createClient(shopDomain, accessToken)
	if err != nil {
		return err
	}
	err = client.Customer.Delete(ctx, uint64(customerID))
	if err != nil {
		return fmt.Errorf("failed to delete customer: %w", err)
	}
	return nil
}

func (c *client) SearchCustomers(ctx context.Context, shopDomain string, accessToken string, query string) ([]goshopify.Customer, error) {
	client, err := c.createClient(shopDomain, accessToken)
	if err != nil {
		return nil, err
	}
	customers, err := client.Customer.Search(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("failed to search customers: %w", err)
	}
	return customers, nil
}

// Inventory API

func (c *client) GetInventoryLevels(ctx context.Context, shopDomain string, accessToken string, options interface{}) ([]goshopify.InventoryLevel, error) {
	client, err := c.createClient(shopDomain, accessToken)
	if err != nil {
		return nil, err
	}
	levels, err := client.InventoryLevel.List(ctx, options)
	if err != nil {
		return nil, fmt.Errorf("failed to list inventory levels: %w", err)
	}
	return levels, nil
}

func (c *client) UpdateInventoryLevel(ctx context.Context, shopDomain string, accessToken string, inventoryLevel *goshopify.InventoryLevel) (*goshopify.InventoryLevel, error) {
	client, err := c.createClient(shopDomain, accessToken)
	if err != nil {
		return nil, err
	}
	// Note: The actual update method may vary based on the goshopify library version
	// This is a placeholder implementation
	updated, err := client.InventoryLevel.Set(ctx, *inventoryLevel)
	if err != nil {
		return nil, fmt.Errorf("failed to update inventory level: %w", err)
	}
	return updated, nil
}

// Webhook API

func (c *client) CreateWebhook(ctx context.Context, shopDomain string, accessToken string, topic string, address string) (*goshopify.Webhook, error) {
	client, err := c.createClient(shopDomain, accessToken)
	if err != nil {
		return nil, err
	}
	webhook := goshopify.Webhook{
		Topic:   topic,
		Address: address,
		Format:  "json",
	}
	created, err := client.Webhook.Create(ctx, webhook)
	if err != nil {
		return nil, fmt.Errorf("failed to create webhook: %w", err)
	}
	return created, nil
}

func (c *client) GetWebhook(ctx context.Context, shopDomain string, accessToken string, webhookID int64) (*goshopify.Webhook, error) {
	client, err := c.createClient(shopDomain, accessToken)
	if err != nil {
		return nil, err
	}
	webhook, err := client.Webhook.Get(ctx, uint64(webhookID), nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get webhook: %w", err)
	}
	return webhook, nil
}

func (c *client) ListWebhooks(ctx context.Context, shopDomain string, accessToken string, options interface{}) ([]goshopify.Webhook, error) {
	client, err := c.createClient(shopDomain, accessToken)
	if err != nil {
		return nil, err
	}
	webhooks, err := client.Webhook.List(ctx, options)
	if err != nil {
		return nil, fmt.Errorf("failed to list webhooks: %w", err)
	}
	return webhooks, nil
}

func (c *client) UpdateWebhook(ctx context.Context, shopDomain string, accessToken string, webhookID int64, address string) (*goshopify.Webhook, error) {
	client, err := c.createClient(shopDomain, accessToken)
	if err != nil {
		return nil, err
	}
	// First get the webhook to preserve other fields
	existing, err := client.Webhook.Get(ctx, uint64(webhookID), nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get webhook for update: %w", err)
	}
	// Update address
	existing.Address = address
	updated, err := client.Webhook.Update(ctx, *existing)
	if err != nil {
		return nil, fmt.Errorf("failed to update webhook: %w", err)
	}
	return updated, nil
}

func (c *client) DeleteWebhook(ctx context.Context, shopDomain string, accessToken string, webhookID int64) error {
	client, err := c.createClient(shopDomain, accessToken)
	if err != nil {
		return err
	}
	err = client.Webhook.Delete(ctx, uint64(webhookID))
	if err != nil {
		return fmt.Errorf("failed to delete webhook: %w", err)
	}
	return nil
}

// Collection API

func (c *client) GetCollection(ctx context.Context, shopDomain string, accessToken string, collectionID int64) (*goshopify.Collection, error) {
	client, err := c.createClient(shopDomain, accessToken)
	if err != nil {
		return nil, err
	}
	collection, err := client.Collection.Get(ctx, uint64(collectionID), nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get collection: %w", err)
	}
	return collection, nil
}

func (c *client) ListCollectionProducts(ctx context.Context, shopDomain string, accessToken string, collectionID int64, options interface{}) ([]goshopify.Product, error) {
	client, err := c.createClient(shopDomain, accessToken)
	if err != nil {
		return nil, err
	}
	products, err := client.Collection.ListProducts(ctx, uint64(collectionID), options)
	if err != nil {
		return nil, fmt.Errorf("failed to list collection products: %w", err)
	}
	return products, nil
}

func (c *client) GetCustomCollection(ctx context.Context, shopDomain string, accessToken string, collectionID int64) (*goshopify.CustomCollection, error) {
	client, err := c.createClient(shopDomain, accessToken)
	if err != nil {
		return nil, err
	}
	collection, err := client.CustomCollection.Get(ctx, uint64(collectionID), nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get custom collection: %w", err)
	}
	return collection, nil
}

func (c *client) ListCustomCollections(ctx context.Context, shopDomain string, accessToken string, options interface{}) ([]goshopify.CustomCollection, error) {
	client, err := c.createClient(shopDomain, accessToken)
	if err != nil {
		return nil, err
	}
	collections, err := client.CustomCollection.List(ctx, options)
	if err != nil {
		return nil, fmt.Errorf("failed to list custom collections: %w", err)
	}
	return collections, nil
}

func (c *client) CreateCustomCollection(ctx context.Context, shopDomain string, accessToken string, collection *goshopify.CustomCollection) (*goshopify.CustomCollection, error) {
	client, err := c.createClient(shopDomain, accessToken)
	if err != nil {
		return nil, err
	}
	created, err := client.CustomCollection.Create(ctx, *collection)
	if err != nil {
		return nil, fmt.Errorf("failed to create custom collection: %w", err)
	}
	return created, nil
}

func (c *client) UpdateCustomCollection(ctx context.Context, shopDomain string, accessToken string, collection *goshopify.CustomCollection) (*goshopify.CustomCollection, error) {
	client, err := c.createClient(shopDomain, accessToken)
	if err != nil {
		return nil, err
	}
	updated, err := client.CustomCollection.Update(ctx, *collection)
	if err != nil {
		return nil, fmt.Errorf("failed to update custom collection: %w", err)
	}
	return updated, nil
}

func (c *client) DeleteCustomCollection(ctx context.Context, shopDomain string, accessToken string, collectionID int64) error {
	client, err := c.createClient(shopDomain, accessToken)
	if err != nil {
		return err
	}
	err = client.CustomCollection.Delete(ctx, uint64(collectionID))
	if err != nil {
		return fmt.Errorf("failed to delete custom collection: %w", err)
	}
	return nil
}

// Fulfillment API

func (c *client) ListFulfillments(ctx context.Context, shopDomain string, accessToken string, options interface{}) ([]goshopify.Fulfillment, error) {
	client, err := c.createClient(shopDomain, accessToken)
	if err != nil {
		return nil, err
	}
	fulfillments, err := client.Fulfillment.List(ctx, options)
	if err != nil {
		return nil, fmt.Errorf("failed to list fulfillments: %w", err)
	}
	return fulfillments, nil
}

func (c *client) GetFulfillment(ctx context.Context, shopDomain string, accessToken string, fulfillmentID int64) (*goshopify.Fulfillment, error) {
	client, err := c.createClient(shopDomain, accessToken)
	if err != nil {
		return nil, err
	}
	fulfillment, err := client.Fulfillment.Get(ctx, uint64(fulfillmentID), nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get fulfillment: %w", err)
	}
	return fulfillment, nil
}

func (c *client) CreateFulfillment(ctx context.Context, shopDomain string, accessToken string, fulfillment *goshopify.Fulfillment) (*goshopify.Fulfillment, error) {
	client, err := c.createClient(shopDomain, accessToken)
	if err != nil {
		return nil, err
	}
	created, err := client.Fulfillment.Create(ctx, *fulfillment)
	if err != nil {
		return nil, fmt.Errorf("failed to create fulfillment: %w", err)
	}
	return created, nil
}

func (c *client) UpdateFulfillment(ctx context.Context, shopDomain string, accessToken string, fulfillment *goshopify.Fulfillment) (*goshopify.Fulfillment, error) {
	client, err := c.createClient(shopDomain, accessToken)
	if err != nil {
		return nil, err
	}
	updated, err := client.Fulfillment.Update(ctx, *fulfillment)
	if err != nil {
		return nil, fmt.Errorf("failed to update fulfillment: %w", err)
	}
	return updated, nil
}

func (c *client) CompleteFulfillment(ctx context.Context, shopDomain string, accessToken string, fulfillmentID int64) (*goshopify.Fulfillment, error) {
	client, err := c.createClient(shopDomain, accessToken)
	if err != nil {
		return nil, err
	}
	fulfillment, err := client.Fulfillment.Complete(ctx, uint64(fulfillmentID))
	if err != nil {
		return nil, fmt.Errorf("failed to complete fulfillment: %w", err)
	}
	return fulfillment, nil
}

func (c *client) CancelFulfillment(ctx context.Context, shopDomain string, accessToken string, fulfillmentID int64) (*goshopify.Fulfillment, error) {
	client, err := c.createClient(shopDomain, accessToken)
	if err != nil {
		return nil, err
	}
	fulfillment, err := client.Fulfillment.Cancel(ctx, uint64(fulfillmentID))
	if err != nil {
		return nil, fmt.Errorf("failed to cancel fulfillment: %w", err)
	}
	return fulfillment, nil
}

// Discount Code API

func (c *client) ListDiscountCodes(ctx context.Context, shopDomain string, accessToken string, priceRuleID int64) ([]goshopify.PriceRuleDiscountCode, error) {
	client, err := c.createClient(shopDomain, accessToken)
	if err != nil {
		return nil, err
	}
	codes, err := client.DiscountCode.List(ctx, uint64(priceRuleID))
	if err != nil {
		return nil, fmt.Errorf("failed to list discount codes: %w", err)
	}
	return codes, nil
}

func (c *client) GetDiscountCode(ctx context.Context, shopDomain string, accessToken string, priceRuleID int64, discountCodeID int64) (*goshopify.PriceRuleDiscountCode, error) {
	client, err := c.createClient(shopDomain, accessToken)
	if err != nil {
		return nil, err
	}
	code, err := client.DiscountCode.Get(ctx, uint64(priceRuleID), uint64(discountCodeID))
	if err != nil {
		return nil, fmt.Errorf("failed to get discount code: %w", err)
	}
	return code, nil
}

func (c *client) CreateDiscountCode(ctx context.Context, shopDomain string, accessToken string, priceRuleID int64, discountCode *goshopify.PriceRuleDiscountCode) (*goshopify.PriceRuleDiscountCode, error) {
	client, err := c.createClient(shopDomain, accessToken)
	if err != nil {
		return nil, err
	}
	created, err := client.DiscountCode.Create(ctx, uint64(priceRuleID), *discountCode)
	if err != nil {
		return nil, fmt.Errorf("failed to create discount code: %w", err)
	}
	return created, nil
}

func (c *client) UpdateDiscountCode(ctx context.Context, shopDomain string, accessToken string, priceRuleID int64, discountCode *goshopify.PriceRuleDiscountCode) (*goshopify.PriceRuleDiscountCode, error) {
	client, err := c.createClient(shopDomain, accessToken)
	if err != nil {
		return nil, err
	}
	updated, err := client.DiscountCode.Update(ctx, uint64(priceRuleID), *discountCode)
	if err != nil {
		return nil, fmt.Errorf("failed to update discount code: %w", err)
	}
	return updated, nil
}

func (c *client) DeleteDiscountCode(ctx context.Context, shopDomain string, accessToken string, priceRuleID int64, discountCodeID int64) error {
	client, err := c.createClient(shopDomain, accessToken)
	if err != nil {
		return err
	}
	err = client.DiscountCode.Delete(ctx, uint64(priceRuleID), uint64(discountCodeID))
	if err != nil {
		return fmt.Errorf("failed to delete discount code: %w", err)
	}
	return nil
}
