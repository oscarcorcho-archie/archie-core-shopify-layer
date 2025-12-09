package shopify

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"archie-core-shopify-layer/internal/ports"
	"github.com/rs/zerolog"
)

// TokenManager manages Shopify access tokens with refresh capabilities
type TokenManager struct {
	encryptionSvc ports.EncryptionService
	logger        zerolog.Logger
}

// NewTokenManager creates a new token manager
func NewTokenManager(encryptionSvc ports.EncryptionService, logger zerolog.Logger) *TokenManager {
	return &TokenManager{
		encryptionSvc: encryptionSvc,
		logger:        logger,
	}
}

// EncryptToken encrypts an access token before storage
func (tm *TokenManager) EncryptToken(token string) (string, error) {
	if token == "" {
		return "", fmt.Errorf("token cannot be empty")
	}
	return tm.encryptionSvc.Encrypt(token)
}

// DecryptToken decrypts an access token after retrieval
func (tm *TokenManager) DecryptToken(encryptedToken string) (string, error) {
	if encryptedToken == "" {
		return "", fmt.Errorf("encrypted token cannot be empty")
	}
	return tm.encryptionSvc.Decrypt(encryptedToken)
}

// TokenInfo represents token metadata
type TokenInfo struct {
	Token       string
	ExpiresAt   *time.Time
	Scopes      []string
	ShopDomain  string
	LastUsed    time.Time
}

// ValidateToken checks if a token is still valid by making a lightweight API call to Shopify
// Note: Shopify access tokens don't expire unless revoked, but we can check if they're still valid
// This method requires a ShopifyClient to make the validation API call
func (tm *TokenManager) ValidateToken(ctx context.Context, client ports.ShopifyClient, token string, shopDomain string) (bool, error) {
	if token == "" {
		return false, fmt.Errorf("token is empty")
	}

	if shopDomain == "" {
		return false, fmt.Errorf("shop domain is required for token validation")
	}

	// Make a lightweight API call to Shopify to verify token validity
	// Using GetShop as it's the simplest endpoint and returns shop info
	// If the token is invalid, Shopify will return a 401 Unauthorized error
	_, err := client.GetShop(ctx, shopDomain, token)
	if err != nil {
		// Check if error is due to authentication failure
		// The go-shopify library wraps HTTP errors, so we check the error message
		errStr := strings.ToLower(err.Error())
		if strings.Contains(errStr, "401") ||
			strings.Contains(errStr, "unauthorized") ||
			strings.Contains(errStr, "authentication") ||
			strings.Contains(errStr, "invalid token") ||
			strings.Contains(errStr, "forbidden") {
			tm.logger.Warn().
				Str("shop", shopDomain).
				Msg("Token validation failed: token is invalid or revoked")
			return false, nil // Token is invalid
		}

		// Other errors (network, timeout, etc.) - we'll assume token is valid
		// but log the error for investigation
		tm.logger.Warn().
			Err(err).
			Str("shop", shopDomain).
			Msg("Token validation encountered an error (assuming token is valid)")
		return true, nil
	}

	// Success - token is valid
	tm.logger.Debug().
		Str("shop", shopDomain).
		Msg("Token validation successful")
	return true, nil
}

// ValidateTokenWithHTTP makes a direct HTTP call to validate a token
// This is an alternative implementation that doesn't require a ShopifyClient
func (tm *TokenManager) ValidateTokenWithHTTP(ctx context.Context, token string, shopDomain string) (bool, error) {
	if token == "" {
		return false, fmt.Errorf("token is empty")
	}

	if shopDomain == "" {
		return false, fmt.Errorf("shop domain is required for token validation")
	}

	// Normalize shop domain (ensure it has .myshopify.com or is a custom domain)
	shopURL := shopDomain
	if !strings.Contains(shopDomain, ".") {
		shopURL = shopDomain + ".myshopify.com"
	}
	if !strings.HasPrefix(shopURL, "https://") {
		shopURL = "https://" + shopURL
	}

	// Make a lightweight API call to Shopify Admin API
	// Using the shop.json endpoint as it's the simplest
	url := fmt.Sprintf("%s/admin/api/2024-01/shop.json", shopURL)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return false, fmt.Errorf("failed to create request: %w", err)
	}

	// Set authorization header with access token
	req.Header.Set("X-Shopify-Access-Token", token)
	req.Header.Set("Content-Type", "application/json")

	// Make the request
	client := &http.Client{
		Timeout: 10 * time.Second,
	}
	resp, err := client.Do(req)
	if err != nil {
		// Network error - assume token is valid but log for investigation
		tm.logger.Warn().
			Err(err).
			Str("shop", shopDomain).
			Msg("Token validation network error (assuming token is valid)")
		return true, nil
	}
	defer resp.Body.Close()

	// Check response status
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		tm.logger.Warn().
			Int("status", resp.StatusCode).
			Str("shop", shopDomain).
			Msg("Token validation failed: token is invalid or revoked")
		return false, nil // Token is invalid
	}

	if resp.StatusCode != http.StatusOK {
		// Other HTTP errors - assume token is valid but log for investigation
		tm.logger.Warn().
			Int("status", resp.StatusCode).
			Str("shop", shopDomain).
			Msg("Token validation returned non-OK status (assuming token is valid)")
		return true, nil
	}

	// Success - token is valid
	tm.logger.Debug().
		Str("shop", shopDomain).
		Msg("Token validation successful")
	return true, nil
}

// ShouldRefresh checks if a token should be refreshed
// Shopify tokens don't expire, but they can be revoked
func (tm *TokenManager) ShouldRefresh(tokenInfo *TokenInfo) bool {
	// Shopify access tokens don't expire, but we can check:
	// 1. If token hasn't been used in a long time (stale)
	// 2. If we've received errors indicating token is invalid

	if tokenInfo.ExpiresAt != nil && time.Now().After(*tokenInfo.ExpiresAt) {
		return true
	}

	// Check if token is stale (not used in 30 days)
	staleThreshold := 30 * 24 * time.Hour
	if time.Since(tokenInfo.LastUsed) > staleThreshold {
		return true
	}

	return false
}

