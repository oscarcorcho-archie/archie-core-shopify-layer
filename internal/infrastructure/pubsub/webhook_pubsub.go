package pubsub

import (
	"context"
	"fmt"
	"sync"

	"archie-core-shopify-layer/internal/domain"

	"github.com/rs/zerolog"
)

// WebhookEventChannel represents a subscription channel
type WebhookEventChannel struct {
	ID     string
	Filter *WebhookEventFilter
	Events chan *domain.WebhookEvent
	Done   chan struct{}
	ctx    context.Context
	cancel context.CancelFunc
}

// WebhookEventFilter filters webhook events
type WebhookEventFilter struct {
	Topics []string // Filter by topics
	Shop   string   // Filter by shop domain
}

// WebhookPubSub manages webhook event subscriptions
type WebhookPubSub struct {
	mu       sync.RWMutex
	channels map[string]*WebhookEventChannel
	logger   zerolog.Logger
	nextID   int64
	idMu     sync.Mutex
}

// NewWebhookPubSub creates a new webhook pub/sub system
func NewWebhookPubSub(logger zerolog.Logger) *WebhookPubSub {
	return &WebhookPubSub{
		channels: make(map[string]*WebhookEventChannel),
		logger:   logger,
	}
}

// Subscribe creates a new subscription channel
func (ps *WebhookPubSub) Subscribe(ctx context.Context, filter *WebhookEventFilter) *WebhookEventChannel {
	ps.idMu.Lock()
	id := ps.generateID()
	ps.idMu.Unlock()

	subCtx, cancel := context.WithCancel(ctx)

	channel := &WebhookEventChannel{
		ID:     id,
		Filter: filter,
		Events: make(chan *domain.WebhookEvent, 10), // Buffered channel
		Done:   make(chan struct{}),
		ctx:    subCtx,
		cancel: cancel,
	}

	ps.mu.Lock()
	ps.channels[id] = channel
	ps.mu.Unlock()

	ps.logger.Info().
		Str("channelId", id).
		Interface("filter", filter).
		Msg("Webhook subscription created")

	// Cleanup when context is cancelled
	go func() {
		<-subCtx.Done()
		ps.Unsubscribe(id)
	}()

	return channel
}

// Unsubscribe removes a subscription channel
func (ps *WebhookPubSub) Unsubscribe(channelID string) {
	ps.mu.Lock()
	defer ps.mu.Unlock()

	channel, exists := ps.channels[channelID]
	if !exists {
		return
	}

	close(channel.Events)
	close(channel.Done)
	channel.cancel()
	delete(ps.channels, channelID)

	ps.logger.Info().
		Str("channelId", channelID).
		Msg("Webhook subscription removed")
}

// Publish broadcasts a webhook event to all matching subscribers
func (ps *WebhookPubSub) Publish(event *domain.WebhookEvent) {
	ps.mu.RLock()
	defer ps.mu.RUnlock()

	publishedCount := 0
	for _, channel := range ps.channels {
		// Check if event matches filter
		if ps.matchesFilter(event, channel.Filter) {
			select {
			case channel.Events <- event:
				publishedCount++
			case <-channel.ctx.Done():
				// Channel is closed, skip
			default:
				// Channel buffer full, skip (non-blocking)
				ps.logger.Warn().
					Str("channelId", channel.ID).
					Msg("Channel buffer full, dropping event")
			}
		}
	}

	if publishedCount > 0 {
		ps.logger.Debug().
			Str("topic", event.Topic).
			Str("shop", event.Shop).
			Int("subscribers", publishedCount).
			Msg("Published webhook event to subscribers")
	}
}

// matchesFilter checks if an event matches the subscription filter
func (ps *WebhookPubSub) matchesFilter(event *domain.WebhookEvent, filter *WebhookEventFilter) bool {
	if filter == nil {
		return true // No filter, match all
	}

	// Check topic filter
	if len(filter.Topics) > 0 {
		topicMatch := false
		for _, topic := range filter.Topics {
			if event.Topic == topic {
				topicMatch = true
				break
			}
		}
		if !topicMatch {
			return false
		}
	}

	// Check shop filter
	if filter.Shop != "" && event.Shop != filter.Shop {
		return false
	}

	return true
}

// generateID generates a unique channel ID
func (ps *WebhookPubSub) generateID() string {
	ps.nextID++
	return fmt.Sprintf("channel-%d", ps.nextID)
}

// GetStats returns pub/sub statistics
func (ps *WebhookPubSub) GetStats() map[string]interface{} {
	ps.mu.RLock()
	defer ps.mu.RUnlock()

	return map[string]interface{}{
		"active_subscriptions": len(ps.channels),
	}
}
