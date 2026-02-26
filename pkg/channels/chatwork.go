package channels

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/sipeed/picoclaw/pkg/bus"
	"github.com/sipeed/picoclaw/pkg/config"
	"github.com/sipeed/picoclaw/pkg/logger"
	"github.com/sipeed/picoclaw/pkg/utils"
)

const chatworkAPIBase = "https://api.chatwork.com/v2"

// ChatworkChannel implements the Channel interface for Chatwork
// using HTTP webhook for receiving messages and REST API for sending.
type ChatworkChannel struct {
	*BaseChannel
	config     config.ChatworkConfig
	httpServer *http.Server
	ctx        context.Context
	cancel     context.CancelFunc
}

// NewChatworkChannel creates a new Chatwork channel instance.
func NewChatworkChannel(cfg config.ChatworkConfig, messageBus *bus.MessageBus) (*ChatworkChannel, error) {
	if cfg.APIToken == "" {
		return nil, fmt.Errorf("chatwork api_token is required")
	}

	base := NewBaseChannel("chatwork", cfg, messageBus, cfg.AllowFrom)

	return &ChatworkChannel{
		BaseChannel: base,
		config:      cfg,
	}, nil
}

// Start launches the HTTP webhook server.
func (c *ChatworkChannel) Start(ctx context.Context) error {
	logger.InfoC("chatwork", "Starting Chatwork channel")

	c.ctx, c.cancel = context.WithCancel(ctx)

	mux := http.NewServeMux()
	path := c.config.WebhookPath
	if path == "" {
		path = "/webhook/chatwork"
	}
	mux.HandleFunc(path, c.webhookHandler)

	addr := fmt.Sprintf("%s:%d", c.config.WebhookHost, c.config.WebhookPort)
	c.httpServer = &http.Server{
		Addr:    addr,
		Handler: mux,
	}

	go func() {
		logger.InfoCF("chatwork", "Chatwork webhook server listening", map[string]any{
			"addr": addr,
			"path": path,
		})
		if err := c.httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.ErrorCF("chatwork", "Webhook server error", map[string]any{
				"error": err.Error(),
			})
		}
	}()

	c.setRunning(true)
	logger.InfoC("chatwork", "Chatwork channel started")
	return nil
}

// Stop gracefully shuts down the HTTP server.
func (c *ChatworkChannel) Stop(ctx context.Context) error {
	logger.InfoC("chatwork", "Stopping Chatwork channel")

	if c.cancel != nil {
		c.cancel()
	}

	if c.httpServer != nil {
		shutdownCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		if err := c.httpServer.Shutdown(shutdownCtx); err != nil {
			logger.ErrorCF("chatwork", "Webhook server shutdown error", map[string]any{
				"error": err.Error(),
			})
		}
	}

	c.setRunning(false)
	logger.InfoC("chatwork", "Chatwork channel stopped")
	return nil
}

// webhookHandler handles incoming Chatwork webhook requests.
func (c *ChatworkChannel) webhookHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		logger.ErrorCF("chatwork", "Failed to read request body", map[string]any{
			"error": err.Error(),
		})
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}

	// Verify signature if webhook_token is configured
	if c.config.WebhookToken != "" {
		signature := r.Header.Get("X-ChatWorkWebhookSignature")
		if !c.verifySignature(body, signature) {
			logger.WarnC("chatwork", "Invalid webhook signature")
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}
	}

	var payload chatworkWebhookPayload
	if err := json.Unmarshal(body, &payload); err != nil {
		logger.ErrorCF("chatwork", "Failed to parse webhook payload", map[string]any{
			"error": err.Error(),
		})
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}

	// Return 200 immediately, process event asynchronously
	w.WriteHeader(http.StatusOK)

	go c.processEvent(payload)
}

// verifySignature validates the X-ChatWorkWebhookSignature using HMAC-SHA256.
func (c *ChatworkChannel) verifySignature(body []byte, signature string) bool {
	if signature == "" {
		return false
	}

	// Chatwork webhook token is base64-encoded; decode it first
	key, err := base64.StdEncoding.DecodeString(c.config.WebhookToken)
	if err != nil {
		logger.ErrorCF("chatwork", "Failed to decode webhook token", map[string]any{
			"error": err.Error(),
		})
		return false
	}

	mac := hmac.New(sha256.New, key)
	mac.Write(body)
	expected := base64.StdEncoding.EncodeToString(mac.Sum(nil))

	return hmac.Equal([]byte(expected), []byte(signature))
}

// Chatwork webhook payload types
type chatworkWebhookPayload struct {
	WebhookSettingID string              `json:"webhook_setting_id"`
	WebhookEventType string              `json:"webhook_event_type"`
	WebhookEventTime int64               `json:"webhook_event_time"`
	WebhookEvent     chatworkWebhookEvent `json:"webhook_event"`
}

type chatworkWebhookEvent struct {
	MessageID  string `json:"message_id"`
	RoomID     int64  `json:"room_id"`
	AccountID  int64  `json:"account_id"`
	Body       string `json:"body"`
	SendTime   int64  `json:"send_time"`
	UpdateTime int64  `json:"update_time"`
}

func (c *ChatworkChannel) processEvent(payload chatworkWebhookPayload) {
	if payload.WebhookEventType != "room_message_created" {
		logger.DebugCF("chatwork", "Ignoring non-message event", map[string]any{
			"type": payload.WebhookEventType,
		})
		return
	}

	event := payload.WebhookEvent
	senderID := fmt.Sprintf("%d", event.AccountID)
	chatID := fmt.Sprintf("%d", event.RoomID)
	content := event.Body

	if strings.TrimSpace(content) == "" {
		return
	}

	metadata := map[string]string{
		"platform":   "chatwork",
		"message_id": event.MessageID,
		"peer_kind":  "group",
		"peer_id":    chatID,
	}

	logger.DebugCF("chatwork", "Received message", map[string]any{
		"sender_id": senderID,
		"chat_id":   chatID,
		"preview":   utils.Truncate(content, 50),
	})

	c.HandleMessage(senderID, chatID, content, nil, metadata)
}

// Send sends a message to a Chatwork room.
func (c *ChatworkChannel) Send(ctx context.Context, msg bus.OutboundMessage) error {
	if !c.IsRunning() {
		return fmt.Errorf("chatwork channel not running")
	}

	endpoint := fmt.Sprintf("%s/rooms/%s/messages", chatworkAPIBase, msg.ChatID)

	form := url.Values{}
	form.Set("body", msg.Content)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-ChatWorkToken", c.config.APIToken)

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("API request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("chatwork API error (status %d): %s", resp.StatusCode, string(respBody))
	}

	logger.DebugCF("chatwork", "Message sent", map[string]any{
		"chat_id": msg.ChatID,
	})

	return nil
}
