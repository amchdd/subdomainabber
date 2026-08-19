package notify

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

type WebhookNotifier struct {
	endpoint string
	secret   []byte
	client   *http.Client
}

func NewWebhookNotifier(endpoint, secret string) (*WebhookNotifier, error) {
	parsed, err := url.Parse(endpoint)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil {
		return nil, fmt.Errorf("o webhook genérico deve usar uma URL HTTPS válida sem credenciais")
	}
	if secret == "" {
		return nil, fmt.Errorf("o webhook genérico exige SABBER_WEBHOOK_SECRET")
	}
	client := &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	return &WebhookNotifier{endpoint: endpoint, secret: []byte(secret), client: client}, nil
}

func (notifier *WebhookNotifier) Send(ctx context.Context, event AlertEvent) error {
	payload, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("serializando evento do webhook: %w", err)
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, notifier.endpoint, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-SubdomainAbber-Signature", webhookSignature(notifier.secret, payload))
	response, err := notifier.client.Do(request)
	if err != nil {
		return fmt.Errorf("enviando webhook: %w", err)
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 32<<10))
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return fmt.Errorf("o webhook respondeu com HTTP %d", response.StatusCode)
	}
	return nil
}

func webhookSignature(secret, payload []byte) string {
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write(payload)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}
