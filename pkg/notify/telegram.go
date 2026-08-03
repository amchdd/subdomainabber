package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"html"
	"net/http"
	"os"
	"strings"

	"github.com/amchdd/subdomainabber/internal/presentation"
)

type TelegramNotifier struct {
	token  string
	chatID string
	client *http.Client
}

func NewTelegramNotifier() *TelegramNotifier {
	token := os.Getenv("TELEGRAM_BOT_TOKEN")
	chatID := os.Getenv("TELEGRAM_CHAT_ID")
	if token == "" || chatID == "" {
		return nil
	}
	return &TelegramNotifier{token: token, chatID: chatID, client: http.DefaultClient}
}

func newTelegramNotifierFromConfig(value string) (*TelegramNotifier, error) {
	separator := strings.LastIndex(value, ":")
	if separator <= 0 || separator == len(value)-1 {
		return nil, fmt.Errorf("SABBER_TELEGRAM deve conter o token do bot e o identificador do chat no formato token_do_bot:identificador_do_chat")
	}
	token := strings.TrimSpace(value[:separator])
	chatID := strings.TrimSpace(value[separator+1:])
	if token == "" || chatID == "" {
		return nil, fmt.Errorf("SABBER_TELEGRAM deve conter o token do bot e o identificador do chat no formato token_do_bot:identificador_do_chat")
	}
	return &TelegramNotifier{token: token, chatID: chatID, client: http.DefaultClient}, nil
}

func (t *TelegramNotifier) Send(ctx context.Context, event AlertEvent) error {
	text := telegramMessage(event)

	payload := map[string]interface{}{
		"chat_id":    t.chatID,
		"text":       text,
		"parse_mode": "HTML",
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("não foi possível preparar a notificação do Telegram")
	}
	url := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", t.token)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewBuffer(body))
	if err != nil {
		return fmt.Errorf("não foi possível preparar a notificação do Telegram")
	}
	req.Header.Set("Content-Type", "application/json")

	client := t.client
	if client == nil {
		client = http.DefaultClient
	}
	resp, err := client.Do(req)
	if err != nil {
		return notificationTransportError("Telegram", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return fmt.Errorf("telegram respondeu com status: %d", resp.StatusCode)
	}

	return nil
}

func telegramMessage(event AlertEvent) string {
	text := fmt.Sprintf("<b>[%s] %s</b>\n\n<b>Transição:</b> %s -> %s\n<b>Severidade:</b> %s\n<b>Pontuação:</b> %d\n<b>Evidência:</b> %s",
		html.EscapeString(presentation.StateChange(event.StateChange)),
		html.EscapeString(event.Host),
		html.EscapeString(presentation.Classification(event.PreviousState)),
		html.EscapeString(presentation.Classification(event.CurrentState)),
		html.EscapeString(presentation.Severity(string(event.Severity))),
		event.Score,
		html.EscapeString(event.Evidences),
	)
	return text
}
