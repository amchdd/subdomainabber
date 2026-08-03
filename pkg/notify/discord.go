package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/amchdd/subdomainabber/internal/presentation"
)

type DiscordNotifier struct {
	webhookURL string
	client     *http.Client
}

func NewDiscordNotifier() *DiscordNotifier {
	return newDiscordNotifier(os.Getenv("DISCORD_WEBHOOK_URL"))
}

func newDiscordNotifier(url string) *DiscordNotifier {
	if strings.TrimSpace(url) == "" {
		return nil
	}
	return &DiscordNotifier{webhookURL: url, client: http.DefaultClient}
}

func (notifier *DiscordNotifier) Send(ctx context.Context, event AlertEvent) error {
	title := fmt.Sprintf("[%s] %s - %s", presentation.Severity(string(event.Severity)), event.Vector, event.Resource)
	fields := []map[string]interface{}{}
	addField := func(name, value string, inline bool) {
		if strings.TrimSpace(value) != "" {
			fields = append(fields, map[string]interface{}{"name": name, "value": value, "inline": inline})
		}
	}

	addField("Evento", presentation.StateChange(event.StateChange), true)
	addField("Classificação", presentation.Classification(event.CurrentState), true)
	addField("Severidade", presentation.Severity(string(event.Severity)), true)
	addField("Pontuação de risco", fmt.Sprint(event.Score), true)
	addField("Host observado", event.Host, false)
	if event.PreviousState != "" {
		addField("Transição", presentation.Classification(event.PreviousState)+" -> "+presentation.Classification(event.CurrentState), false)
	}
	addField("Evidência causal", event.Evidences, false)

	payload := map[string]interface{}{
		"allowed_mentions": map[string]interface{}{"parse": []string{}},
		"embeds": []map[string]interface{}{{
			"title":  title,
			"color":  discordColor(event.Severity),
			"fields": fields,
			"footer": map[string]interface{}{
				"text": fmt.Sprintf("Notificado em: %s", event.ChangedAt.UTC().Format("2006-01-02 15:04:05 UTC")),
			},
		}},
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("não foi possível preparar a notificação do Discord")
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, notifier.webhookURL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("não foi possível preparar a notificação do Discord")
	}
	request.Header.Set("Content-Type", "application/json")

	response, err := notifier.client.Do(request)
	if err != nil {
		return notificationTransportError("Discord", err)
	}
	defer response.Body.Close()
	if response.StatusCode >= http.StatusBadRequest {
		return fmt.Errorf("discord retornou HTTP %d", response.StatusCode)
	}
	return nil
}

func discordColor(severity AlertSeverity) int {
	switch severity {
	case SeverityCritical:
		return 0xED4245
	case SeverityHigh:
		return 0xE67E22
	case SeverityMedium:
		return 0xF1C40F
	case SeverityLow:
		return 0x3498DB
	default:
		return 0x57F287
	}
}
