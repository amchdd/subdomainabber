package notify

import (
	"bytes"
	"context"
	"errors"
	"log"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/amchdd/subdomainabber/internal/classification"
	"github.com/amchdd/subdomainabber/internal/core"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (roundTrip roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return roundTrip(request)
}

func credentialBearingTransportError(request *http.Request) (*http.Response, error) {
	requestURL := request.URL.String()
	return nil, &url.Error{
		Op:  request.Method,
		URL: requestURL,
		Err: errors.New("falha simulada ao acessar " + requestURL),
	}
}

func TestDiscordErrorDoesNotExposeWebhookURL(t *testing.T) {
	const webhook = "https://discord.example.invalid/api/webhooks/123/segredo-do-webhook"
	notifier := newDiscordNotifier(webhook)
	notifier.client = &http.Client{Transport: roundTripFunc(credentialBearingTransportError)}

	err := notifier.Send(context.Background(), AlertEvent{})
	assertErrorDoesNotContainSecrets(t, err, webhook, "segredo-do-webhook")
}

func TestTelegramErrorDoesNotExposeBotToken(t *testing.T) {
	const token = "123456:segredo-do-token"
	notifier := &TelegramNotifier{
		token:  token,
		chatID: "-987654",
		client: &http.Client{Transport: roundTripFunc(credentialBearingTransportError)},
	}

	err := notifier.Send(context.Background(), AlertEvent{})
	assertErrorDoesNotContainSecrets(t, err, token, "segredo-do-token")
}

func TestDispatcherLogDoesNotExposeDiscordWebhookURL(t *testing.T) {
	t.Setenv("DISCORD_WEBHOOK_URL", "")
	t.Setenv("TELEGRAM_BOT_TOKEN", "")
	t.Setenv("TELEGRAM_CHAT_ID", "")

	const webhook = "https://discord.example.invalid/api/webhooks/123/segredo-do-webhook"
	dispatcher, err := NewDispatcherWithOptions(DispatcherConfig{
		Workers: 1, DiscordWebhook: webhook, MinimumSeverity: "low",
	})
	if err != nil {
		t.Fatal(err)
	}
	discord := dispatcher.notifiers[0].(*DiscordNotifier)
	discord.client = &http.Client{Transport: roundTripFunc(credentialBearingTransportError)}

	var output bytes.Buffer
	previousOutput := log.Writer()
	log.SetOutput(&output)
	t.Cleanup(func() { log.SetOutput(previousOutput) })

	dispatcher.DispatchAnalysis(&core.HostAnalysis{
		Host:           "app.example.com",
		Classification: classification.LevelMisconfigured,
		Evidences:      []core.Evidence{{Type: "HTTP_HSTS_MISSING"}},
	})
	dispatcher.Flush()

	for _, secret := range []string{webhook, "segredo-do-webhook"} {
		if strings.Contains(output.String(), secret) {
			t.Fatalf("o log expôs uma credencial de notificação: %q", output.String())
		}
	}
}

func TestPreparationErrorsDoNotExposeNotificationCredentials(t *testing.T) {
	discordWebhook := "https://discord.example.invalid/api/webhooks/123/segredo%zz"
	discordErr := newDiscordNotifier(discordWebhook).Send(context.Background(), AlertEvent{})
	assertErrorDoesNotContainSecrets(t, discordErr, discordWebhook, "segredo")

	telegramToken := "123456:segredo\ndo-token"
	telegramErr := (&TelegramNotifier{token: telegramToken, chatID: "-987654"}).Send(context.Background(), AlertEvent{})
	assertErrorDoesNotContainSecrets(t, telegramErr, telegramToken, "segredo", "do-token")
}

func assertErrorDoesNotContainSecrets(t *testing.T, err error, secrets ...string) {
	t.Helper()
	if err == nil {
		t.Fatal("era esperado um erro de notificação")
	}
	message := err.Error()
	for _, secret := range secrets {
		if secret != "" && strings.Contains(message, secret) {
			t.Fatalf("o erro expôs uma credencial de notificação: %q", message)
		}
	}
}
