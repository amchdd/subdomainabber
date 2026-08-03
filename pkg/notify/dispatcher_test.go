package notify

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/amchdd/subdomainabber/internal/classification"
	"github.com/amchdd/subdomainabber/internal/core"
)

func TestDispatcherUsesMergedNotificationConfig(t *testing.T) {
	t.Setenv("DISCORD_WEBHOOK_URL", "")
	t.Setenv("TELEGRAM_BOT_TOKEN", "")
	t.Setenv("TELEGRAM_CHAT_ID", "")

	dispatcher, err := NewDispatcherWithConfig(1, "https://discord.example.invalid/webhook", "123456:token:-987654")
	if err != nil {
		t.Fatal(err)
	}
	defer dispatcher.Flush()
	if len(dispatcher.notifiers) != 2 {
		t.Fatalf("quantidade de notificadores = %d; esperado: 2", len(dispatcher.notifiers))
	}
	telegram, ok := dispatcher.notifiers[1].(*TelegramNotifier)
	if !ok || telegram.token != "123456:token" || telegram.chatID != "-987654" {
		t.Fatalf("a configuração do Telegram foi interpretada incorretamente: %#v", dispatcher.notifiers[1])
	}
}

func TestDispatcherRejectsMalformedTelegramConfig(t *testing.T) {
	_, err := NewDispatcherWithConfig(1, "", "missing-separator")
	if err == nil {
		t.Fatal("uma configuração inválida do Telegram foi aceita")
	}
	if !strings.Contains(err.Error(), "token do bot e o identificador do chat") {
		t.Fatalf("mensagem de erro inesperada: %q", err)
	}
}

func TestDispatchAnalysisSendsRelevantInitialFindingToDiscord(t *testing.T) {
	t.Setenv("DISCORD_WEBHOOK_URL", "")
	t.Setenv("TELEGRAM_BOT_TOKEN", "")
	t.Setenv("TELEGRAM_CHAT_ID", "")

	var requests atomic.Int32
	var payload string
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		requests.Add(1)
		body, _ := io.ReadAll(request.Body)
		payload = string(body)
		response.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	dispatcher, err := NewDispatcherWithConfig(1, server.URL, "")
	if err != nil {
		t.Fatal(err)
	}
	dispatcher.DispatchAnalysis(&core.HostAnalysis{
		Host:           "assets.example.com",
		Classification: classification.LevelLikelyTakeoverable,
		RiskScore:      80,
		Evidences: []core.Evidence{{
			Type: "HTTP_BODY_MATCH",
		}},
	})
	dispatcher.Flush()

	if requests.Load() != 1 {
		t.Fatalf("requisições ao Discord = %d; esperado: 1", requests.Load())
	}
	for _, expected := range []string{"DESCOBERTO", "assets.example.com", "TAKEOVER PROVÁVEL", "HTTP_BODY_MATCH", "Evidência causal", "Notificado em:"} {
		if !strings.Contains(payload, expected) {
			t.Fatalf("o payload do Discord não contém %q: %s", expected, payload)
		}
	}
	if strings.Contains(payload, "Alertado em:") {
		t.Fatalf("o payload do Discord ainda usa o texto antigo: %s", payload)
	}
}

func TestDispatchAnalysisSuppressesUnknownResult(t *testing.T) {
	t.Setenv("DISCORD_WEBHOOK_URL", "")
	t.Setenv("TELEGRAM_BOT_TOKEN", "")
	t.Setenv("TELEGRAM_CHAT_ID", "")

	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		requests.Add(1)
	}))
	defer server.Close()

	dispatcher, err := NewDispatcherWithConfig(1, server.URL, "")
	if err != nil {
		t.Fatal(err)
	}
	dispatcher.DispatchAnalysis(&core.HostAnalysis{Host: "unknown.example.com", Classification: classification.LevelUnknown})
	dispatcher.Flush()
	if requests.Load() != 0 {
		t.Fatalf("o Discord recebeu %d alertas ruidosos de resultado UNKNOWN", requests.Load())
	}
}

func TestDispatchAnalysisSuppressesHealthyResultEvenAtInfoThreshold(t *testing.T) {
	t.Setenv("DISCORD_WEBHOOK_URL", "")
	t.Setenv("TELEGRAM_BOT_TOKEN", "")
	t.Setenv("TELEGRAM_CHAT_ID", "")

	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		requests.Add(1)
	}))
	defer server.Close()

	dispatcher, err := NewDispatcherWithOptions(DispatcherConfig{
		Workers: 1, DiscordWebhook: server.URL, MinimumSeverity: "info",
	})
	if err != nil {
		t.Fatal(err)
	}
	dispatcher.DispatchAnalysis(&core.HostAnalysis{Host: "healthy.example.com", Classification: classification.LevelHealthy})
	dispatcher.Flush()
	if requests.Load() != 0 {
		t.Fatalf("o Discord recebeu %d alertas ruidosos de resultado HEALTHY", requests.Load())
	}
}

func TestAlertContextUsesSharedCausalHTTPVector(t *testing.T) {
	analysis := &core.HostAnalysis{
		Host: "app.example.com",
		Evidences: []core.Evidence{{
			Type: "HTTP_HSTS_MISSING", Description: "HSTS ausente",
		}},
	}
	vector, resource, evidence := alertContext(analysis)
	if vector != "HTTP" || resource != analysis.Host || !strings.Contains(evidence, "HTTP_HSTS_MISSING") {
		t.Fatalf("contexto de alerta inesperado: vetor=%s recurso=%s evidência=%s", vector, resource, evidence)
	}
}

func TestDispatcherDeduplicatesDelegationAlertsByZoneCut(t *testing.T) {
	t.Setenv("DISCORD_WEBHOOK_URL", "")
	t.Setenv("TELEGRAM_BOT_TOKEN", "")
	t.Setenv("TELEGRAM_CHAT_ID", "")

	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		response.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	dispatcher, err := NewDispatcherWithOptions(DispatcherConfig{
		Workers: 1, DiscordWebhook: server.URL, MinimumSeverity: "medium",
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, host := range []string{"one.projects.example.com", "two.projects.example.com"} {
		dispatcher.DispatchAnalysis(&core.HostAnalysis{
			Host: host, Classification: classification.LevelDelegationTakeoverCandidate,
			Delegation: &core.DelegationCandidate{Zone: "projects.example.com"},
			Evidences:  []core.Evidence{{Type: "DELEGATION_TAKEOVER_CANDIDATE"}},
		})
	}
	dispatcher.Flush()
	if requests.Load() != 1 {
		t.Fatalf("requisições ao Discord = %d; esperado: um alerta por corte de zona", requests.Load())
	}
}

func TestNotificationSeverityFollowsClassificationRisk(t *testing.T) {
	dispatcher := &Dispatcher{}
	tests := []struct {
		old  string
		new  string
		want AlertSeverity
	}{
		{"", classification.LevelMisconfigured, SeverityLow},
		{"", classification.LevelLikelyTakeoverable, SeverityMedium},
		{"", classification.LevelTakeoverable, SeverityHigh},
		{classification.LevelTakeoverable, classification.LevelConfirmed, SeverityHigh},
		{classification.LevelTakenOver, classification.LevelMisconfigured, SeverityInfo},
		{classification.LevelOrphaned, classification.LevelHealthy, SeverityInfo},
		{"", classification.LevelUnknown, SeverityInfo},
	}
	for _, tt := range tests {
		got := dispatcher.mapSeverity(tt.old, tt.new)
		if got != tt.want {
			t.Fatalf("mapSeverity(%q, %q) = %q; esperado: %q", tt.old, tt.new, got, tt.want)
		}
	}
}

type notifierFunc func(context.Context, AlertEvent) error

func (notifier notifierFunc) Send(ctx context.Context, event AlertEvent) error {
	return notifier(ctx, event)
}

func TestDispatcherAllowsConcurrentDispatchAndRepeatedFlush(t *testing.T) {
	t.Setenv("DISCORD_WEBHOOK_URL", "")
	t.Setenv("TELEGRAM_BOT_TOKEN", "")
	t.Setenv("TELEGRAM_CHAT_ID", "")

	dispatcher, err := NewDispatcherWithOptions(DispatcherConfig{Workers: 2, MinimumSeverity: "low"})
	if err != nil {
		t.Fatal(err)
	}
	dispatcher.notifiers = []Notifier{notifierFunc(func(context.Context, AlertEvent) error { return nil })}

	const dispatches = 200
	start := make(chan struct{})
	var callers sync.WaitGroup
	for index := 0; index < dispatches; index++ {
		callers.Add(1)
		go func(index int) {
			defer callers.Done()
			<-start
			dispatcher.DispatchAnalysis(&core.HostAnalysis{
				Host:           fmt.Sprintf("host-%d.example.com", index),
				Classification: classification.LevelMisconfigured,
				Evidences:      []core.Evidence{{Type: "HTTP_HSTS_MISSING"}},
			})
		}(index)
	}

	flushDone := make(chan struct{})
	go func() {
		defer close(flushDone)
		<-start
		dispatcher.Flush()
		dispatcher.Flush()
	}()

	close(start)
	callers.Wait()
	select {
	case <-flushDone:
	case <-time.After(5 * time.Second):
		t.Fatal("Flush não terminou apó as chamadas concorrentes de Dispatch")
	}

	// Uma chamada posterior ao fechamento deve ser ignorada, sem pânico.
	dispatcher.DispatchAnalysis(&core.HostAnalysis{
		Host:           "depois-do-fechamento.example.com",
		Classification: classification.LevelMisconfigured,
	})
	dispatcher.Flush()
}

func TestFlushAcceptsZeroValueAndRepeatedCalls(t *testing.T) {
	dispatcher := &Dispatcher{}
	dispatcher.Flush()
	dispatcher.Flush()
}
