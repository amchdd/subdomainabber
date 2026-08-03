package notify

import (
	"strings"
	"testing"

	"github.com/amchdd/subdomainabber/internal/verify"
)

func TestTelegramMessageUsesPortugueseAndEscapesHTML(t *testing.T) {
	message := telegramMessage(AlertEvent{
		Host:          "api.<exemplo>.com",
		PreviousState: "HEALTHY",
		CurrentState:  "LIKELY_TAKEOVERABLE",
		StateChange:   verify.Regressed,
		Score:         90,
		Severity:      SeverityMedium,
		Evidences:     "HTTP_BODY_MATCH — <fingerprint>",
	})

	for _, expected := range []string{
		"REGREDIU",
		"Transição:",
		"SAUDÁVEL",
		"TAKEOVER PROVÁVEL",
		"Severidade:",
		"MÉDIA",
		"Pontuação:",
		"Evidência:",
		"api.&lt;exemplo&gt;.com",
		"&lt;fingerprint&gt;",
	} {
		if !strings.Contains(message, expected) {
			t.Fatalf("mensagem Telegram não contém %q:\n%s", expected, message)
		}
	}
	if strings.Contains(message, "<fingerprint>") {
		t.Fatalf("a evidência não foi escapada: %s", message)
	}
}
