package notify

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestWebhookSignsPayload(t *testing.T) {
	var signature string
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		signature = request.Header.Get("X-SubdomainAbber-Signature")
		writer.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	notifier, err := NewWebhookNotifier(server.URL, "segredo")
	if err != nil {
		t.Fatal(err)
	}
	notifier.client = server.Client()
	if err := notifier.Send(context.Background(), AlertEvent{Host: "app.example"}); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(signature, "sha256=") || len(signature) != 71 {
		t.Fatalf("assinatura inválida: %q", signature)
	}
}
