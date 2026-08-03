package netclient

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type countingWaiter struct{ calls atomic.Int32 }

func (waiter *countingWaiter) Wait(context.Context) error {
	waiter.calls.Add(1)
	return nil
}

func TestInvalidProxyErrorDoesNotExposeCredentials(t *testing.T) {
	secret := "segredo-nao-deve-aparecer"
	_, err := NewScopedClient(time.Second, "http://usuario:"+secret+"@", nil)
	if err == nil {
		t.Fatal("proxy inválido foi aceito")
	}
	if strings.Contains(err.Error(), secret) || strings.Contains(err.Error(), "usuario") {
		t.Fatalf("erro expôs credenciais do proxy: %v", err)
	}
}

func TestProxyConfigurationRejectsUnsupportedSchemeAndEmptyFile(t *testing.T) {
	if _, err := NewScopedClient(time.Second, "ftp://proxy.example.com:21", nil); err == nil {
		t.Fatal("esquema de proxy sem suporte foi aceito")
	}

	path := filepath.Join(t.TempDir(), "proxies.txt")
	if err := os.WriteFile(path, []byte(" \r\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := NewScopedClient(time.Second, path, nil); err == nil {
		t.Fatal("arquivo de proxies vazio habilitou conexão direta")
	}
}

func TestScopedClientBlocksExternalRedirectAndLimitsTransaction(t *testing.T) {
	var externalHits atomic.Int32
	external := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		externalHits.Add(1)
	}))
	defer external.Close()
	origin := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		http.Redirect(writer, request, external.URL, http.StatusFound)
	}))
	defer origin.Close()

	waiter := &countingWaiter{}
	client, err := NewScopedClient(2*time.Second, "", waiter)
	if err != nil {
		t.Fatalf("NewScopedClient: %v", err)
	}
	response, err := client.Get(origin.URL)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusFound || externalHits.Load() != 0 {
		t.Fatalf("external redirect escaped scope: status=%d hits=%d", response.StatusCode, externalHits.Load())
	}
	if waiter.calls.Load() != 1 {
		t.Fatalf("limiter calls = %d, want 1", waiter.calls.Load())
	}
}
