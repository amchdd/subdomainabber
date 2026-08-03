package dns

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	mdns "github.com/miekg/dns"
)

func TestNormalizeResolverEndpointSupportsIPv4IPv6AndHostnames(t *testing.T) {
	tests := map[string]string{
		"1.1.1.1":               "1.1.1.1:53",
		"1.1.1.1:5353":          "1.1.1.1:5353",
		"2001:0db8::1":          "[2001:db8::1]:53",
		"[2001:db8::1]":         "[2001:db8::1]:53",
		"[2001:db8::1]:5353":    "[2001:db8::1]:5353",
		" DNS.EXAMPLE.COM. ":    "dns.example.com:53",
		"DNS.EXAMPLE.COM.:5353": "dns.example.com:5353",
	}
	for input, want := range tests {
		got, err := normalizeResolverEndpoint(input)
		if err != nil {
			t.Fatalf("normalizeResolverEndpoint(%q): %v", input, err)
		}
		if got != want {
			t.Fatalf("normalizeResolverEndpoint(%q) = %q, esperado %q", input, got, want)
		}
	}
}

func TestNormalizeResolverEndpointRejectsMalformedValues(t *testing.T) {
	for _, input := range []string{"", "[]", "[invalid]", "example.com:abc", "[2001:db8::1]:0", "[2001:db8::1]:65536"} {
		if _, err := normalizeResolverEndpoint(input); err == nil {
			t.Fatalf("endpoint inválido aceito: %q", input)
		}
	}
}

func TestNewNormalizesWithoutMutatingCallerSlice(t *testing.T) {
	servers := []string{"2001:db8::1", "DNS.EXAMPLE.COM."}
	resolver := New(servers)
	if servers[0] != "2001:db8::1" || servers[1] != "DNS.EXAMPLE.COM." {
		t.Fatalf("New alterou a fatia fornecida: %#v", servers)
	}
	want := []string{"[2001:db8::1]:53", "dns.example.com:53"}
	if len(resolver.servers) != len(want) {
		t.Fatalf("resolvers normalizados = %#v, esperado %#v", resolver.servers, want)
	}
	for index := range want {
		if resolver.servers[index] != want[index] {
			t.Fatalf("resolver %d = %q, esperado %q", index, resolver.servers[index], want[index])
		}
	}
}

func TestLoadResolversFromFileNormalizesIPv6AndReportsLine(t *testing.T) {
	validPath := filepath.Join(t.TempDir(), "resolvers.txt")
	validContents := "# resolvers de teste\n2001:db8::1\n[2001:db8::2]:5353\n1.1.1.1\n"
	if err := os.WriteFile(validPath, []byte(validContents), 0o600); err != nil {
		t.Fatal(err)
	}
	servers, err := LoadResolversFromFile(validPath)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"[2001:db8::1]:53", "[2001:db8::2]:5353", "1.1.1.1:53"}
	if strings.Join(servers, "|") != strings.Join(want, "|") {
		t.Fatalf("resolvers = %#v, esperado %#v", servers, want)
	}

	invalidPath := filepath.Join(t.TempDir(), "invalid-resolvers.txt")
	if err := os.WriteFile(invalidPath, []byte("1.1.1.1\nexample.com:invalid\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err = LoadResolversFromFile(invalidPath)
	if err == nil || !strings.Contains(err.Error(), "linha 2") {
		t.Fatalf("erro sem linha precisa: %v", err)
	}
}

func TestResolverRejectsInvalidDirectConfigurationWithoutPanicking(t *testing.T) {
	resolver := New([]string{"example.com:invalid"})
	message := new(mdns.Msg)
	message.SetQuestion("example.com.", mdns.TypeA)
	_, err := resolver.exchangeUncached(context.Background(), message)
	if err == nil || !strings.Contains(err.Error(), "configuração dos resolvedores inválida") {
		t.Fatalf("erro inesperado: %v", err)
	}
}

func TestDoHExchangeAcceptsValidDNSMessage(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		defer request.Body.Close()
		wire, err := io.ReadAll(io.LimitReader(request.Body, maxDoHResponseSize+1))
		if err != nil {
			t.Errorf("lendo consulta: %v", err)
			return
		}
		query := new(mdns.Msg)
		if err := query.Unpack(wire); err != nil {
			t.Errorf("decodificando consulta: %v", err)
			return
		}
		response := new(mdns.Msg)
		response.SetReply(query)
		responseWire, err := response.Pack()
		if err != nil {
			t.Errorf("codificando resposta: %v", err)
			return
		}
		writer.Header().Set("Content-Type", "application/dns-message")
		_, _ = writer.Write(responseWire)
	}))
	defer server.Close()

	resolver := New(nil)
	resolver.SetDoH(server.URL)
	query := new(mdns.Msg)
	query.SetQuestion("example.com.", mdns.TypeA)
	response, err := resolver.exchangeDoH(context.Background(), query)
	if err != nil {
		t.Fatal(err)
	}
	if response.Id != query.Id || len(response.Question) != 1 {
		t.Fatalf("resposta DoH inesperada: %#v", response)
	}
}

func TestDoHExchangeDoesNotFollowRedirects(t *testing.T) {
	var destinationRequests atomic.Int64
	destination := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		destinationRequests.Add(1)
		writer.WriteHeader(http.StatusOK)
	}))
	defer destination.Close()

	redirect := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		http.Redirect(writer, request, destination.URL, http.StatusTemporaryRedirect)
	}))
	defer redirect.Close()

	resolver := New(nil)
	resolver.SetDoH(redirect.URL)
	query := new(mdns.Msg)
	query.SetQuestion("example.com.", mdns.TypeA)
	_, err := resolver.exchangeDoH(context.Background(), query)
	if err == nil || !strings.Contains(err.Error(), "redirecionamento") {
		t.Fatalf("redirecionamento não foi recusado: %v", err)
	}
	if destinationRequests.Load() != 0 {
		t.Fatalf("a consulta DNS foi enviada ao destino do redirecionamento %d vez(es)", destinationRequests.Load())
	}
}

func TestDoHExchangeRejectsOversizedResponse(t *testing.T) {
	body := bytes.Repeat([]byte{0}, maxDoHResponseSize+1)
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Content-Type", "application/dns-message")
		_, _ = writer.Write(body)
	}))
	defer server.Close()

	resolver := New(nil)
	resolver.SetDoH(server.URL)
	query := new(mdns.Msg)
	query.SetQuestion("example.com.", mdns.TypeA)
	_, err := resolver.exchangeDoH(context.Background(), query)
	if err == nil || !strings.Contains(err.Error(), "excede o limite") {
		t.Fatalf("resposta acima do limite não foi recusada: %v", err)
	}
}
