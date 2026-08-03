package evidence

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/amchdd/subdomainabber/internal/core"
)

func TestReadRawHTTPObservationFraming(t *testing.T) {
	tests := []struct {
		name       string
		response   string
		maxBody    int
		wantBody   string
		wantStatus int
		complete   bool
		parseError bool
	}{
		{name: "content length", response: "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello", maxBody: 64, wantBody: "hello", wantStatus: 200, complete: true},
		{name: "chunked", response: "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n", maxBody: 64, wantBody: "hello", wantStatus: 200, complete: true},
		{name: "partial", response: "HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nshort", maxBody: 64, wantBody: "short", wantStatus: 200, parseError: true},
		{name: "malformed status", response: "NOT HTTP\r\n\r\n", maxBody: 64, parseError: true},
		{name: "malformed header", response: "HTTP/1.1 200 OK\r\nBroken\r\n\r\n", maxBody: 64, wantStatus: 200, parseError: true},
		{name: "body limit", response: "HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\n0123456789", maxBody: 5, wantStatus: 200, parseError: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			observation := readRawHTTPObservation(bufio.NewReader(strings.NewReader(tt.response)), tt.maxBody)
			if observation.StatusCode != tt.wantStatus {
				t.Fatalf("status = %d, want %d", observation.StatusCode, tt.wantStatus)
			}
			if string(observation.Body) != tt.wantBody {
				t.Fatalf("body = %q, want %q", observation.Body, tt.wantBody)
			}
			if observation.Complete != tt.complete {
				t.Fatalf("complete = %t, want %t", observation.Complete, tt.complete)
			}
			if (observation.ParseError != "") != tt.parseError {
				t.Fatalf("parse error = %q, want error %t", observation.ParseError, tt.parseError)
			}
		})
	}
}

func TestRawTransportCompletesKeepAliveResponseFromContentLength(t *testing.T) {
	address, closeServer := startRawServer(t, func(conn net.Conn) {
		defer conn.Close()
		_, _ = bufio.NewReader(conn).ReadString('\n')
		_, _ = fmt.Fprint(conn, "HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: keep-alive\r\n\r\nhello")
		time.Sleep(400 * time.Millisecond)
	})
	defer closeServer()

	transport := NewNetworkHTTPRawTransport(250 * time.Millisecond)
	mutationContext, _ := mutationContextForAuthority(address, "http")
	payload, _ := buildRawRequest("GET", "/", standardRawHeaders(address, "close"), nil)
	started := time.Now()
	observation := transport.Send(context.Background(), mutationContext, payload)
	if elapsed := time.Since(started); elapsed >= 150*time.Millisecond {
		t.Fatalf("transport waited for close/timeout: %s", elapsed)
	}
	if !observation.Complete || string(observation.Body) != "hello" {
		t.Fatalf("unexpected observation: %#v", observation)
	}
}

func TestRawTransportClassifiesTimeoutsAndReset(t *testing.T) {
	t.Run("timeout before headers", func(t *testing.T) {
		address, closeServer := startRawServer(t, func(conn net.Conn) {
			defer conn.Close()
			time.Sleep(150 * time.Millisecond)
		})
		defer closeServer()
		observation := sendTestRawRequest(address, 40*time.Millisecond)
		if !observation.TimedOut || observation.Complete {
			t.Fatalf("expected timeout before headers: %#v", observation)
		}
	})

	t.Run("timeout in body", func(t *testing.T) {
		address, closeServer := startRawServer(t, func(conn net.Conn) {
			defer conn.Close()
			_, _ = fmt.Fprint(conn, "HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nshort")
			time.Sleep(150 * time.Millisecond)
		})
		defer closeServer()
		observation := sendTestRawRequest(address, 40*time.Millisecond)
		if !observation.TimedOut || observation.Complete {
			t.Fatalf("expected timeout in body: %#v", observation)
		}
	})

	t.Run("connection reset", func(t *testing.T) {
		address, closeServer := startRawServer(t, func(conn net.Conn) {
			if tcpConn, ok := conn.(*net.TCPConn); ok {
				_ = tcpConn.SetLinger(0)
			}
			_ = conn.Close()
		})
		defer closeServer()
		observation := sendTestRawRequest(address, 100*time.Millisecond)
		if observation.Complete || observation.TransportError == "" || !observation.ConnectionReset {
			t.Fatalf("expected reset/transport error: %#v", observation)
		}
	})
}

func TestNetworkRawTransportUsesConfiguredCONNECTProxy(t *testing.T) {
	target, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	go func() {
		conn, err := target.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		reader := bufio.NewReader(conn)
		for {
			line, err := reader.ReadString('\n')
			if err != nil || line == "\r\n" {
				break
			}
		}
		body := "proxied"
		fmt.Fprintf(conn, "HTTP/1.1 200 OK\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", len(body), body)
	}()
	proxy, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer proxy.Close()
	connectSeen := make(chan string, 1)
	go func() {
		client, err := proxy.Accept()
		if err != nil {
			return
		}
		defer client.Close()
		reader := bufio.NewReader(client)
		line, _ := reader.ReadString('\n')
		connectSeen <- line
		for {
			header, err := reader.ReadString('\n')
			if err != nil || header == "\r\n" {
				break
			}
		}
		upstream, err := net.Dial("tcp", target.Addr().String())
		if err != nil {
			return
		}
		defer upstream.Close()
		fmt.Fprint(client, "HTTP/1.1 200 Connection Established\r\n\r\n")
		go io.Copy(upstream, reader)
		io.Copy(client, upstream)
	}()
	host, portText, _ := net.SplitHostPort(target.Addr().String())
	port, _ := strconv.Atoi(portText)
	transport := NewNetworkHTTPRawTransport(time.Second)
	if err := transport.SetProxy("http://" + proxy.Addr().String()); err != nil {
		t.Fatal(err)
	}
	payload, _ := buildRawRequest("GET", "/", standardRawHeaders(target.Addr().String(), "close"), nil)
	observation := transport.Send(context.Background(), core.MutationContext{DialHost: host, DialPort: port, HTTPAuthority: target.Addr().String(), Scheme: "http"}, payload)
	if observation.StatusCode != 200 || string(observation.Body) != "proxied" {
		t.Fatalf("proxy observation = %#v", observation)
	}
	select {
	case line := <-connectSeen:
		if !strings.HasPrefix(line, "CONNECT "+target.Addr().String()) {
			t.Fatalf("CONNECT line = %q", line)
		}
	case <-time.After(time.Second):
		t.Fatal("proxy did not receive CONNECT")
	}
}

func TestNetworkRawTransportBlocksInvalidProxyWithoutExposingCredentials(t *testing.T) {
	transport := NewNetworkHTTPRawTransport(time.Second)
	err := transport.SetProxy("http://usuario:segredo@proxy.example/%zz")
	if err == nil {
		t.Fatal("um proxy inválido foi aceito")
	}
	if strings.Contains(err.Error(), "usuario") || strings.Contains(err.Error(), "segredo") {
		t.Fatalf("o erro expôs credenciais do proxy: %q", err)
	}

	payload, _ := buildRawRequest("GET", "/", standardRawHeaders("alvo.example", "close"), nil)
	observation := transport.Send(context.Background(), core.MutationContext{
		DialHost:      "127.0.0.1",
		DialPort:      1,
		HTTPAuthority: "alvo.example",
		Scheme:        "http",
	}, payload)
	if observation.TransportError != "proxy HTTP raw inválido" {
		t.Fatalf("o transporte não preservou o bloqueio do proxy inválido: %#v", observation)
	}
	if strings.Contains(observation.TransportError, "usuario") || strings.Contains(observation.TransportError, "segredo") {
		t.Fatalf("a observação expôs credenciais do proxy: %#v", observation)
	}
}

func TestNetworkRawTransportRejectsWhitespaceOnlyProxy(t *testing.T) {
	transport := NewNetworkHTTPRawTransport(time.Second)
	if err := transport.SetProxy("   "); err == nil {
		t.Fatal("uma configuração de proxy composta apenas por espaços foi tratada como conexão direta")
	}
	payload, _ := buildRawRequest("GET", "/", standardRawHeaders("alvo.example", "close"), nil)
	observation := transport.Send(context.Background(), core.MutationContext{
		DialHost:      "127.0.0.1",
		DialPort:      1,
		HTTPAuthority: "alvo.example",
		Scheme:        "http",
	}, payload)
	if observation.TransportError != "a configuração de proxy não contém endpoint utilizável" {
		t.Fatalf("o transporte não preservou o bloqueio da configuração vazia: %#v", observation)
	}
}

func TestMutationTargetSeparatesDialAuthorityAndSNI(t *testing.T) {
	sniSeen := make(chan string, 1)
	authoritySeen := make(chan string, 1)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		authoritySeen <- request.Host
		writer.WriteHeader(http.StatusOK)
		fmt.Fprint(writer, "ok")
	}))
	server.TLS = &tls.Config{GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) { sniSeen <- hello.ServerName; return nil, nil }}
	server.StartTLS()
	defer server.Close()
	dialHost, portText, _ := net.SplitHostPort(server.Listener.Addr().String())
	dialPort, _ := strconv.Atoi(portText)
	mutationContext := core.MutationContext{DialHost: dialHost, DialPort: dialPort, HTTPAuthority: "authority.example", TLSServerName: "sni.example", Scheme: "https"}
	payload, _ := buildRawRequest("GET", "/", standardRawHeaders(mutationContext.HTTPAuthority, "close"), nil)
	observation := NewNetworkHTTPRawTransport(time.Second).Send(context.Background(), mutationContext, payload)
	if observation.StatusCode != 200 || string(observation.Body) != "ok" {
		t.Fatalf("observation = %#v", observation)
	}
	if got := <-authoritySeen; got != "authority.example" {
		t.Fatalf("HTTP authority = %q", got)
	}
	if got := <-sniSeen; got != "sni.example" {
		t.Fatalf("TLS SNI = %q", got)
	}
}

func TestMutationEndpointUsesOnlyExplicitDialFields(t *testing.T) {
	ctx := core.MutationContext{DialHost: "127.0.0.1", DialPort: 18080, HTTPAuthority: "unrelated.example:9443", TLSServerName: "sni.example", Scheme: "https"}
	host, port, err := mutationEndpoint(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if host != "127.0.0.1" || port != 18080 {
		t.Fatalf("endpoint = %s:%d", host, port)
	}
	if mutationHost(ctx) != "unrelated.example:9443" {
		t.Fatalf("authority = %q", mutationHost(ctx))
	}
}

func TestHTTPSRawTransportDoesNotInferSNIFromDialHostOrAuthority(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		conn, err := listener.Accept()
		if err == nil {
			defer conn.Close()
			time.Sleep(100 * time.Millisecond)
		}
	}()
	host, portText, _ := net.SplitHostPort(listener.Addr().String())
	port, _ := strconv.Atoi(portText)
	ctx := core.MutationContext{DialHost: host, DialPort: port, HTTPAuthority: "authority.example", Scheme: "https"}
	payload, _ := buildRawRequest("GET", "/", standardRawHeaders(ctx.HTTPAuthority, "close"), nil)
	observation := NewNetworkHTTPRawTransport(time.Second).Send(context.Background(), ctx, payload)
	if !strings.Contains(observation.TransportError, "o nome de servidor TLS é obrigatório") {
		t.Fatalf("SNI was inferred or wrong error returned: %#v", observation)
	}
}

func startRawServer(t *testing.T, handler func(net.Conn)) (string, func()) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr == nil {
			handler(conn)
		}
	}()
	return listener.Addr().String(), func() { _ = listener.Close() }
}

func sendTestRawRequest(address string, timeout time.Duration) core.RawHTTPObservation {
	transport := NewNetworkHTTPRawTransport(timeout)
	mutationContext, _ := mutationContextForAuthority(address, "http")
	payload, _ := buildRawRequest("GET", "/", standardRawHeaders(address, "close"), nil)
	return transport.Send(context.Background(), mutationContext, payload)
}
