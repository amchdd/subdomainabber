package benchmark

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// MockServer fornece servidores DNS e HTTP locais para cenários sintéticos controlados.
type MockServer struct {
	dnsAddr   string
	dnsServer *dns.Server

	httpServer *httptest.Server
	proxyURL   string

	// Respostas configuradas em memória.
	dnsRecords map[string][]dns.RR
	httpRoutes map[string]http.HandlerFunc
	tlsStates  map[string]*tls.ConnectionState
}

func NewMockServer() *MockServer {
	return &MockServer{
		dnsAddr:    "127.0.0.1:53530",
		dnsRecords: make(map[string][]dns.RR),
		httpRoutes: make(map[string]http.HandlerFunc),
		tlsStates:  make(map[string]*tls.ConnectionState),
	}
}

// ProxyURL retorna a URL do servidor HTTP simulado que será usado como proxy.
func (m *MockServer) ProxyURL() string {
	return m.proxyURL
}

// Start inicia os servidores UDP e TCP em segundo plano.
func (m *MockServer) Start() error {
	dns.HandleFunc(".", m.handleDNSRequest)
	packetConn, err := net.ListenPacket("udp", m.dnsAddr)
	if err != nil {
		return fmt.Errorf("não foi possível abrir o servidor DNS simulado em %s: %w", m.dnsAddr, err)
	}
	m.dnsServer = &dns.Server{PacketConn: packetConn}
	go func() {
		_ = m.dnsServer.ActivateAndServe()
	}()

	mux := http.NewServeMux()
	mux.HandleFunc("/", m.handleHTTPRequest)
	m.httpServer = httptest.NewServer(mux)
	m.proxyURL = m.httpServer.URL

	return nil
}

// MockRoundTripper implementa um http.RoundTripper que não usa a rede.
type MockRoundTripper struct {
	server *MockServer
}

func (rt *MockRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	w := httptest.NewRecorder()
	rt.server.handleHTTPRequest(w, req)
	return w.Result(), nil
}

// MockTLSDialer implementa o discador TLS em memória.
type MockTLSDialer struct {
	server *MockServer
}

func (md *MockTLSDialer) DialTLSContext(ctx context.Context, network, addr string, config *tls.Config) (*tls.ConnectionState, error) {
	host, _, _ := net.SplitHostPort(addr)
	if host == "" {
		host = addr
	}

	if state, exists := md.server.tlsStates[host]; exists {
		return state, nil
	}

	// Sem resposta configurada, simula um host ativo sem certificado personalizado.
	fallback := &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{
			{
				Subject:  pkix.Name{CommonName: "mocked.internal"},
				Issuer:   pkix.Name{CommonName: "Mock CA"},
				NotAfter: time.Now().Add(24 * time.Hour),
			},
		},
	}
	return fallback, nil
}

// TLSDialer retorna o discador TLS usado pelas suítes L1 e L3.
func (m *MockServer) TLSDialer() *MockTLSDialer {
	return &MockTLSDialer{server: m}
}

// RoundTripper retorna o transporte HTTP usado pela suíte L1.
func (m *MockServer) RoundTripper() http.RoundTripper {
	return &MockRoundTripper{server: m}
}

func (m *MockServer) Stop() {
	if m.dnsServer != nil {
		m.dnsServer.Shutdown()
	}
	if m.httpServer != nil {
		m.httpServer.Close()
	}
}

// SetCNAME injeta um CNAME no simulador.
func (m *MockServer) SetCNAME(domain, target string) {
	domain = dns.Fqdn(domain)
	target = dns.Fqdn(target)
	rr, _ := dns.NewRR(fmt.Sprintf("%s 60 IN CNAME %s", domain, target))
	m.dnsRecords[domain] = append(m.dnsRecords[domain], rr)
}

// SetA injeta um IP no simulador.
func (m *MockServer) SetA(domain, ip string) {
	domain = dns.Fqdn(domain)
	rr, _ := dns.NewRR(fmt.Sprintf("%s 60 IN A %s", domain, ip))
	m.dnsRecords[domain] = append(m.dnsRecords[domain], rr)
}

// SetNS injeta um servidor de nomes no simulador.
func (m *MockServer) SetNS(domain, target string) {
	domain = dns.Fqdn(domain)
	target = dns.Fqdn(target)
	rr, _ := dns.NewRR(fmt.Sprintf("%s 60 IN NS %s", domain, target))
	m.dnsRecords[domain] = append(m.dnsRecords[domain], rr)
}

func (m *MockServer) SetAAAA(domain string, ip string) {
	domain = dns.Fqdn(domain)
	rr, _ := dns.NewRR(fmt.Sprintf("%s 60 IN AAAA %s", domain, ip))
	m.dnsRecords[domain] = append(m.dnsRecords[domain], rr)
}

func (m *MockServer) SetMX(domain string, target string) {
	domain = dns.Fqdn(domain)
	target = dns.Fqdn(target)
	rr, _ := dns.NewRR(fmt.Sprintf("%s 60 IN MX 10 %s", domain, target))
	m.dnsRecords[domain] = append(m.dnsRecords[domain], rr)
}

func (m *MockServer) SetTXT(domain string, txt string) {
	domain = dns.Fqdn(domain)
	rr, _ := dns.NewRR(fmt.Sprintf("%s 60 IN TXT \"%s\"", domain, txt))
	m.dnsRecords[domain] = append(m.dnsRecords[domain], rr)
}

// SetNXDOMAIN configura uma resposta NameError.
func (m *MockServer) SetNXDOMAIN(domain string) {
	domain = dns.Fqdn(domain)
	m.dnsRecords[domain] = nil // Um valor vazio representa NXDOMAIN explícito quando registrado.
}

func (m *MockServer) handleDNSRequest(w dns.ResponseWriter, r *dns.Msg) {
	m_reply := new(dns.Msg)
	m_reply.SetReply(r)

	q := r.Question[0]
	name := q.Name

	records, exists := m.dnsRecords[name]
	if !exists {
		m_reply.Rcode = dns.RcodeNameError
		w.WriteMsg(m_reply)
		return
	}

	if records == nil {
		m_reply.Rcode = dns.RcodeNameError
		w.WriteMsg(m_reply)
		return
	}

	for _, rr := range records {
		if rr.Header().Rrtype == q.Qtype || q.Qtype == dns.TypeANY {
			m_reply.Answer = append(m_reply.Answer, rr)
		}
	}

	w.WriteMsg(m_reply)
}

// SetHTTP injeta uma resposta HTTP baseada no host.
func (m *MockServer) SetHTTP(host string, handler http.HandlerFunc) {
	m.httpRoutes[host] = handler
}

func (m *MockServer) handleHTTPRequest(w http.ResponseWriter, r *http.Request) {
	host := r.Host
	if strings.Contains(host, ":") {
		host, _, _ = net.SplitHostPort(host)
	}

	if handler, exists := m.httpRoutes[host]; exists {
		handler(w, r)
		return
	}
	http.NotFound(w, r)
}

// SetTLS simula a resposta da negociação TLS para um host.
func (m *MockServer) SetTLS(host string, subject, issuer string, expired bool) {
	notAfter := time.Now().Add(24 * time.Hour)
	if expired {
		notAfter = time.Now().Add(-24 * time.Hour)
	}

	m.tlsStates[host] = &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{
			{
				Subject:  pkix.Name{CommonName: subject},
				Issuer:   pkix.Name{CommonName: issuer},
				DNSNames: []string{subject},
				NotAfter: notAfter,
			},
		},
	}
}
