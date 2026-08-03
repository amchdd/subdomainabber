package netclient

import (
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"github.com/amchdd/subdomainabber/pkg/ratelimit"
)

// NewScopedClient constrói o cliente compartilhado dos verificadores. Ele usa o
// proxy configurado, aplica o limitador global a cada transação HTTP e segue
// somente redirecionamentos para o mesmo host.
func NewScopedClient(timeout time.Duration, proxyConfig string, limiter ratelimit.Waiter) (*http.Client, error) {
	transport := &http.Transport{
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 100,
		ForceAttemptHTTP2:   true,
	}
	proxies, err := parseProxies(proxyConfig)
	if err != nil {
		return nil, err
	}
	if len(proxies) > 0 {
		var index uint64
		transport.Proxy = func(*http.Request) (*url.URL, error) {
			current := atomic.AddUint64(&index, 1) - 1
			return proxies[current%uint64(len(proxies))], nil
		}
	}
	return &http.Client{
		Transport: ratelimit.NewTimedTransport(limiter, transport, timeout),
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return fmt.Errorf("interrompido após 10 redirecionamentos")
			}
			if len(via) == 0 || !strings.EqualFold(req.URL.Host, via[0].URL.Host) {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}, nil
}

func parseProxies(config string) ([]*url.URL, error) {
	if strings.TrimSpace(config) == "" {
		return nil, nil
	}
	raw := config
	if data, err := os.ReadFile(config); err == nil {
		raw = string(data)
	}
	parts := strings.FieldsFunc(raw, func(r rune) bool { return r == ',' || r == '\n' || r == '\r' })
	if len(parts) == 0 {
		return nil, fmt.Errorf("a configuração de proxy está vazia")
	}
	result := make([]*url.URL, 0, len(parts))
	for index, part := range parts {
		parsed, err := url.Parse(strings.TrimSpace(part))
		if err != nil || parsed.Host == "" || !supportedProxyScheme(parsed.Scheme) {
			return nil, fmt.Errorf("proxy inválido na posição %d", index+1)
		}
		result = append(result, parsed)
	}
	return result, nil
}

func supportedProxyScheme(scheme string) bool {
	switch strings.ToLower(scheme) {
	case "http", "https", "socks5", "socks5h":
		return true
	default:
		return false
	}
}
