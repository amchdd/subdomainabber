package evidence

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/amchdd/subdomainabber/internal/core"
	"github.com/amchdd/subdomainabber/pkg/ratelimit"
)

type HttpSecurityCollector struct {
	client         *http.Client
	checkHeaders   bool
	checkRedirects bool
}

func (c *HttpSecurityCollector) SetRequestLimiter(limiter ratelimit.Waiter) {
	timeout := c.client.Timeout
	c.client.Timeout = 0
	c.client.Transport = ratelimit.NewTimedTransport(limiter, c.client.Transport, timeout)
}

func NewHttpSecurityCollector() *HttpSecurityCollector {
	return NewHttpSecurityCollectorForChecks(true, true)
}

func NewHttpSecurityCollectorForChecks(checkHeaders, checkRedirects bool, clients ...*http.Client) *HttpSecurityCollector {
	if len(clients) > 0 && clients[0] != nil {
		return &HttpSecurityCollector{
			client:         clients[0],
			checkHeaders:   checkHeaders,
			checkRedirects: checkRedirects,
		}
	}
	return &HttpSecurityCollector{
		client: &http.Client{
			Timeout: 5 * time.Second,
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		checkHeaders:   checkHeaders,
		checkRedirects: checkRedirects,
	}
}

func (c *HttpSecurityCollector) Name() string {
	return "HttpSecurity"
}

func (c *HttpSecurityCollector) Collect(ctx context.Context, analysis *core.HostAnalysis) error {
	if c.checkHeaders {
		if c.collectHeaders(analysis) {
			analysis.AddTestedVector("SEC_HEADERS")
		}
	}
	if !c.checkRedirects || !hasCompleteHTTPBaseline(analysis) {
		return nil
	}
	analysis.AddTestedVector("OPEN_REDIRECT")
	return c.collectRedirects(ctx, analysis)
}

func (c *HttpSecurityCollector) collectHeaders(analysis *core.HostAnalysis) bool {
	observation, ok := analysis.HTTPObservation("https")
	if !ok || !observation.Complete {
		return false
	}
	hasHSTS := false
	hasCSP := false
	for k := range observation.Headers {
		kLower := strings.ToLower(k)
		if kLower == "strict-transport-security" {
			hasHSTS = true
		}
		if kLower == "content-security-policy" {
			hasCSP = true
		}
	}
	if !hasHSTS {
		analysis.AddEvidence(core.Evidence{
			Type:        "HTTP_HSTS_MISSING",
			Source:      "HttpSecurity",
			Description: "O cabeçalho Strict-Transport-Security está ausente.",
			Weight:      0,
			Confidence:  100,
		})
	}
	if !hasCSP {
		analysis.AddEvidence(core.Evidence{
			Type:        "HTTP_CSP_MISSING",
			Source:      "HttpSecurity",
			Description: "O cabeçalho Content-Security-Policy está ausente.",
			Weight:      0,
			Confidence:  100,
		})
	}
	return true
}

func hasCompleteHTTPBaseline(analysis *core.HostAnalysis) bool {
	for _, scheme := range []string{"https", "http"} {
		if observation, ok := analysis.HTTPObservation(scheme); ok && observation.Complete {
			return true
		}
	}
	return false
}

func (c *HttpSecurityCollector) collectRedirects(ctx context.Context, analysis *core.HostAnalysis) error {
	// Sonda caminhos conhecidos para detectar redirecionamento aberto.
	paths := []string{"//evil.com", "/redirect?url=https://evil.com"}
	for _, path := range paths {
		req, err := http.NewRequestWithContext(ctx, "GET", "http://"+analysis.Host+path, nil)
		if err != nil {
			continue
		}
		resp, err := c.client.Do(req)
		if err == nil {
			defer resp.Body.Close()
			if resp.StatusCode >= 300 && resp.StatusCode <= 399 {
				loc := resp.Header.Get("Location")
				if redirectsToProbeHost(loc) {
					analysis.AddEvidence(core.Evidence{
						Type:        "HTTP_OPEN_REDIRECT",
						Source:      "HttpSecurity",
						Description: "O host permite um redirecionamento aberto em " + path + " para " + loc,
						Weight:      80,
						Confidence:  100,
					})
					break // Encontrado; não é necessário testar outros caminhos.
				}
			}
		}
	}

	return nil
}

func redirectsToProbeHost(location string) bool {
	parsed, err := url.Parse(location)
	return err == nil && strings.EqualFold(parsed.Hostname(), "evil.com")
}
