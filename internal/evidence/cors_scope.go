package evidence

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/amchdd/subdomainabber/internal/core"
	"github.com/amchdd/subdomainabber/internal/dns"
	"github.com/amchdd/subdomainabber/pkg/ratelimit"
)

type CORSScopeCollector struct {
	client       *http.Client
	allowedRoots map[string]struct{}
}

// SetAllowedRootDomains limita as sondagens related-domain aos domínios
// registráveis incluídos explicitamente na entrada da varredura.
func (c *CORSScopeCollector) SetAllowedRootDomains(hosts []string) {
	c.allowedRoots = explicitRegistrableDomains(hosts)
}

func (c *CORSScopeCollector) SetRequestLimiter(limiter ratelimit.Waiter) {
	timeout := c.client.Timeout
	c.client.Timeout = 0
	c.client.Transport = ratelimit.NewTimedTransport(limiter, c.client.Transport, timeout)
}

func NewCORSScopeCollector(timeout time.Duration, clients ...*http.Client) *CORSScopeCollector {
	if len(clients) > 0 && clients[0] != nil {
		return &CORSScopeCollector{client: clients[0]}
	}
	return &CORSScopeCollector{
		client: &http.Client{
			Timeout: timeout,
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
}

func (c *CORSScopeCollector) Name() string {
	return "CORSScopeCollector"
}

func (c *CORSScopeCollector) Phase() CollectorPhase { return PhaseImpact }

func (c *CORSScopeCollector) Collect(ctx context.Context, analysis *core.HostAnalysis) error {
	if !hasRelatedDomainImpactCandidate(analysis) {
		return nil
	}
	rootDomain := dns.ExtractRootDomain(analysis.Host)
	if rootDomain == "" || strings.EqualFold(rootDomain, analysis.Host) || !relatedDomainProbeAllowed(c.allowedRoots, rootDomain) {
		return nil
	}
	req, err := http.NewRequestWithContext(ctx, "GET", "https://"+rootDomain, nil)
	if err != nil {
		return nil
	}

	candidateOrigin := "https://" + analysis.Host
	req.Header.Set("Origin", candidateOrigin)

	resp, err := c.client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	allowOrigin := resp.Header.Get("Access-Control-Allow-Origin")
	allowCreds := resp.Header.Get("Access-Control-Allow-Credentials")

	// O nome do campo é mantido por compatibilidade com a saída estruturada. Ele
	// só representa impacto de sessão quando a origem candidata é refletida de
	// forma exata e o navegador pode enviar credenciais. Um curinga nunca atende
	// a esse requisito, mesmo se o servidor também enviar ACAC: true.
	if allowOrigin == candidateOrigin && strings.TrimSpace(allowCreds) == "true" {
		analysis.ParentCORSWildcard = true
		analysis.AddEvidence(core.Evidence{
			Type:        "RELATED_DOMAIN_CORS_CREDENTIALS",
			Source:      rootDomain,
			Description: "O domínio registrável refletiu exatamente a origem candidata e permitiu credenciais; uma tomada de controle comprovada poderia expor respostas acessíveis à sessão do usuário.",
			Weight:      0,
			Confidence:  90,
			Metadata: map[string]string{
				"access_control_allow_origin":      allowOrigin,
				"access_control_allow_credentials": allowCreds,
			},
		})
		return nil
	}

	if allowOrigin == "*" {
		analysis.AddEvidence(core.Evidence{
			Type:        "CORS_PUBLIC_WILDCARD_OBSERVED",
			Source:      rootDomain,
			Description: "O domínio registrável permite leitura CORS sem credenciais para qualquer origem; isso não demonstra acesso à sessão nem amplia, por si só, o impacto de takeover.",
			Weight:      0,
			Confidence:  100,
			Metadata: map[string]string{
				"access_control_allow_origin":      allowOrigin,
				"access_control_allow_credentials": allowCreds,
			},
		})
	}

	return nil
}
