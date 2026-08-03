package evidence

import (
	"context"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/amchdd/subdomainabber/internal/core"
	"github.com/amchdd/subdomainabber/internal/dns"
	"github.com/amchdd/subdomainabber/pkg/ratelimit"
	"golang.org/x/sync/singleflight"
)

type CookieScopeCollector struct {
	client       *http.Client
	cache        sync.Map
	group        singleflight.Group
	allowedRoots map[string]struct{}
}

// SetAllowedRootDomains limita as sondagens related-domain aos domínios
// registráveis incluídos explicitamente na entrada da varredura.
func (c *CookieScopeCollector) SetAllowedRootDomains(hosts []string) {
	c.allowedRoots = explicitRegistrableDomains(hosts)
}

func (c *CookieScopeCollector) SetRequestLimiter(limiter ratelimit.Waiter) {
	timeout := c.client.Timeout
	c.client.Timeout = 0
	c.client.Transport = ratelimit.NewTimedTransport(limiter, c.client.Transport, timeout)
}

func NewCookieScopeCollector(timeout time.Duration, clients ...*http.Client) *CookieScopeCollector {
	if len(clients) > 0 && clients[0] != nil {
		return &CookieScopeCollector{client: clients[0]}
	}
	return &CookieScopeCollector{
		client: &http.Client{
			Timeout: timeout,
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
}

func (c *CookieScopeCollector) Name() string {
	return "CookieScopeCollector"
}

func (c *CookieScopeCollector) Phase() CollectorPhase { return PhaseImpact }

func (c *CookieScopeCollector) BeginBatch() {
	c.cache = sync.Map{}
	c.group = singleflight.Group{}
}

func (c *CookieScopeCollector) Collect(ctx context.Context, analysis *core.HostAnalysis) error {
	if !hasRelatedDomainImpactCandidate(analysis) {
		return nil
	}
	rootDomain := dns.ExtractRootDomain(analysis.Host)
	if rootDomain == "" || !strings.Contains(rootDomain, ".") || !relatedDomainProbeAllowed(c.allowedRoots, rootDomain) {
		return nil
	}
	if cached, ok := c.cache.Load(rootDomain); ok {
		analysis.ParentCookieScope = cached.(bool)
		return nil
	}

	value, _, _ := c.group.Do(rootDomain, func() (interface{}, error) {
		if cached, ok := c.cache.Load(rootDomain); ok {
			return cached.(bool), nil
		}
		result := c.inspectRootCookieScope(ctx, rootDomain)
		if ctx.Err() == nil {
			c.cache.Store(rootDomain, result)
		}
		return result, nil
	})
	if value != nil {
		analysis.ParentCookieScope = value.(bool)
	}
	return nil
}

func (c *CookieScopeCollector) inspectRootCookieScope(ctx context.Context, rootDomain string) bool {
	req, err := http.NewRequestWithContext(ctx, "GET", "https://"+rootDomain, nil)
	if err != nil {
		return false
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	cookies := resp.Header.Values("Set-Cookie")
	for _, cookie := range cookies {
		// Ex.: "session=123; Domain=.example.com; Path=/"
		parts := strings.Split(cookie, ";")
		for _, p := range parts {
			p = strings.TrimSpace(p)
			if strings.HasPrefix(strings.ToLower(p), "domain=") {
				domainVal := strings.TrimPrefix(strings.ToLower(p), "domain=")
				domainVal = strings.TrimSpace(domainVal)
				if domainVal == "."+rootDomain || domainVal == rootDomain {
					return true
				}
			}
		}
	}
	return false
}
