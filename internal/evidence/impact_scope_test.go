package evidence

import (
	"context"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/amchdd/subdomainabber/internal/core"
)

type impactRoundTripperFunc func(*http.Request) (*http.Response, error)

func (function impactRoundTripperFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return function(request)
}

func TestCookieScopeUsesRegistrableDomainAndBatchCache(t *testing.T) {
	collector := NewCookieScopeCollector(time.Second)
	collector.SetAllowedRootDomains([]string{"example.co.uk"})
	var calls atomic.Int64
	collector.client.Transport = impactRoundTripperFunc(func(request *http.Request) (*http.Response, error) {
		calls.Add(1)
		if request.URL.Host != "example.co.uk" {
			t.Fatalf("expected PSL registrable domain, got %s", request.URL.Host)
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Header: http.Header{
				"Set-Cookie": []string{"session=value; Domain=.example.co.uk; Path=/"},
			},
			Body:    io.NopCloser(strings.NewReader("ok")),
			Request: request,
		}, nil
	})

	first := relatedDomainAnalysis("api.example.co.uk")
	second := relatedDomainAnalysis("assets.example.co.uk")
	if err := collector.Collect(context.Background(), first); err != nil {
		t.Fatal(err)
	}
	if err := collector.Collect(context.Background(), second); err != nil {
		t.Fatal(err)
	}
	if !first.ParentCookieScope || !second.ParentCookieScope || calls.Load() != 1 {
		t.Fatalf("cache or cookie result failed: first=%t second=%t calls=%d", first.ParentCookieScope, second.ParentCookieScope, calls.Load())
	}

	collector.BeginBatch()
	if err := collector.Collect(context.Background(), relatedDomainAnalysis("new.example.co.uk")); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 2 {
		t.Fatalf("batch reset did not revalidate root: %d calls", calls.Load())
	}
}

func TestImpactCollectorsSkipHostsWithoutTakeoverCandidate(t *testing.T) {
	cookie := NewCookieScopeCollector(time.Second)
	cors := NewCORSScopeCollector(time.Second)
	cookie.SetAllowedRootDomains([]string{"example.com"})
	cors.SetAllowedRootDomains([]string{"example.com"})
	var calls atomic.Int64
	transport := impactRoundTripperFunc(func(*http.Request) (*http.Response, error) {
		calls.Add(1)
		return nil, context.Canceled
	})
	cookie.client.Transport = transport
	cors.client.Transport = transport
	analysis := &core.HostAnalysis{Host: "healthy.example.com"}
	if err := cookie.Collect(context.Background(), analysis); err != nil {
		t.Fatal(err)
	}
	if err := cors.Collect(context.Background(), analysis); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 0 {
		t.Fatalf("impact collectors performed %d unrelated requests", calls.Load())
	}
}

func TestImpactCollectorsSkipProviderContextAlone(t *testing.T) {
	cookie := NewCookieScopeCollector(time.Second)
	cors := NewCORSScopeCollector(time.Second)
	cookie.SetAllowedRootDomains([]string{"example.com"})
	cors.SetAllowedRootDomains([]string{"example.com"})
	var calls atomic.Int64
	transport := impactRoundTripperFunc(func(*http.Request) (*http.Response, error) {
		calls.Add(1)
		return nil, context.Canceled
	})
	cookie.client.Transport = transport
	cors.client.Transport = transport
	analysis := &core.HostAnalysis{
		Host: "healthy.example.com",
		ProviderCandidates: []core.ProviderCandidate{{
			Vector: "CNAME", ProviderID: "test", CNAME: "healthy.provider.example",
		}},
		Evidences: []core.Evidence{{Type: "CNAME_PROVIDER_MATCH"}},
	}
	if err := cookie.Collect(context.Background(), analysis); err != nil {
		t.Fatal(err)
	}
	if err := cors.Collect(context.Background(), analysis); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 0 {
		t.Fatalf("context-only provider match triggered %d impact requests", calls.Load())
	}
}

func TestCORSScopeRequiresExactReflectedOriginWithCredentials(t *testing.T) {
	tests := []struct {
		name             string
		allowOrigin      string
		allowCredentials string
		wantImpact       bool
		wantEvidence     string
	}{
		{
			name:             "origem refletida e credenciais permitidas",
			allowOrigin:      "https://api.example.com",
			allowCredentials: "true",
			wantImpact:       true,
			wantEvidence:     "RELATED_DOMAIN_CORS_CREDENTIALS",
		},
		{
			name:         "origem refletida sem credenciais",
			allowOrigin:  "https://api.example.com",
			wantImpact:   false,
			wantEvidence: "",
		},
		{
			name:             "curinga com credenciais declaradas",
			allowOrigin:      "*",
			allowCredentials: "true",
			wantImpact:       false,
			wantEvidence:     "CORS_PUBLIC_WILDCARD_OBSERVED",
		},
		{
			name:         "curinga sem credenciais",
			allowOrigin:  "*",
			wantImpact:   false,
			wantEvidence: "CORS_PUBLIC_WILDCARD_OBSERVED",
		},
		{
			name:             "credenciais com valor inválido",
			allowOrigin:      "https://api.example.com",
			allowCredentials: "TRUE",
			wantImpact:       false,
			wantEvidence:     "",
		},
		{
			name:             "outra origem",
			allowOrigin:      "https://other.example.com",
			allowCredentials: "true",
			wantImpact:       false,
			wantEvidence:     "",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			collector := NewCORSScopeCollector(time.Second)
			collector.SetAllowedRootDomains([]string{"example.com"})
			collector.client.Transport = impactRoundTripperFunc(func(request *http.Request) (*http.Response, error) {
				if got := request.Header.Get("Origin"); got != "https://api.example.com" {
					t.Fatalf("origem enviada = %q; esperado %q", got, "https://api.example.com")
				}
				return &http.Response{
					StatusCode: http.StatusOK,
					Header: http.Header{
						"Access-Control-Allow-Origin":      []string{test.allowOrigin},
						"Access-Control-Allow-Credentials": []string{test.allowCredentials},
					},
					Body:    io.NopCloser(strings.NewReader("ok")),
					Request: request,
				}, nil
			})

			analysis := relatedDomainAnalysis("api.example.com")
			if err := collector.Collect(context.Background(), analysis); err != nil {
				t.Fatal(err)
			}
			if analysis.ParentCORSWildcard != test.wantImpact {
				t.Fatalf("impacto CORS = %t; esperado %t", analysis.ParentCORSWildcard, test.wantImpact)
			}

			gotEvidence := ""
			for _, item := range analysis.Evidences {
				if strings.HasPrefix(item.Type, "CORS_") || strings.HasPrefix(item.Type, "RELATED_DOMAIN_CORS_") {
					gotEvidence = item.Type
					if item.Weight != 0 {
						t.Fatalf("evidência CORS %s não é neutra: peso %d", item.Type, item.Weight)
					}
				}
			}
			if gotEvidence != test.wantEvidence {
				t.Fatalf("evidência CORS = %q; esperado %q", gotEvidence, test.wantEvidence)
			}
		})
	}
}

func TestImpactCollectorsRequireExplicitRegistrableDomainInScope(t *testing.T) {
	var calls atomic.Int64
	transport := impactRoundTripperFunc(func(*http.Request) (*http.Response, error) {
		calls.Add(1)
		return nil, context.Canceled
	})
	cookie := NewCookieScopeCollector(time.Second)
	cors := NewCORSScopeCollector(time.Second)
	cookie.client.Transport = transport
	cors.client.Transport = transport
	cookie.SetAllowedRootDomains([]string{"api.example.com"})
	cors.SetAllowedRootDomains([]string{"api.example.com"})

	analysis := relatedDomainAnalysis("api.example.com")
	if err := cookie.Collect(context.Background(), analysis); err != nil {
		t.Fatal(err)
	}
	if err := cors.Collect(context.Background(), analysis); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 0 {
		t.Fatalf("o domínio registrável não estava explicitamente no escopo, mas houve %d sondagens", calls.Load())
	}
}

func relatedDomainAnalysis(host string) *core.HostAnalysis {
	return &core.HostAnalysis{
		Host:      host,
		Evidences: []core.Evidence{{Type: "CNAME_DANGLING"}},
		ProviderCandidates: []core.ProviderCandidate{{
			Vector: "CNAME", ProviderID: "test", Resource: "resource.test",
		}},
	}
}
