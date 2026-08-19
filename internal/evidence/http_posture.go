package evidence

import (
	"context"
	"net/url"
	"strconv"
	"strings"

	"github.com/amchdd/subdomainabber/internal/core"
)

type HTTPPostureCollector struct{}

func NewHTTPPostureCollector() *HTTPPostureCollector { return &HTTPPostureCollector{} }

func (*HTTPPostureCollector) Phase() CollectorPhase { return PhaseImpact }

func (*HTTPPostureCollector) Collect(_ context.Context, analysis *core.HostAnalysis) error {
	if analysis == nil {
		return nil
	}
	analysis.AddTestedVector("HTTP_POSTURE")
	httpObservation, hasHTTP := analysis.HTTPObservation("http")
	httpsObservation, hasHTTPS := analysis.HTTPObservation("https")

	if hasHTTP && httpObservation.Complete {
		location := firstWebHeader(httpObservation.Headers, "Location")
		upgradeURL, upgraded := httpUpgradeURL(analysis, location)
		if !isRedirectStatus(httpObservation.StatusCode) || !upgraded {
			analysis.AddEvidence(core.Evidence{
				Type: "HTTP_HTTPS_REDIRECT_MISSING", Source: "http",
				Description: "O endpoint HTTP não conclui o redirecionamento em HTTPS.",
				Weight:      0, Confidence: 100,
				Metadata: map[string]string{"status": strconv.Itoa(httpObservation.StatusCode), "location": location},
			})
		} else if inconsistentHTTPSPort(upgradeURL) {
			analysis.AddEvidence(core.Evidence{
				Type: "HTTP_HTTPS_PORT_INCONSISTENT", Source: "http",
				Description: "O redirecionamento de upgrade usa uma porta HTTPS não convencional.",
				Weight:      0, Confidence: 100, Metadata: map[string]string{"location": upgradeURL},
			})
		}
	}

	if hasHTTPS && httpsObservation.Complete && isRedirectStatus(httpsObservation.StatusCode) {
		location := firstWebHeader(httpsObservation.Headers, "Location")
		if parsed, err := url.Parse(location); err == nil && strings.EqualFold(parsed.Scheme, "http") {
			analysis.AddEvidence(core.Evidence{
				Type: "HTTPS_DOWNGRADE_REDIRECT", Source: "https",
				Description: "O endpoint HTTPS redireciona para uma URL HTTP.",
				Weight:      10, Confidence: 100, Metadata: map[string]string{"location": location},
			})
		}
	}

	if hasHTTP && httpObservation.Complete && (!hasHTTPS || httpsObservation.TransportError != "") {
		analysis.AddEvidence(core.Evidence{
			Type: "HTTPS_UNAVAILABLE", Source: "https",
			Description: "O endpoint HTTP respondeu, mas a coleta HTTPS não foi concluída.",
			Weight:      0, Confidence: 80,
		})
	}
	return nil
}

func firstWebHeader(headers map[string][]string, name string) string {
	for key, values := range headers {
		if strings.EqualFold(key, name) && len(values) > 0 {
			return strings.TrimSpace(values[0])
		}
	}
	return ""
}

func httpUpgradeURL(analysis *core.HostAnalysis, location string) (string, bool) {
	if chain, ok := analysis.Redirects["http"]; ok {
		if finalURL := strings.TrimSpace(chain.FinalURL); isHTTPSURL(finalURL) {
			return finalURL, true
		}
	}
	return location, isHTTPSURL(location)
}

func isHTTPSURL(value string) bool {
	parsed, err := url.Parse(value)
	return err == nil && strings.EqualFold(parsed.Scheme, "https") && parsed.Hostname() != ""
}

func inconsistentHTTPSPort(location string) bool {
	parsed, err := url.Parse(location)
	return err == nil && parsed.Port() != "" && parsed.Port() != "443"
}
