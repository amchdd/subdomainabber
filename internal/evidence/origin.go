package evidence

import (
	"context"
	"net"
	"strconv"
	"strings"

	"github.com/amchdd/subdomainabber/internal/core"
	"github.com/amchdd/subdomainabber/internal/dns"
	"github.com/amchdd/subdomainabber/internal/domainutil"
)

const maxOriginCandidates = 8

type originCandidate struct {
	target string
	source string
	kind   string
}

type OriginCollector struct {
	transport HTTPRawTransport
	allowed   map[string]struct{}
	limiter   interface{ Wait(context.Context) error }
}

func NewOriginCollector(transport HTTPRawTransport) *OriginCollector {
	return &OriginCollector{transport: transport, allowed: make(map[string]struct{})}
}

func (collector *OriginCollector) Phase() CollectorPhase { return PhaseImpact }

func (collector *OriginCollector) SetAllowedTargets(targets []string) {
	collector.allowed = make(map[string]struct{}, len(targets))
	for _, target := range targets {
		if normalized := normalizeOriginTarget(target); normalized != "" {
			collector.allowed[normalized] = struct{}{}
		}
	}
}

func (collector *OriginCollector) SetRequestLimiter(limiter interface{ Wait(context.Context) error }) {
	collector.limiter = limiter
}

func (collector *OriginCollector) Collect(ctx context.Context, analysis *core.HostAnalysis) error {
	if analysis == nil || !behindCDN(analysis) {
		return nil
	}
	analysis.AddTestedVector("ORIGIN_EXPOSURE")
	candidates := collector.candidates(analysis)
	for index, candidate := range candidates {
		if index >= maxOriginCandidates {
			break
		}
		typeName := "ORIGIN_EXPOSURE_HINT"
		confidence := 60
		if candidate.kind == "header" {
			typeName = "ORIGIN_EXPOSURE_CANDIDATE"
			confidence = 85
		}
		if ip := net.ParseIP(candidate.target); ip != nil && analysis.OriginIPCandidate == "" {
			analysis.OriginIPCandidate = candidate.target
		}
		analysis.AddEvidence(core.Evidence{
			Type: typeName, Source: candidate.source,
			Description: "DNS, TLS ou cabeçalho revelou um candidato a origin atrás da camada de borda.",
			Weight:      0, Confidence: confidence,
			Metadata: map[string]string{"target": candidate.target, "signal": candidate.kind, "cdn": analysis.CDN},
		})
		if _, ok := collector.allowed[candidate.target]; ok {
			collector.confirm(ctx, analysis, candidate)
		}
	}
	return nil
}

func (collector *OriginCollector) candidates(analysis *core.HostAnalysis) []originCandidate {
	seen := make(map[string]struct{})
	var result []originCandidate
	add := func(candidate originCandidate) {
		candidate.target = normalizeOriginTarget(candidate.target)
		if candidate.target == "" || strings.EqualFold(candidate.target, analysis.Host) {
			return
		}
		key := candidate.kind + "|" + candidate.target
		if _, ok := seen[key]; ok {
			return
		}
		seen[key] = struct{}{}
		result = append(result, candidate)
	}

	for _, scheme := range []string{"https", "http"} {
		observation, ok := analysis.HTTPObservation(scheme)
		if !ok || !observation.Complete {
			continue
		}
		for _, name := range []string{"X-Origin-Ip", "X-Backend-Ip", "X-Origin-Host", "X-Backend-Host", "X-Upstream-Host"} {
			for _, value := range originHeaderValues(observation.Headers, name) {
				add(originCandidate{target: value, source: name, kind: "header"})
			}
		}
	}

	cdnID := cdnProviderID(analysis.CDN)
	for _, candidate := range analysis.CloudIPCandidates {
		if candidate.ProviderID != "" && cdnID != "" && candidate.ProviderID != cdnID {
			add(originCandidate{target: candidate.IP, source: candidate.Provider, kind: "dns"})
		}
	}

	if analysis.TLS != nil {
		root := dns.ExtractRootDomain(analysis.Host)
		for _, san := range analysis.TLS.SANs {
			if originName(san, root) {
				add(originCandidate{target: san, source: "TLS SAN", kind: "tls"})
			}
		}
	}
	return result
}

func (collector *OriginCollector) confirm(ctx context.Context, analysis *core.HostAnalysis, candidate originCandidate) {
	if collector.transport == nil {
		return
	}
	payload, err := buildRawRequest("GET", "/", standardRawHeaders(analysis.Host, "close"), nil)
	if err != nil {
		return
	}
	for _, scheme := range []string{"https", "http"} {
		baseline, ok := analysis.HTTPObservation(scheme)
		if !ok || !baseline.Complete {
			continue
		}
		port := 443
		serverName := analysis.Host
		if scheme == "http" {
			port = 80
			serverName = ""
		}
		target := core.MutationContext{
			DialHost: candidate.target, DialPort: port, HTTPAuthority: analysis.Host,
			TLSServerName: serverName, Scheme: scheme, Baseline: baseline,
		}
		matches := 0
		for attempt := 0; attempt < 2; attempt++ {
			if collector.limiter != nil && collector.limiter.Wait(ctx) != nil {
				return
			}
			observation := collector.transport.Send(ctx, target, payload)
			if !observation.Complete || observation.StatusCode != baseline.StatusCode || hashBytes(normalizeHTTPBody(observation.Body)) != baseline.BodyHash {
				break
			}
			matches++
		}
		if matches != 2 {
			continue
		}
		analysis.AddEvidence(core.Evidence{
			Type: "ORIGIN_DIRECT_MATCH", Source: candidate.source,
			Description: "O destino permitido reproduziu a resposta da aplicação ao receber o Host e o SNI originais.",
			Weight:      20, Confidence: 95,
			Metadata: map[string]string{"target": candidate.target, "scheme": scheme, "status": strconv.Itoa(baseline.StatusCode), "cdn": analysis.CDN, "confirmations": "2"},
		})
		return
	}
}

func normalizeOriginTarget(value string) string {
	value = strings.TrimSpace(strings.Trim(value, "[]"))
	if host, _, err := net.SplitHostPort(value); err == nil {
		value = host
	}
	if ip := net.ParseIP(value); ip != nil {
		if !ip.IsGlobalUnicast() || ip.IsPrivate() {
			return ""
		}
		return ip.String()
	}
	host, err := domainutil.NormalizeHostname(value)
	if err != nil {
		return ""
	}
	return host
}

func behindCDN(analysis *core.HostAnalysis) bool {
	if strings.TrimSpace(analysis.CDN) != "" {
		return true
	}
	return hasEvidenceType(analysis.Evidences, "CDN_DETECTED")
}

func cdnProviderID(name string) string {
	name = strings.ToLower(name)
	switch {
	case strings.Contains(name, "cloudflare"):
		return "cloudflare"
	case strings.Contains(name, "cloudfront"), strings.Contains(name, "amazon"):
		return "aws"
	case strings.Contains(name, "azure"):
		return "microsoft-azure"
	case strings.Contains(name, "google"):
		return "google-cloud"
	default:
		return ""
	}
}

func originName(host, root string) bool {
	if root == "" || (host != root && !strings.HasSuffix(host, "."+root)) {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		switch label {
		case "origin", "backend", "direct":
			return true
		}
	}
	return false
}

func originHeaderValues(headers map[string][]string, name string) []string {
	for key, values := range headers {
		if strings.EqualFold(key, name) {
			return values
		}
	}
	return nil
}
