package evidence

import (
	"context"
	"net"
	"net/http"
	"testing"

	"github.com/amchdd/subdomainabber/internal/core"
)

type fixedRawTransport struct {
	result core.RawHTTPObservation
	calls  int
	target core.MutationContext
}

type sequenceRawTransport struct {
	results []core.RawHTTPObservation
	calls   int
}

func (transport *sequenceRawTransport) Send(context.Context, core.MutationContext, []byte) core.RawHTTPObservation {
	result := transport.results[transport.calls]
	transport.calls++
	return result
}

func (transport *fixedRawTransport) Send(_ context.Context, target core.MutationContext, _ []byte) core.RawHTTPObservation {
	transport.calls++
	transport.target = target
	return transport.result
}

func TestOriginReadsExplicitHeader(t *testing.T) {
	analysis := originAnalysis("203.0.113.15")
	collector := NewOriginCollector(nil)

	if err := collector.Collect(context.Background(), analysis); err != nil {
		t.Fatal(err)
	}
	if analysis.OriginIPCandidate != "203.0.113.15" || !hasEvidenceType(analysis.Evidences, "ORIGIN_EXPOSURE_CANDIDATE") {
		t.Fatalf("origin não observado: %+v", analysis)
	}
}

func TestOriginConfirmsAllowedTarget(t *testing.T) {
	analysis := originAnalysis("203.0.113.15")
	raw := &fixedRawTransport{result: core.RawHTTPObservation{StatusCode: http.StatusOK, Body: []byte("application"), Complete: true}}
	collector := NewOriginCollector(raw)
	collector.SetAllowedTargets([]string{"203.0.113.15"})

	if err := collector.Collect(context.Background(), analysis); err != nil {
		t.Fatal(err)
	}
	if raw.calls != 2 || !hasEvidenceType(analysis.Evidences, "ORIGIN_DIRECT_MATCH") {
		t.Fatalf("origin permitido não confirmado: chamadas=%d evidências=%+v", raw.calls, analysis.Evidences)
	}
	if raw.target.DialHost != "203.0.113.15" || raw.target.HTTPAuthority != analysis.Host || raw.target.TLSServerName != analysis.Host {
		t.Fatalf("destino da confirmação incorreto: %+v", raw.target)
	}
}

func TestOriginRejectsPrivateIP(t *testing.T) {
	analysis := originAnalysis("10.0.0.8")
	if err := NewOriginCollector(nil).Collect(context.Background(), analysis); err != nil {
		t.Fatal(err)
	}
	if hasEvidenceType(analysis.Evidences, "ORIGIN_EXPOSURE_CANDIDATE") {
		t.Fatalf("IP privado foi exposto como origin: %+v", analysis.Evidences)
	}
}

func TestOriginDoesNotDialPrivateHostname(t *testing.T) {
	analysis := originAnalysis("origin.example.net")
	raw := &fixedRawTransport{result: core.RawHTTPObservation{StatusCode: http.StatusOK, Body: []byte("application"), Complete: true}}
	collector := NewOriginCollector(raw)
	collector.SetAllowedTargets([]string{"origin.example.net"})
	collector.lookup = func(context.Context, string, string) ([]net.IP, error) {
		return []net.IP{net.ParseIP("10.0.0.8")}, nil
	}

	if err := collector.Collect(context.Background(), analysis); err != nil {
		t.Fatal(err)
	}
	if raw.calls != 0 || hasEvidenceType(analysis.Evidences, "ORIGIN_DIRECT_MATCH") {
		t.Fatalf("hostname privado foi sondado: chamadas=%d evidências=%+v", raw.calls, analysis.Evidences)
	}
}

func TestOriginRequiresTwoMatches(t *testing.T) {
	analysis := originAnalysis("203.0.113.15")
	raw := &sequenceRawTransport{results: []core.RawHTTPObservation{
		{StatusCode: http.StatusOK, Body: []byte("application"), Complete: true},
		{StatusCode: http.StatusNotFound, Body: []byte("other"), Complete: true},
	}}
	collector := NewOriginCollector(raw)
	collector.SetAllowedTargets([]string{"203.0.113.15"})

	if err := collector.Collect(context.Background(), analysis); err != nil {
		t.Fatal(err)
	}
	if hasEvidenceType(analysis.Evidences, "ORIGIN_DIRECT_MATCH") {
		t.Fatalf("resposta não reproduzível confirmou origin: %+v", analysis.Evidences)
	}
}

func TestOriginReadsDNSAndTLSHints(t *testing.T) {
	analysis := &core.HostAnalysis{
		Host: "app.example.com", CDN: "Cloudflare",
		CloudIPCandidates: []core.CloudIPCandidate{{IP: "203.0.113.20", ProviderID: "aws", Provider: "Amazon Web Services"}},
		TLS:               &core.TLSObservation{SANs: []string{"origin.example.com"}},
	}
	if err := NewOriginCollector(nil).Collect(context.Background(), analysis); err != nil {
		t.Fatal(err)
	}
	if evidenceCount(analysis, "ORIGIN_EXPOSURE_HINT") != 2 {
		t.Fatalf("sinais DNS/TLS não correlacionados: %+v", analysis.Evidences)
	}
}

func TestOriginIgnoresCDNProviderFamily(t *testing.T) {
	analysis := &core.HostAnalysis{
		Host: "app.example.com", CDN: "AWS CloudFront",
		CloudIPCandidates: []core.CloudIPCandidate{{
			IP: "203.0.113.20", ProviderID: "amazon_web_services", Provider: "Amazon Web Services",
		}},
	}
	if err := NewOriginCollector(nil).Collect(context.Background(), analysis); err != nil {
		t.Fatal(err)
	}
	if hasEvidenceType(analysis.Evidences, "ORIGIN_EXPOSURE_HINT") {
		t.Fatalf("IP da família do CDN foi tratado como origin: %+v", analysis.Evidences)
	}
}

func TestNormalizeOriginTargetWithIPv6Port(t *testing.T) {
	const target = "2606:4700:4700::1111"
	if got := normalizeOriginTarget("[" + target + "]:443"); got != target {
		t.Fatalf("IPv6 com porta normalizado como %q", got)
	}
}

func originAnalysis(value string) *core.HostAnalysis {
	analysis := &core.HostAnalysis{Host: "app.example.com", CDN: "Cloudflare"}
	analysis.SetHTTPObservation("https", newHTTPObservation("https", http.StatusOK,
		http.Header{"X-Origin-Ip": []string{value}}, []byte("application"), true, 0, "", ""))
	return analysis
}
