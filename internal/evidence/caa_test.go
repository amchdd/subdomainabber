package evidence

import (
	"context"
	"testing"

	"github.com/amchdd/subdomainabber/internal/core"
)

type fakeCAAResolver struct {
	records []string
}

func (resolver fakeCAAResolver) ResolveCAA(context.Context, string) ([]string, error) {
	return append([]string(nil), resolver.records...), nil
}

type hierarchyCAAResolver struct {
	records map[string][]string
	calls   []string
}

func (resolver *hierarchyCAAResolver) ResolveCAA(_ context.Context, host string) ([]string, error) {
	resolver.calls = append(resolver.calls, host)
	return append([]string(nil), resolver.records[host]...), nil
}

func TestCAAUsesNearestAncestor(t *testing.T) {
	analysis := &core.HostAnalysis{
		Host: "app.team.example.com",
		Evidences: []core.Evidence{{Metadata: map[string]string{
			"tls_issuer": "DigiCert TLS RSA SHA256 2020 CA1",
		}}},
	}
	resolver := &hierarchyCAAResolver{records: map[string][]string{
		"team.example.com": {"issue digicert.com"},
		"example.com":      {"issue letsencrypt.org"},
	}}

	if err := NewCAACollector(resolver).Collect(context.Background(), analysis); err != nil {
		t.Fatal(err)
	}
	if hasEvidenceType(analysis.Evidences, "CAA_ISSUER_MISMATCH") {
		t.Fatalf("emissor foi comparado com ancestral incorreto: %+v", analysis.Evidences)
	}
	if len(resolver.calls) != 1 || resolver.calls[0] != "team.example.com" {
		t.Fatalf("resolução CAA não parou no ancestral mais próximo: %v", resolver.calls)
	}
}

func TestCAAComparesZoneAndIssuer(t *testing.T) {
	analysis := &core.HostAnalysis{
		Host: "app.example.com",
		DNS:  core.DNSRecordSet{CAA: []string{"issue digicert.com"}},
		Evidences: []core.Evidence{{Type: "TLS_SAN_MATCH", Metadata: map[string]string{
			"tls_issuer": "Let's Encrypt R11",
		}}},
	}
	collector := NewCAACollector(fakeCAAResolver{records: []string{"issue letsencrypt.org"}})

	if err := collector.Collect(context.Background(), analysis); err != nil {
		t.Fatal(err)
	}
	for _, evidenceType := range []string{"CAA_POLICY_INCONSISTENT", "CAA_ISSUER_MISMATCH"} {
		if !hasEvidenceType(analysis.Evidences, evidenceType) {
			t.Fatalf("%s ausente: %+v", evidenceType, analysis.Evidences)
		}
	}
}

func TestCAAAllowsObservedIssuer(t *testing.T) {
	analysis := &core.HostAnalysis{
		Host: "example.com", DNS: core.DNSRecordSet{CAA: []string{"issue letsencrypt.org"}},
		Evidences: []core.Evidence{{Metadata: map[string]string{"tls_issuer": "Let's Encrypt R11"}}},
	}
	if err := NewCAACollector().Collect(context.Background(), analysis); err != nil {
		t.Fatal(err)
	}
	if hasEvidenceType(analysis.Evidences, "CAA_ISSUER_MISMATCH") {
		t.Fatalf("issuer permitido foi marcado como inconsistente: %+v", analysis.Evidences)
	}
}

func TestCAAIssuewildForRegularCert(t *testing.T) {
	analysis := &core.HostAnalysis{
		Host: "example.com", DNS: core.DNSRecordSet{CAA: []string{"issuewild digicert.com"}},
		Evidences: []core.Evidence{{Metadata: map[string]string{"tls_issuer": "Let's Encrypt R11", "tls_sans": "example.com"}}},
	}
	if err := NewCAACollector().Collect(context.Background(), analysis); err != nil {
		t.Fatal(err)
	}
	if hasEvidenceType(analysis.Evidences, "CAA_ISSUER_MISMATCH") {
		t.Fatalf("issuewild foi aplicado a certificado sem wildcard: %+v", analysis.Evidences)
	}
}

func TestCAAIodefStopsParentPolicy(t *testing.T) {
	analysis := &core.HostAnalysis{
		Host: "app.example.com", DNS: core.DNSRecordSet{CAA: []string{"iodef mailto:security@example.com"}},
		Evidences: []core.Evidence{{Metadata: map[string]string{"tls_issuer": "DigiCert TLS RSA SHA256 2020 CA1"}}},
	}
	collector := NewCAACollector(fakeCAAResolver{records: []string{"issue letsencrypt.org"}})
	if err := collector.Collect(context.Background(), analysis); err != nil {
		t.Fatal(err)
	}
	if hasEvidenceType(analysis.Evidences, "CAA_ISSUER_MISMATCH") {
		t.Fatalf("política da zona foi herdada apesar do RRset no host: %+v", analysis.Evidences)
	}
}
