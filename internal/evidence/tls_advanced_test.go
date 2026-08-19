package evidence

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"testing"
	"time"

	"github.com/amchdd/subdomainabber/internal/core"
	"github.com/amchdd/subdomainabber/pkg/signatures"
)

type routedTLSDialer struct {
	states map[string]*tls.ConnectionState
	names  []string
}

func (dialer *routedTLSDialer) DialTLSContext(_ context.Context, _, _ string, config *tls.Config) (*tls.ConnectionState, error) {
	dialer.names = append(dialer.names, config.ServerName)
	return dialer.states[config.ServerName], nil
}

func TestSNIWithoutNameRunsByDefault(t *testing.T) {
	primary := testCert("app.example.com", "Issuer A")
	fallback := testCert("default.example.net", "Issuer B")
	dialer := &routedTLSDialer{states: map[string]*tls.ConnectionState{
		"app.example.com": {PeerCertificates: []*x509.Certificate{primary}},
		"":                {PeerCertificates: []*x509.Certificate{fallback}},
	}}
	collector := NewTLSCollector(nil, time.Second)
	collector.SetDialer(dialer)
	analysis := &core.HostAnalysis{Host: "app.example.com", DNS: core.DNSRecordSet{A: []string{"192.0.2.10"}}}

	if err := collector.Collect(context.Background(), analysis); err != nil {
		t.Fatal(err)
	}
	if evidenceCount(analysis, "SNI_CERT_MISMATCH") != 1 || len(dialer.names) != 2 || dialer.names[1] != "" {
		t.Fatalf("comparação SNI padrão inesperada: nomes=%v evidências=%+v", dialer.names, analysis.Evidences)
	}
}

func TestSNIFindsDifferentCert(t *testing.T) {
	primary := testCert("app.example.com", "Issuer A")
	fallback := testCert("default.example.net", "Issuer B")
	collector := NewTLSCollector(nil, time.Second)
	collector.SetDialer(&routedTLSDialer{states: map[string]*tls.ConnectionState{
		"app.example.com":   {PeerCertificates: []*x509.Certificate{primary}},
		"":                  {PeerCertificates: []*x509.Certificate{fallback}},
		"probe.example.com": {PeerCertificates: []*x509.Certificate{fallback}},
	}})
	collector.EnableSNI(true)
	collector.sniName = func(string) string { return "probe.example.com" }
	analysis := &core.HostAnalysis{Host: "app.example.com", DNS: core.DNSRecordSet{A: []string{"192.0.2.10"}}}

	if err := collector.Collect(context.Background(), analysis); err != nil {
		t.Fatal(err)
	}
	if evidenceCount(analysis, "SNI_CERT_MISMATCH") != 2 || len(analysis.SNIVariants) != 2 {
		t.Fatalf("diferenças SNI não registradas: %+v", analysis)
	}
}

func TestSANPivotKeepsAllowedNames(t *testing.T) {
	cert := testCert("app.example.com", "Issuer")
	cert.DNSNames = []string{"app.example.com", "api.example.com", "*.example.com", "outside.example.net"}
	collector := NewTLSCollector(nil, time.Second)
	collector.SetDialer(fixedTLSStateDialer{state: &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}})
	collector.SetSANRoots([]string{"example.com"})
	analysis := &core.HostAnalysis{Host: "app.example.com", DNS: core.DNSRecordSet{A: []string{"192.0.2.10"}}}

	if err := collector.Collect(context.Background(), analysis); err != nil {
		t.Fatal(err)
	}
	if len(analysis.SANCandidates) != 1 || analysis.SANCandidates[0] != "api.example.com" {
		t.Fatalf("candidatos SAN inesperados: %#v", analysis.SANCandidates)
	}
}

func TestSANDiscoveryKeepsRelatedNamesWithoutPivot(t *testing.T) {
	cert := testCert("app.example.com", "Issuer")
	cert.DNSNames = []string{"app.example.com", "api.example.com", "outside.example.net"}
	collector := NewTLSCollector(nil, time.Second)
	collector.SetDialer(fixedTLSStateDialer{state: &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}})
	analysis := &core.HostAnalysis{Host: "app.example.com", DNS: core.DNSRecordSet{A: []string{"192.0.2.10"}}}

	if err := collector.Collect(context.Background(), analysis); err != nil {
		t.Fatal(err)
	}
	if len(analysis.SANCandidates) != 1 || analysis.SANCandidates[0] != "api.example.com" {
		t.Fatalf("descoberta SAN inesperada: %#v", analysis.SANCandidates)
	}
}

func TestCertificateDrift(t *testing.T) {
	cert := testCert("app.example.com", "Issuer B")
	collector := NewTLSCollector(nil, time.Second)
	collector.SetDialer(fixedTLSStateDialer{state: &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}})
	analysis := &core.HostAnalysis{
		Host: "app.example.com", DNS: core.DNSRecordSet{A: []string{"192.0.2.10"}},
		PreviousEvidences: []core.Evidence{{Type: "TLS_CERTIFICATE_OBSERVED", Metadata: map[string]string{
			"tls_fingerprint": "old", "tls_issuer": "Issuer A", "tls_sans": "old.example.com",
		}}},
	}

	if err := collector.Collect(context.Background(), analysis); err != nil {
		t.Fatal(err)
	}
	if !hasEvidenceType(analysis.Evidences, "TLS_CERTIFICATE_DRIFT") {
		t.Fatalf("drift semântico não detectado: %+v", analysis.Evidences)
	}
}

func TestCertificateRenewal(t *testing.T) {
	cert := testCert("app.example.com", "Issuer A")
	collector := NewTLSCollector(nil, time.Second)
	collector.SetDialer(fixedTLSStateDialer{state: &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}})
	analysis := &core.HostAnalysis{
		Host: "app.example.com", DNS: core.DNSRecordSet{A: []string{"192.0.2.10"}},
		PreviousEvidences: []core.Evidence{{Type: "TLS_CERTIFICATE_OBSERVED", Metadata: map[string]string{
			"tls_fingerprint": "old", "tls_issuer": "Issuer A", "tls_sans": "app.example.com", "tls_provider": "",
		}}},
	}

	if err := collector.Collect(context.Background(), analysis); err != nil {
		t.Fatal(err)
	}
	if hasEvidenceType(analysis.Evidences, "TLS_CERTIFICATE_DRIFT") {
		t.Fatalf("renovação comum foi tratada como drift: %+v", analysis.Evidences)
	}
}

func TestCertificateProviderDrift(t *testing.T) {
	cert := testCert("app.example.com", "Issuer")
	collector := NewTLSCollector([]signatures.Fingerprint{{Service: "Provider B", TLSFingerprints: []string{"app.example.com"}}}, time.Second)
	collector.SetDialer(fixedTLSStateDialer{state: &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}})
	analysis := &core.HostAnalysis{
		Host: "app.example.com", DNS: core.DNSRecordSet{A: []string{"192.0.2.10"}},
		PreviousEvidences: []core.Evidence{{Type: "TLS_CERTIFICATE_OBSERVED", Metadata: map[string]string{
			"tls_fingerprint": "old", "tls_issuer": "Issuer", "tls_sans": "app.example.com", "tls_provider": "Provider A",
		}}},
	}

	if err := collector.Collect(context.Background(), analysis); err != nil {
		t.Fatal(err)
	}
	evidence, ok := evidenceOfType(analysis.Evidences, "TLS_CERTIFICATE_DRIFT")
	if !ok || evidence.Metadata["changed"] != "provider" {
		t.Fatalf("mudança de provider não detectada: %+v", analysis.Evidences)
	}
}

func testCert(name, issuer string) *x509.Certificate {
	cert := &x509.Certificate{DNSNames: []string{name}, NotAfter: time.Now().Add(time.Hour)}
	cert.Issuer.CommonName = issuer
	cert.Subject.CommonName = name
	return cert
}

func evidenceCount(analysis *core.HostAnalysis, evidenceType string) int {
	count := 0
	for _, evidence := range analysis.Evidences {
		if evidence.Type == evidenceType {
			count++
		}
	}
	return count
}
