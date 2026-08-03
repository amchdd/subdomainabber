package evidence

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"strings"
	"testing"
	"time"

	"github.com/amchdd/subdomainabber/internal/core"
	"github.com/amchdd/subdomainabber/pkg/signatures"
)

type fixedTLSStateDialer struct {
	state *tls.ConnectionState
	err   error
}

func (d fixedTLSStateDialer) DialTLSContext(context.Context, string, string, *tls.Config) (*tls.ConnectionState, error) {
	return d.state, d.err
}

func TestTLSExactNameDoesNotCoverSubdomain(t *testing.T) {
	cert := &x509.Certificate{DNSNames: []string{"example.com"}}
	if !certificateCoversHost(cert, "example.com") {
		t.Fatal("o nome exato do certificado deveria corresponder ao host")
	}
	if certificateCoversHost(cert, "foo.example.com") {
		t.Fatal("um certificado para example.com não deve cobrir foo.example.com")
	}
}

func TestTLSWildcardCoversOnlyOneLabel(t *testing.T) {
	cert := &x509.Certificate{DNSNames: []string{"*.example.com"}}
	if !certificateCoversHost(cert, "foo.example.com") {
		t.Fatal("o curinga deveria cobrir exatamente um label")
	}
	if certificateCoversHost(cert, "bar.foo.example.com") {
		t.Fatal("o curinga não deve cobrir dois labels")
	}
}

func TestTLSCommonNameLegadoNaoSubstituiSAN(t *testing.T) {
	cert := &x509.Certificate{Subject: x509.Certificate{}.Subject}
	cert.Subject.CommonName = "example.com"
	if certificateCoversHost(cert, "example.com") {
		t.Fatal("o Common Name legado não deve substituir a extensão SAN")
	}
}

func TestTLSCollectorSemCertificadoApresentadoNaoEntraEmPanico(t *testing.T) {
	for _, peerCertificates := range [][]*x509.Certificate{nil, {nil}} {
		collector := NewTLSCollector(nil, time.Second)
		collector.SetDialer(fixedTLSStateDialer{state: &tls.ConnectionState{PeerCertificates: peerCertificates}})
		analysis := &core.HostAnalysis{
			Host: "example.com",
			DNS:  core.DNSRecordSet{A: []string{"192.0.2.1"}},
		}

		if err := collector.Collect(context.Background(), analysis); err != nil {
			t.Fatalf("a coleta TLS retornou erro: %v", err)
		}
		if len(analysis.Evidences) != 0 {
			t.Fatalf("a coleta sem certificado gerou evidências: %#v", analysis.Evidences)
		}
	}
}

func TestTLSCollectorDistingueHostnameDeCadeiaConfiavel(t *testing.T) {
	cert := &x509.Certificate{
		DNSNames: []string{"example.com"},
		NotAfter: time.Now().Add(time.Hour),
	}
	collector := NewTLSCollector(nil, time.Second)
	collector.SetDialer(fixedTLSStateDialer{state: &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{cert},
	}})
	analysis := &core.HostAnalysis{
		Host: "example.com",
		DNS:  core.DNSRecordSet{A: []string{"192.0.2.1"}},
	}

	if err := collector.Collect(context.Background(), analysis); err != nil {
		t.Fatalf("a coleta TLS retornou erro: %v", err)
	}
	evidence, ok := evidenceOfType(analysis.Evidences, "TLS_SAN_MATCH")
	if !ok {
		t.Fatalf("a correspondência SAN não foi registrada: %#v", analysis.Evidences)
	}
	if evidence.Metadata["tls_hostname_match"] != "true" {
		t.Fatalf("tls_hostname_match = %q; esperado: true", evidence.Metadata["tls_hostname_match"])
	}
	if evidence.Metadata["tls_chain_validation"] != "not_performed" {
		t.Fatalf("tls_chain_validation = %q; esperado: not_performed", evidence.Metadata["tls_chain_validation"])
	}
	if !strings.Contains(evidence.Description, "cadeia de confiança") || !strings.Contains(evidence.Description, "não foram verificadas") {
		t.Fatalf("a descrição não esclarece a ausência de validação criptográfica: %q", evidence.Description)
	}
}

func TestTLSCollectorIgnoraFingerprintVazio(t *testing.T) {
	cert := &x509.Certificate{
		DNSNames: []string{"example.com"},
		NotAfter: time.Now().Add(time.Hour),
	}
	collector := NewTLSCollector([]signatures.Fingerprint{{
		Service:         "Provedor vazio",
		TLSFingerprints: []string{"", "   "},
		Confidence:      100,
	}}, time.Second)
	collector.SetDialer(fixedTLSStateDialer{state: &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{cert},
	}})
	analysis := &core.HostAnalysis{
		Host: "example.com",
		DNS:  core.DNSRecordSet{A: []string{"192.0.2.1"}},
	}

	if err := collector.Collect(context.Background(), analysis); err != nil {
		t.Fatalf("a coleta TLS retornou erro: %v", err)
	}
	if _, ok := evidenceOfType(analysis.Evidences, "TLS_PROVIDER_MATCH"); ok {
		t.Fatalf("uma fingerprint TLS vazia gerou correspondência: %#v", analysis.Evidences)
	}
}

func evidenceOfType(evidences []core.Evidence, evidenceType string) (core.Evidence, bool) {
	for _, evidence := range evidences {
		if evidence.Type == evidenceType {
			return evidence, true
		}
	}
	return core.Evidence{}, false
}
