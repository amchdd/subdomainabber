package evidence

import (
	"context"
	"crypto/x509"
	"testing"

	"github.com/amchdd/subdomainabber/internal/core"
)

func TestTLSWildcardRequiresDNSLabelBoundary(t *testing.T) {
	cert := &x509.Certificate{DNSNames: []string{"*.example.com"}}
	if !certificateCoversHost(cert, "app.example.com") {
		t.Fatal("o curinga válido de um único label não correspondeu ao host")
	}
	for _, host := range []string{"example.com", "deep.app.example.com", "x.badexample.com"} {
		if certificateCoversHost(cert, host) {
			t.Fatalf("o curinga correspondeu indevidamente ao host %q", host)
		}
	}
}

func TestShadowITCollectorRequiresDNSLabelBoundary(t *testing.T) {
	collector := NewShadowITCollector()
	analysis := &core.HostAnalysis{DNS: core.DNSRecordSet{CNAME: []string{
		"tracker.segment.com",
		"segment.com.attacker.example",
	}}}
	if err := collector.Collect(context.Background(), analysis); err != nil {
		t.Fatal(err)
	}
	if len(analysis.Evidences) != 1 {
		t.Fatalf("evidências de Shadow IT = %d; esperado: 1: %#v", len(analysis.Evidences), analysis.Evidences)
	}
}
