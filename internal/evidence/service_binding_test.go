package evidence

import (
	"context"
	"testing"

	"github.com/amchdd/subdomainabber/internal/core"
	"github.com/amchdd/subdomainabber/pkg/signatures"
)

func TestServiceBindingsPreserveModeAndProvider(t *testing.T) {
	analysis := &core.HostAnalysis{Host: "www.example.com", DNS: core.DNSRecordSet{
		HTTPS: []core.ServiceBinding{{Priority: 1, Target: "app.vendor.test", Params: map[string]string{"alpn": "h2"}}},
		DNAME: []core.DNAMERecord{{Owner: "example.com", Target: "example.net"}},
	}}
	collector := NewServiceBindingCollector([]signatures.Fingerprint{{Service: "Fornecedor", CNames: []string{"vendor.test"}}})
	if err := collector.Collect(context.Background(), analysis); err != nil {
		t.Fatal(err)
	}
	if !hasEvidenceType(analysis.Evidences, "HTTPS_BINDING") || !hasEvidenceType(analysis.Evidences, "HTTPS_PROVIDER_MATCH") {
		t.Fatalf("evidências ausentes: %+v", analysis.Evidences)
	}
	if alias := synthesizeDNAME(analysis.Host, analysis.DNS.DNAME[0]); alias != "www.example.net" {
		t.Fatalf("alias DNAME inesperado: %s", alias)
	}
}
