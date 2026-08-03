package evidence

import (
	"context"
	"testing"

	"github.com/amchdd/subdomainabber/internal/core"
	"github.com/amchdd/subdomainabber/internal/dns"
)

type fakeDNSSECResolver struct {
	checked string
}

func (resolver *fakeDNSSECResolver) CheckDNSSEC(_ context.Context, zone string) (map[string]bool, error) {
	resolver.checked = zone
	return map[string]bool{"DNSKEY": true}, nil
}

func (resolver *fakeDNSSECResolver) FindAuthoritativeZone(_ context.Context, host string) (dns.AuthoritativeZone, error) {
	return dns.AuthoritativeZone{Zone: "example.com"}, nil
}

func TestDNSSECCollectorUsesDelegationZoneApex(t *testing.T) {
	resolver := &fakeDNSSECResolver{}
	analysis := &core.HostAnalysis{
		Host:       "api.dev.example.com",
		Delegation: &core.DelegationCandidate{Zone: "dev.example.com"},
	}
	if err := NewDNSSECCollector(resolver).Collect(context.Background(), analysis); err != nil {
		t.Fatal(err)
	}
	if resolver.checked != "dev.example.com" {
		t.Fatalf("checked %q instead of delegated apex", resolver.checked)
	}
	if len(analysis.Evidences) != 1 || analysis.Evidences[0].Metadata["zone"] != "dev.example.com" {
		t.Fatalf("unexpected evidence: %+v", analysis.Evidences)
	}
	if analysis.Evidences[0].Type != "DNSSEC_ARTIFACTS_OBSERVED" || analysis.Evidences[0].IsNegative || analysis.Evidences[0].Weight != 0 {
		t.Fatalf("artefatos DNSSEC foram tratados como validação: %+v", analysis.Evidences[0])
	}
}
