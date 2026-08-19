package evidence

import (
	"context"
	"testing"

	"github.com/amchdd/subdomainabber/internal/core"
)

type fakeTargetResolver struct {
	chains map[string][]string
	status map[string]core.DNSStatus
}

func (resolver *fakeTargetResolver) ResolveCNAMEChain(_ context.Context, host string) ([]string, error) {
	return append([]string(nil), resolver.chains[host]...), nil
}

func (resolver *fakeTargetResolver) ResolveAddressStatus(_ context.Context, host string) core.DNSStatus {
	if status, ok := resolver.status[host]; ok {
		return status
	}
	return core.DNSStatusResolved
}

func TestMXKeepsHealthyFallback(t *testing.T) {
	resolver := &fakeTargetResolver{status: map[string]core.DNSStatus{
		"primary.mail.test": core.DNSStatusNXDomain,
		"backup.mail.test":  core.DNSStatusResolved,
	}}
	analysis := &core.HostAnalysis{DNS: core.DNSRecordSet{MXRecords: []core.MXRecord{
		{Preference: 10, Target: "primary.mail.test"},
		{Preference: 20, Target: "backup.mail.test"},
	}}}

	if err := NewMXCollector(resolver, nil).Collect(context.Background(), analysis); err != nil {
		t.Fatal(err)
	}
	if !hasEvidenceType(analysis.Evidences, "MX_PRIMARY_BROKEN_WITH_FALLBACK") {
		t.Fatalf("fallback saudável não reconhecido: %+v", analysis.Evidences)
	}
	if analysis.MXCandidates[0].Role != "primary" || analysis.MXCandidates[0].HealthyAlternatives != 1 {
		t.Fatalf("estado MX incorreto: %+v", analysis.MXCandidates)
	}
}

func TestMXFollowsCNAME(t *testing.T) {
	resolver := &fakeTargetResolver{
		chains: map[string][]string{"mx.example.test": {"mail.provider.test"}},
		status: map[string]core.DNSStatus{"mail.provider.test": core.DNSStatusNXDomain},
	}
	analysis := &core.HostAnalysis{DNS: core.DNSRecordSet{MXRecords: []core.MXRecord{{Preference: 10, Target: "mx.example.test"}}}}

	if err := NewMXCollector(resolver, nil).Collect(context.Background(), analysis); err != nil {
		t.Fatal(err)
	}
	if analysis.MXCandidates[0].FinalTarget != "mail.provider.test" || !hasEvidenceType(analysis.Evidences, "MX_BROKEN") {
		t.Fatalf("cadeia MX não seguida: %+v", analysis.MXCandidates)
	}
}

func TestSRVFollowsCNAME(t *testing.T) {
	resolver := &fakeTargetResolver{
		chains: map[string][]string{"sip.example.test": {"edge.provider.test"}},
		status: map[string]core.DNSStatus{"edge.provider.test": core.DNSStatusNoData},
	}
	analysis := &core.HostAnalysis{DNS: core.DNSRecordSet{SRVRecords: []core.SRVRecord{{
		Owner: "_sip._tcp.example.test", Target: "sip.example.test", Port: 443,
	}}}}

	if err := NewSRVCollector(resolver, nil).Collect(context.Background(), analysis); err != nil {
		t.Fatal(err)
	}
	if analysis.SRVCandidates[0].FinalTarget != "edge.provider.test" || !hasEvidenceType(analysis.Evidences, "SRV_BROKEN") {
		t.Fatalf("cadeia SRV não seguida: %+v", analysis.SRVCandidates)
	}
}
