package evidence

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/amchdd/subdomainabber/internal/core"
	"github.com/amchdd/subdomainabber/internal/dns"
)

type fakeZoneTransferResolver struct {
	attempts atomic.Int64
}

func (resolver *fakeZoneTransferResolver) FindAuthoritativeZone(context.Context, string) (dns.AuthoritativeZone, error) {
	return dns.AuthoritativeZone{
		Zone: "example.com", Nameservers: []string{"ns1.example.net"},
	}, nil
}

func (resolver *fakeZoneTransferResolver) AttemptAXFR(context.Context, string, string) (bool, error) {
	resolver.attempts.Add(1)
	return true, nil
}

func TestZoneTransferSharesNetworkCheckAndReportsEveryHost(t *testing.T) {
	resolver := &fakeZoneTransferResolver{}
	collector := NewZoneTransferCollector(resolver)
	analyses := []*core.HostAnalysis{
		{
			Host: "a.example.com",
			Delegation: &core.DelegationCandidate{
				Zone: "example.com", DelegatedNameservers: []string{"ns1.example.net"},
			},
		},
		{
			Host: "b.example.com",
			Delegation: &core.DelegationCandidate{
				Zone: "example.com", DelegatedNameservers: []string{"ns1.example.net"},
			},
		},
	}
	start := make(chan struct{})
	var group sync.WaitGroup
	for _, analysis := range analyses {
		group.Add(1)
		go func(current *core.HostAnalysis) {
			defer group.Done()
			<-start
			if err := collector.Collect(context.Background(), current); err != nil {
				t.Errorf("collect: %v", err)
			}
		}(analysis)
	}
	close(start)
	group.Wait()

	for _, analysis := range analyses {
		if !containsString(analysis.TestedVectors, "AXFR") {
			t.Errorf("%s perdeu o vetor AXFR: %v", analysis.Host, analysis.TestedVectors)
		}
		if !analysisHasEvidenceType(analysis, "DNS_AXFR_ALLOWED") {
			t.Errorf("%s não recebeu o achado AXFR: %+v", analysis.Host, analysis.Evidences)
		}
		if got := analysis.Evidences[0].Metadata["zone"]; got != "example.com" {
			t.Errorf("chave de zona de %s = %q; esperado: example.com", analysis.Host, got)
		}
	}
	if got := resolver.attempts.Load(); got != 1 {
		t.Fatalf("tentativas AXFR de rede = %d; esperado: 1", got)
	}

	analyses[0].Evidences[0].Metadata["alterado"] = "sim"
	if analyses[1].Evidences[0].Metadata["alterado"] != "" {
		t.Fatal("os metadados AXFR foram compartilhados entre hosts")
	}

	collector.BeginBatch()
	next := &core.HostAnalysis{
		Host: "c.example.com",
		Delegation: &core.DelegationCandidate{
			Zone: "example.com", DelegatedNameservers: []string{"ns1.example.net"},
		},
	}
	if err := collector.Collect(context.Background(), next); err != nil {
		t.Fatal(err)
	}
	if len(next.Evidences) != 1 {
		t.Fatalf("a troca de lote não permitiu revalidar: %+v", next.Evidences)
	}
	if got := resolver.attempts.Load(); got != 2 {
		t.Fatalf("tentativas AXFR após dois lotes = %d; esperado: 2", got)
	}
}
