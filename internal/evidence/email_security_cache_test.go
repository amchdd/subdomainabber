package evidence

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/amchdd/subdomainabber/internal/core"
)

type fakeEmailSecurityResolver struct {
	mu       sync.Mutex
	mxCalls  map[string]int
	txtCalls map[string]int
}

func newFakeEmailSecurityResolver() *fakeEmailSecurityResolver {
	return &fakeEmailSecurityResolver{
		mxCalls:  make(map[string]int),
		txtCalls: make(map[string]int),
	}
}

func (resolver *fakeEmailSecurityResolver) ResolveMX(_ context.Context, name string) ([]string, error) {
	resolver.mu.Lock()
	resolver.mxCalls[name]++
	resolver.mu.Unlock()
	// Mantém a primeira coleta aberta o bastante para que as demais chamadas
	// concorrentes compartilhem a mesma execução.
	time.Sleep(10 * time.Millisecond)
	return []string{"mail.example.net"}, nil
}

func (resolver *fakeEmailSecurityResolver) ResolveTXTWithStatus(_ context.Context, name string) ([]string, core.DNSStatus, error) {
	resolver.mu.Lock()
	resolver.txtCalls[name]++
	resolver.mu.Unlock()
	switch name {
	case "example.com":
		return []string{"v=spf1 include:orphan.example.invalid -all"}, core.DNSStatusResolved, nil
	case "orphan.example.invalid":
		return nil, core.DNSStatusNXDomain, nil
	case "_dmarc.example.com":
		return nil, core.DNSStatusNoData, nil
	default:
		return nil, core.DNSStatusNoData, nil
	}
}

func (resolver *fakeEmailSecurityResolver) callCounts() (map[string]int, map[string]int) {
	resolver.mu.Lock()
	defer resolver.mu.Unlock()
	mx := make(map[string]int, len(resolver.mxCalls))
	for name, count := range resolver.mxCalls {
		mx[name] = count
	}
	txt := make(map[string]int, len(resolver.txtCalls))
	for name, count := range resolver.txtCalls {
		txt[name] = count
	}
	return mx, txt
}

func TestEmailSecuritySharesZoneCollectionWithoutLosingHostFindings(t *testing.T) {
	resolver := newFakeEmailSecurityResolver()
	collector := &EmailSecurityCollector{resolver: resolver}
	analyses := []*core.HostAnalysis{
		{Host: "a.example.com"},
		{Host: "b.example.com"},
		{Host: "nested.c.example.com"},
	}

	start := make(chan struct{})
	var group sync.WaitGroup
	for _, analysis := range analyses {
		group.Add(1)
		go func(current *core.HostAnalysis) {
			defer group.Done()
			<-start
			if err := collector.Collect(context.Background(), current); err != nil {
				t.Errorf("Collect() retornou erro: %v", err)
			}
		}(analysis)
	}
	close(start)
	group.Wait()

	for _, analysis := range analyses {
		if !containsString(analysis.TestedVectors, "EMAIL") {
			t.Errorf("%s perdeu o vetor EMAIL: %v", analysis.Host, analysis.TestedVectors)
		}
		if !analysisHasEvidenceType(analysis, "SPF_BROKEN_INCLUDE") || !analysisHasEvidenceType(analysis, "EMAIL_DMARC_MISSING") {
			t.Errorf("%s não recebeu os achados da zona: %+v", analysis.Host, analysis.Evidences)
		}
		if len(analysis.SPFCandidates) != 1 {
			t.Errorf("%s recebeu %d candidatos SPF; esperado: 1", analysis.Host, len(analysis.SPFCandidates))
		}
	}

	mxCalls, txtCalls := resolver.callCounts()
	if mxCalls["example.com"] != 1 {
		t.Fatalf("consultas MX da zona = %d; esperado: 1", mxCalls["example.com"])
	}
	for _, owner := range []string{"example.com", "orphan.example.invalid", "_dmarc.example.com"} {
		if txtCalls[owner] != 1 {
			t.Errorf("consultas TXT de %s = %d; esperado: 1", owner, txtCalls[owner])
		}
	}

	// O cache não pode compartilhar mapas ou slices mutáveis entre hosts.
	analyses[0].Evidences[0].Metadata["alterado"] = "sim"
	analyses[0].SPFCandidates[0].Chain[0] = "alterado.example"
	if analyses[1].Evidences[0].Metadata["alterado"] != "" {
		t.Fatal("o mapa de metadados foi compartilhado entre hosts")
	}
	if analyses[1].SPFCandidates[0].Chain[0] == "alterado.example" {
		t.Fatal("a cadeia SPF foi compartilhada entre hosts")
	}
}

func TestEmailSecurityBeginBatchForcesOneNewZoneCollection(t *testing.T) {
	resolver := newFakeEmailSecurityResolver()
	collector := &EmailSecurityCollector{resolver: resolver}

	first := &core.HostAnalysis{Host: "a.example.com"}
	if err := collector.Collect(context.Background(), first); err != nil {
		t.Fatal(err)
	}
	collector.BeginBatch()
	second := &core.HostAnalysis{Host: "b.example.com"}
	if err := collector.Collect(context.Background(), second); err != nil {
		t.Fatal(err)
	}

	mxCalls, txtCalls := resolver.callCounts()
	if mxCalls["example.com"] != 2 {
		t.Fatalf("consultas MX após dois lotes = %d; esperado: 2", mxCalls["example.com"])
	}
	for _, owner := range []string{"example.com", "orphan.example.invalid", "_dmarc.example.com"} {
		if txtCalls[owner] != 2 {
			t.Errorf("consultas TXT de %s após dois lotes = %d; esperado: 2", owner, txtCalls[owner])
		}
	}
	if !analysisHasEvidenceType(second, "SPF_BROKEN_INCLUDE") || !analysisHasEvidenceType(second, "EMAIL_DMARC_MISSING") {
		t.Fatalf("o segundo lote não recebeu os achados: %+v", second.Evidences)
	}
}

func containsString(values []string, expected string) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}

func analysisHasEvidenceType(analysis *core.HostAnalysis, expected string) bool {
	for _, evidence := range analysis.Evidences {
		if evidence.Type == expected {
			return true
		}
	}
	return false
}
