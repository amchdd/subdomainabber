package dns

import (
	"testing"

	"github.com/amchdd/subdomainabber/internal/core"
	mdns "github.com/miekg/dns"
)

func TestConsensusStates(t *testing.T) {
	tests := []struct {
		name  string
		views []core.DNSView
		want  string
	}{
		{"consenso", []core.DNSView{{Status: core.DNSStatusNXDomain}, {Status: core.DNSStatusNXDomain}, {Status: core.DNSStatusResolved}}, "CONSENSUS"},
		{"propagação", []core.DNSView{{Status: core.DNSStatusNXDomain}, {Status: core.DNSStatusResolved}}, "PROPAGATING"},
		{"divergência", []core.DNSView{{Status: core.DNSStatusResolved, Answers: []string{"a"}}, {Status: core.DNSStatusResolved, Answers: []string{"b"}}}, "SPLIT_HORIZON"},
		{"inconclusivo", []core.DNSView{{Status: core.DNSStatusTimeout}, {Status: core.DNSStatusResolved}}, "INCONCLUSIVE"},
	}
	for _, test := range tests {
		if got := consensusState(test.views, len(test.views)/2+1); got != test.want {
			t.Errorf("%s: estado %s, esperado %s", test.name, got, test.want)
		}
	}
}

func TestConsensusAnswerIgnoresTTL(t *testing.T) {
	first, _ := mdns.NewRR("app.example. 60 IN A 192.0.2.10")
	second, _ := mdns.NewRR("app.example. 30 IN A 192.0.2.10")
	if consensusAnswer(first) != consensusAnswer(second) {
		t.Fatalf("o TTL alterou a identidade da resposta: %q != %q", consensusAnswer(first), consensusAnswer(second))
	}
}

func TestResolverCloneKeepsIndependentConsensusState(t *testing.T) {
	original := New([]string{"192.0.2.1:53", "192.0.2.2:53"})
	clone := original.Clone()
	clone.SetConsensus(true)
	if original.consensus || !clone.consensus || !clone.ConsensusAvailable() {
		t.Fatalf("estado inesperado: original=%t clone=%t disponível=%t", original.consensus, clone.consensus, clone.ConsensusAvailable())
	}
}

func TestConsensusStatusRequiresQuorum(t *testing.T) {
	views := []core.DNSView{{Status: core.DNSStatusNXDomain}, {Status: core.DNSStatusNXDomain}, {Status: core.DNSStatusResolved}}
	if got := consensusStatus(views, 2); got != core.DNSStatusNXDomain {
		t.Fatalf("status %s, esperado NXDOMAIN", got)
	}
	if got := consensusStatus(views, 3); got != core.DNSStatusError {
		t.Fatalf("quórum ausente produziu %s", got)
	}
}
