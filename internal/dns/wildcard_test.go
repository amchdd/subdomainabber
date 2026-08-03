package dns

import (
	"context"
	"net"
	"sync/atomic"
	"testing"

	mdns "github.com/miekg/dns"
)

func TestWildcardRequiresTwoMatchingTypedProbes(t *testing.T) {
	var requests atomic.Int64
	address, shutdown := startTestDNSServer(t, "udp", func(writer mdns.ResponseWriter, request *mdns.Msg) {
		requests.Add(1)
		response := new(mdns.Msg)
		response.SetReply(request)
		name := request.Question[0].Name
		switch request.Question[0].Qtype {
		case mdns.TypeA:
			response.Answer = []mdns.RR{
				&mdns.CNAME{Hdr: mdns.RR_Header{Name: name, Rrtype: mdns.TypeCNAME, Class: mdns.ClassINET}, Target: "edge.example.net."},
				&mdns.A{Hdr: mdns.RR_Header{Name: "edge.example.net.", Rrtype: mdns.TypeA, Class: mdns.ClassINET}, A: net.ParseIP("192.0.2.10")},
			}
		case mdns.TypeAAAA:
			response.Answer = []mdns.RR{
				&mdns.AAAA{Hdr: mdns.RR_Header{Name: "edge.example.net.", Rrtype: mdns.TypeAAAA, Class: mdns.ClassINET}, AAAA: net.ParseIP("2001:db8::10")},
			}
		}
		_ = writer.WriteMsg(response)
	})
	defer shutdown()

	resolver := New([]string{address})
	isWildcard, signature, err := resolver.IsWildcard(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("a verificação de curinga falhou: %v", err)
	}
	if !isWildcard || !signature.MatchesA([]string{"192.0.2.10"}) ||
		!signature.MatchesAAAA([]string{"2001:db8::10"}) ||
		!signature.MatchesCNAME([]string{"edge.example.net"}) {
		t.Fatalf("assinatura de curinga inesperada: %+v", signature)
	}
	if requests.Load() != 4 {
		t.Fatalf("a verificação não executou duas sondas A/AAAA: consultas=%d", requests.Load())
	}
}

func TestWildcardRejectsNonReproducibleResponses(t *testing.T) {
	var aQueries atomic.Int64
	address, shutdown := startTestDNSServer(t, "udp", func(writer mdns.ResponseWriter, request *mdns.Msg) {
		response := new(mdns.Msg)
		response.SetReply(request)
		if request.Question[0].Qtype == mdns.TypeA {
			lastOctet := byte(10 + aQueries.Add(1))
			response.Answer = []mdns.RR{&mdns.A{
				Hdr: mdns.RR_Header{Name: request.Question[0].Name, Rrtype: mdns.TypeA, Class: mdns.ClassINET},
				A:   net.IPv4(192, 0, 2, lastOctet),
			}}
		}
		_ = writer.WriteMsg(response)
	})
	defer shutdown()

	resolver := New([]string{address})
	isWildcard, signature, err := resolver.IsWildcard(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("a verificação de curinga falhou: %v", err)
	}
	if isWildcard || !signature.Empty() {
		t.Fatalf("respostas não reproduzíveis foram aceitas como curinga: %+v", signature)
	}
}
