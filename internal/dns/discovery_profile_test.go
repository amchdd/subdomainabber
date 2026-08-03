package dns

import (
	"context"
	"sync"
	"testing"

	mdns "github.com/miekg/dns"
)

func TestDiscoverySkipsBareSRVAndForwardPTRQueries(t *testing.T) {
	var mu sync.Mutex
	counts := make(map[uint16]int)
	address, shutdown := startTestDNSServer(t, "udp", func(writer mdns.ResponseWriter, request *mdns.Msg) {
		mu.Lock()
		counts[request.Question[0].Qtype]++
		mu.Unlock()
		response := new(mdns.Msg)
		response.SetReply(request)
		_ = writer.WriteMsg(response)
	})
	defer shutdown()

	resolver := New([]string{address})
	resolver.SetWildcardFiltering(false)
	if _, err := resolver.DiscoverProfile(context.Background(), "www.example.com"); err != nil {
		t.Fatal(err)
	}
	if counts[mdns.TypeSRV] != 0 || counts[mdns.TypePTR] != 0 {
		t.Fatalf("bare profile issued SRV/PTR queries: SRV=%d PTR=%d", counts[mdns.TypeSRV], counts[mdns.TypePTR])
	}
}

func TestDiscoveryQueriesExactSRVOwner(t *testing.T) {
	var srvQueries int
	address, shutdown := startTestDNSServer(t, "udp", func(writer mdns.ResponseWriter, request *mdns.Msg) {
		if request.Question[0].Qtype == mdns.TypeSRV {
			srvQueries++
		}
		response := new(mdns.Msg)
		response.SetReply(request)
		_ = writer.WriteMsg(response)
	})
	defer shutdown()

	resolver := New([]string{address})
	resolver.SetWildcardFiltering(false)
	if _, err := resolver.DiscoverProfile(context.Background(), "_sip._tcp.example.com"); err != nil {
		t.Fatal(err)
	}
	if srvQueries != 1 {
		t.Fatalf("exact SRV owner queries = %d, want 1", srvQueries)
	}
}
