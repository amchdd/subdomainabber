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
	mu.Lock()
	srvCount := counts[mdns.TypeSRV]
	ptrCount := counts[mdns.TypePTR]
	mu.Unlock()
	if srvCount != 0 || ptrCount != 0 {
		t.Fatalf("bare profile issued SRV/PTR queries: SRV=%d PTR=%d", srvCount, ptrCount)
	}
}

func TestDiscoveryQueriesExactSRVOwner(t *testing.T) {
	var srvQueries int
	var mu sync.Mutex
	address, shutdown := startTestDNSServer(t, "udp", func(writer mdns.ResponseWriter, request *mdns.Msg) {
		if request.Question[0].Qtype == mdns.TypeSRV {
			mu.Lock()
			srvQueries++
			mu.Unlock()
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
	mu.Lock()
	got := srvQueries
	mu.Unlock()
	if got != 1 {
		t.Fatalf("exact SRV owner queries = %d, want 1", got)
	}
}
