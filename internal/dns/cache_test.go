package dns

import (
	"context"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	mdns "github.com/miekg/dns"
)

func TestDNSQueryCacheKeyIncludesDNSSECFlags(t *testing.T) {
	plain := new(mdns.Msg)
	plain.SetQuestion("example.com.", mdns.TypeA)
	plain.RecursionDesired = true

	dnssec := plain.Copy()
	dnssec.SetEdns0(4096, true)
	if dnsQueryCacheKey(plain) == dnsQueryCacheKey(dnssec) {
		t.Fatal("plain A and DNSSEC DO query share a cache key")
	}
}

func TestExchangeSingleflightAndBatchReset(t *testing.T) {
	var requests atomic.Int64
	address, shutdown := startTestDNSServer(t, "udp", func(writer mdns.ResponseWriter, request *mdns.Msg) {
		requests.Add(1)
		time.Sleep(30 * time.Millisecond)
		response := new(mdns.Msg)
		response.SetReply(request)
		response.Answer = []mdns.RR{&mdns.A{
			Hdr: mdns.RR_Header{Name: request.Question[0].Name, Rrtype: mdns.TypeA, Class: mdns.ClassINET, Ttl: 60},
			A:   net.ParseIP("192.0.2.10"),
		}}
		_ = writer.WriteMsg(response)
	})
	defer shutdown()

	resolver := New([]string{address})
	var group sync.WaitGroup
	for index := 0; index < 25; index++ {
		group.Add(1)
		go func() {
			defer group.Done()
			message := new(mdns.Msg)
			message.SetQuestion("singleflight.example.", mdns.TypeA)
			message.RecursionDesired = true
			if _, err := resolver.exchange(context.Background(), message); err != nil {
				t.Errorf("exchange: %v", err)
			}
		}()
	}
	group.Wait()
	if requests.Load() != 1 {
		t.Fatalf("expected one wire query, got %d", requests.Load())
	}

	resolver.ClearCache()
	message := new(mdns.Msg)
	message.SetQuestion("singleflight.example.", mdns.TypeA)
	message.RecursionDesired = true
	if _, err := resolver.exchange(context.Background(), message); err != nil {
		t.Fatal(err)
	}
	if requests.Load() != 2 {
		t.Fatalf("cache did not reset between batches: %d requests", requests.Load())
	}
}

func TestNSHealthIsCachedPerZoneAndNameserver(t *testing.T) {
	var requests atomic.Int64
	address, shutdown := startTestDNSServer(t, "udp", func(writer mdns.ResponseWriter, request *mdns.Msg) {
		requests.Add(1)
		response := new(mdns.Msg)
		response.SetReply(request)
		response.Authoritative = true
		response.Answer = []mdns.RR{&mdns.SOA{
			Hdr:     mdns.RR_Header{Name: request.Question[0].Name, Rrtype: mdns.TypeSOA, Class: mdns.ClassINET, Ttl: 60},
			Ns:      "ns1.example.net.",
			Mbox:    "hostmaster.example.com.",
			Serial:  1,
			Refresh: 60,
			Retry:   60,
			Expire:  60,
			Minttl:  60,
		}}
		_ = writer.WriteMsg(response)
	})
	defer shutdown()

	resolver := New(nil)
	for index := 0; index < 2; index++ {
		status, err := resolver.CheckNSHealth(context.Background(), address, "example.com")
		if err != nil || status != "HEALTHY" {
			t.Fatalf("health %d: status=%s err=%v", index, status, err)
		}
	}
	if requests.Load() != 1 {
		t.Fatalf("expected one authoritative health query, got %d", requests.Load())
	}
}

func TestNSHealthRequiresAuthoritativeMatchingSOA(t *testing.T) {
	tests := []struct {
		name          string
		authoritative bool
		owner         string
	}{
		{name: "non-authoritative", owner: "example.com."},
		{name: "wrong SOA owner", authoritative: true, owner: "other.example."},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			address, shutdown := startTestDNSServer(t, "udp", func(writer mdns.ResponseWriter, request *mdns.Msg) {
				response := new(mdns.Msg)
				response.SetReply(request)
				response.Authoritative = test.authoritative
				response.Answer = []mdns.RR{&mdns.SOA{
					Hdr: mdns.RR_Header{Name: test.owner, Rrtype: mdns.TypeSOA, Class: mdns.ClassINET, Ttl: 60},
					Ns:  "ns1.example.net.", Mbox: "hostmaster.example.com.",
				}}
				_ = writer.WriteMsg(response)
			})
			defer shutdown()

			resolver := New(nil)
			status, err := resolver.CheckNSHealth(context.Background(), address, "example.com")
			if err != nil || status != "LAME" {
				t.Fatalf("status=%s err=%v, want LAME", status, err)
			}
		})
	}
}

func TestAXFRAttemptIsCachedPerZoneAndNameserver(t *testing.T) {
	var requests atomic.Int64
	address, shutdown := startTestDNSServer(t, "tcp", func(writer mdns.ResponseWriter, request *mdns.Msg) {
		requests.Add(1)
		response := new(mdns.Msg)
		response.SetRcode(request, mdns.RcodeRefused)
		_ = writer.WriteMsg(response)
	})
	defer shutdown()

	resolver := New(nil)
	for index := 0; index < 2; index++ {
		success, err := resolver.AttemptAXFR(context.Background(), "example.com", address)
		if success {
			t.Fatalf("refused AXFR was reported successful on attempt %d", index)
		}
		if err != nil {
			t.Logf("expected refused AXFR error: %v", err)
		}
	}
	if requests.Load() != 1 {
		t.Fatalf("expected one AXFR transaction per batch, got %d", requests.Load())
	}
}

func TestDNSSECResultIsCachedByZoneAndResetPerBatch(t *testing.T) {
	var requests atomic.Int64
	address, shutdown := startTestDNSServer(t, "udp", func(writer mdns.ResponseWriter, request *mdns.Msg) {
		requests.Add(1)
		response := new(mdns.Msg)
		response.SetReply(request)
		_ = writer.WriteMsg(response)
	})
	defer shutdown()

	resolver := New([]string{address})
	for index := 0; index < 2; index++ {
		if _, err := resolver.CheckDNSSEC(context.Background(), "example.com"); err != nil {
			t.Fatal(err)
		}
	}
	if requests.Load() != 3 {
		t.Fatalf("expected three DNSSEC queries for one zone, got %d", requests.Load())
	}
	resolver.ClearCache()
	if _, err := resolver.CheckDNSSEC(context.Background(), "example.com"); err != nil {
		t.Fatal(err)
	}
	if requests.Load() != 6 {
		t.Fatalf("DNSSEC batch cache did not reset: %d requests", requests.Load())
	}
}

func startTestDNSServer(
	t *testing.T,
	network string,
	handler func(mdns.ResponseWriter, *mdns.Msg),
) (string, func()) {
	t.Helper()
	var (
		server  *mdns.Server
		address string
	)
	switch network {
	case "udp":
		connection, listenErr := net.ListenPacket("udp", "127.0.0.1:0")
		if listenErr != nil {
			t.Fatal(listenErr)
		}
		server = &mdns.Server{PacketConn: connection, Handler: mdns.HandlerFunc(handler)}
		address = connection.LocalAddr().String()
	case "tcp":
		listener, listenErr := net.Listen("tcp", "127.0.0.1:0")
		if listenErr != nil {
			t.Fatal(listenErr)
		}
		server = &mdns.Server{Listener: listener, Handler: mdns.HandlerFunc(handler)}
		address = listener.Addr().String()
	default:
		t.Fatalf("unsupported network %q", network)
	}
	started := make(chan struct{})
	go func() {
		close(started)
		_ = server.ActivateAndServe()
	}()
	<-started
	return address, func() {
		_ = server.Shutdown()
	}
}
