package dns

import (
	"context"
	"testing"

	mdns "github.com/miekg/dns"
)

func TestResolveMXPreservesNullMX(t *testing.T) {
	address, shutdown := startTestDNSServer(t, "udp", func(writer mdns.ResponseWriter, request *mdns.Msg) {
		response := new(mdns.Msg)
		response.SetReply(request)
		response.Answer = []mdns.RR{&mdns.MX{
			Hdr:        mdns.RR_Header{Name: request.Question[0].Name, Rrtype: mdns.TypeMX, Class: mdns.ClassINET, Ttl: 60},
			Preference: 0,
			Mx:         ".",
		}}
		_ = writer.WriteMsg(response)
	})
	defer shutdown()

	resolver := New([]string{address})
	records, err := resolver.ResolveMX(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("a consulta Null MX falhou: %v", err)
	}
	if len(records) != 1 || records[0] != "." {
		t.Fatalf("Null MX não foi preservado: %#v", records)
	}
}

func TestResolveMXKeepsPriorityOrder(t *testing.T) {
	address, shutdown := startTestDNSServer(t, "udp", func(writer mdns.ResponseWriter, request *mdns.Msg) {
		response := new(mdns.Msg)
		response.SetReply(request)
		header := mdns.RR_Header{Name: request.Question[0].Name, Rrtype: mdns.TypeMX, Class: mdns.ClassINET, Ttl: 60}
		response.Answer = []mdns.RR{
			&mdns.MX{Hdr: header, Preference: 20, Mx: "backup.example.net."},
			&mdns.MX{Hdr: header, Preference: 10, Mx: "primary.example.net."},
		}
		_ = writer.WriteMsg(response)
	})
	defer shutdown()

	records, err := New([]string{address}).ResolveMXRecords(context.Background(), "example.com")
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 2 || records[0].Preference != 10 || records[0].Target != "primary.example.net" {
		t.Fatalf("prioridades MX não preservadas: %#v", records)
	}
}
