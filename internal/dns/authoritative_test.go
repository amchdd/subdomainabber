package dns

import (
	"context"
	"net"
	"reflect"
	"sync/atomic"
	"testing"

	"github.com/amchdd/subdomainabber/internal/core"
	mdns "github.com/miekg/dns"
)

func TestResolveAddressStatusRequiresConclusiveAbsence(t *testing.T) {
	address, shutdown := startTestDNSServer(t, "udp", func(writer mdns.ResponseWriter, request *mdns.Msg) {
		response := new(mdns.Msg)
		if request.Question[0].Qtype == mdns.TypeAAAA {
			response.SetRcode(request, mdns.RcodeServerFailure)
		} else {
			response.SetReply(request)
		}
		_ = writer.WriteMsg(response)
	})
	defer shutdown()

	resolver := New([]string{address})
	if got := resolver.ResolveAddressStatus(context.Background(), "mixed.example"); got != core.DNSStatusServFail {
		t.Fatalf("A=NODATA + AAAA=SERVFAIL = %s, want %s", got, core.DNSStatusServFail)
	}
}

func TestResolveAddressStatusDoesNotPreferNXDomainOverServFail(t *testing.T) {
	address, shutdown := startTestDNSServer(t, "udp", func(writer mdns.ResponseWriter, request *mdns.Msg) {
		response := new(mdns.Msg)
		if request.Question[0].Qtype == mdns.TypeA {
			response.SetRcode(request, mdns.RcodeNameError)
		} else {
			response.SetRcode(request, mdns.RcodeServerFailure)
		}
		_ = writer.WriteMsg(response)
	})
	defer shutdown()

	resolver := New([]string{address})
	if got := resolver.ResolveAddressStatus(context.Background(), "mixed.example"); got != core.DNSStatusServFail {
		t.Fatalf("A=NXDOMAIN + AAAA=SERVFAIL = %s, esperado %s", got, core.DNSStatusServFail)
	}
}

func TestResolveAddressStatusTreatsNXDomainAndNoDataAsContradictory(t *testing.T) {
	address, shutdown := startTestDNSServer(t, "udp", func(writer mdns.ResponseWriter, request *mdns.Msg) {
		response := new(mdns.Msg)
		if request.Question[0].Qtype == mdns.TypeA {
			response.SetRcode(request, mdns.RcodeNameError)
		} else {
			response.SetReply(request)
		}
		_ = writer.WriteMsg(response)
	})
	defer shutdown()

	resolver := New([]string{address})
	if got := resolver.ResolveAddressStatus(context.Background(), "mixed.example"); got != core.DNSStatusError {
		t.Fatalf("A=NXDOMAIN + AAAA=NODATA = %s, esperado %s", got, core.DNSStatusError)
	}
}

func TestAuthoritativeDiscoveryFallsBackToParentWalkAfterInconclusiveSOA(t *testing.T) {
	var requests atomic.Int64
	address, shutdown := startTestDNSServer(t, "udp", func(writer mdns.ResponseWriter, request *mdns.Msg) {
		requests.Add(1)
		response := new(mdns.Msg)
		response.SetRcode(request, mdns.RcodeServerFailure)
		_ = writer.WriteMsg(response)
	})
	defer shutdown()

	resolver := New([]string{address})
	if _, err := resolver.FindAuthoritativeZone(context.Background(), "deep.api.example.com"); err == nil {
		t.Fatal("SERVFAIL sem delegação autoritativa foi tratado como conclusivo")
	}
	if requests.Load() <= 1 {
		t.Fatalf("a resposta SOA inconclusiva não acionou a busca segura pela delegação pai: %d consulta(s)", requests.Load())
	}
}

func TestProfileWildcardComparisonPreservesExplicitDifferentRecord(t *testing.T) {
	signature := WildcardSignature{A: []string{"192.0.2.10"}}
	if profileMatchesWildcard(core.DNSRecordSet{A: []string{"192.0.2.20"}}, signature) {
		t.Fatal("explicit record different from wildcard was filtered")
	}
	if !profileMatchesWildcard(core.DNSRecordSet{A: []string{"192.0.2.10"}}, signature) {
		t.Fatal("identical wildcard response was not recognized")
	}
}

func TestProfileWildcardComparisonPreservesTypedRRsets(t *testing.T) {
	signature := WildcardSignature{
		A: []string{"192.0.2.10"}, CNAME: []string{"edge.example.net"},
	}
	if profileMatchesWildcard(core.DNSRecordSet{
		A: []string{"192.0.2.20"}, CNAME: []string{"edge.example.net"},
	}, signature) {
		t.Fatal("um CNAME igual ocultou um endereço A explícito diferente")
	}
	if !profileMatchesWildcard(core.DNSRecordSet{
		A: []string{"192.0.2.10"}, CNAME: []string{"edge.example.net"},
	}, signature) {
		t.Fatal("RRsets tipados idênticos não foram reconhecidos como curinga")
	}
}

func TestResponseStatusUsesDNSRcode(t *testing.T) {
	nxdomain := &mdns.Msg{MsgHdr: mdns.MsgHdr{Rcode: mdns.RcodeNameError}}
	if got := responseStatus(nxdomain, mdns.TypeA); got != core.DNSStatusNXDomain {
		t.Fatalf("NXDOMAIN = %s", got)
	}
	nodata := &mdns.Msg{MsgHdr: mdns.MsgHdr{Rcode: mdns.RcodeSuccess}}
	if got := responseStatus(nodata, mdns.TypeA); got != core.DNSStatusNoData {
		t.Fatalf("NODATA = %s", got)
	}
}

func TestAuthoritativeZoneMustBeDNSAncestorOfOriginalOwner(t *testing.T) {
	tests := []struct {
		name string
		zone string
		want bool
	}{
		{"go2.anaconda.com", "anaconda.com", true},
		{"projects.bk.dev.anaconda.com", "projects.bk.dev.anaconda.com", true},
		{"go2.anaconda.com.", "ANACONDA.COM.", true},
		{"go2.anaconda.com", "mkto-ab140016.com", false},
		{"notanaconda.com", "anaconda.com", false},
		{"", "example.com", false},
	}
	for _, test := range tests {
		if got := isDNSAncestorOrSelf(test.name, test.zone); got != test.want {
			t.Fatalf("isDNSAncestorOrSelf(%q, %q) = %t, want %t", test.name, test.zone, got, test.want)
		}
	}
}

func TestNameserverEndpointHandlesIPv4AndIPv6Literals(t *testing.T) {
	resolver := New(nil)
	for input, want := range map[string]string{"192.0.2.1": "192.0.2.1:53", "2001:db8::1": "[2001:db8::1]:53"} {
		got, err := resolver.nameserverEndpoint(context.Background(), input)
		if err != nil || got != want {
			t.Fatalf("endpoint(%s) = %q, %v; want %q", input, got, err, want)
		}
	}
}

func TestParentZonePreservesDelegatedSubzone(t *testing.T) {
	if got := parentZone("dev.example.com"); got != "example.com" {
		t.Fatalf("parent = %s", got)
	}
	if got := parentZone("example.com"); got != "com" {
		t.Fatalf("registrable parent = %s", got)
	}
}

func TestAuthoritativeZoneCacheReturnsClonesAndResetsPerBatch(t *testing.T) {
	resolver := New(nil)
	resolver.zoneCache.Store("example.com", AuthoritativeZone{
		Zone: "example.com", ParentZone: "com",
		Nameservers: []string{"ns1.example.net"},
		Glue: map[string][]string{
			"ns1.example.net": {"192.0.2.53"},
		},
	})

	first, err := resolver.authoritativeZoneDetails(context.Background(), "example.com", nil, nil, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	first.Nameservers[0] = "mutated.example"
	first.Glue["ns1.example.net"][0] = "192.0.2.99"

	second, err := resolver.authoritativeZoneDetails(context.Background(), "example.com", nil, nil, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	if second.Nameservers[0] != "ns1.example.net" || second.Glue["ns1.example.net"][0] != "192.0.2.53" {
		t.Fatalf("cached authoritative details were mutated: %+v", second)
	}
	resolver.ClearCache()
	if _, exists := resolver.zoneCache.Load("example.com"); exists {
		t.Fatal("authoritative zone cache survived batch reset")
	}
}

func TestParentDSAnyObservedRecordPrevails(t *testing.T) {
	wanted := mdns.Fqdn("child.example.com")
	nodata := &mdns.Msg{MsgHdr: mdns.MsgHdr{Rcode: mdns.RcodeSuccess}}
	withDS := &mdns.Msg{
		MsgHdr: mdns.MsgHdr{Rcode: mdns.RcodeSuccess},
		Answer: []mdns.RR{&mdns.DS{
			Hdr:        mdns.RR_Header{Name: wanted, Rrtype: mdns.TypeDS, Class: mdns.ClassINET},
			KeyTag:     12345,
			Algorithm:  mdns.RSASHA256,
			DigestType: mdns.SHA256,
			Digest:     "0123456789abcdef",
		}},
	}

	for name, responses := range map[string][]*mdns.Msg{
		"DS após NODATA":     {nodata, withDS},
		"DS antes de NODATA": {withDS, nodata},
	} {
		t.Run(name, func(t *testing.T) {
			hasDS, checked := summarizeParentDSResponses(responses, wanted)
			if !hasDS || !checked {
				t.Fatalf("hasDS=%t, checked=%t; esperado true, true", hasDS, checked)
			}
		})
	}
}

func TestParentServerQueryDoesNotStopAfterFirstPositiveResponse(t *testing.T) {
	wanted := mdns.Fqdn("child.example.com")
	withDS := &mdns.Msg{
		MsgHdr: mdns.MsgHdr{Rcode: mdns.RcodeSuccess},
		Answer: []mdns.RR{&mdns.DS{
			Hdr:        mdns.RR_Header{Name: wanted, Rrtype: mdns.TypeDS, Class: mdns.ClassINET},
			KeyTag:     12345,
			Algorithm:  mdns.RSASHA256,
			DigestType: mdns.SHA256,
			Digest:     "0123456789abcdef",
		}},
	}
	nodata := &mdns.Msg{MsgHdr: mdns.MsgHdr{Rcode: mdns.RcodeSuccess}}
	resolver := New(nil)
	var endpoints []string

	responses, complete := resolver.queryParentServers(
		context.Background(),
		[]string{"192.0.2.3", "192.0.2.1", "192.0.2.2"},
		wanted,
		mdns.TypeDS,
		func(_ context.Context, request *mdns.Msg, endpoint string) (*mdns.Msg, error) {
			endpoints = append(endpoints, endpoint)
			if len(request.Question) != 1 || request.Question[0].Qtype != mdns.TypeDS || request.RecursionDesired {
				t.Fatalf("consulta autoritativa inválida: %+v", request)
			}
			if len(endpoints) == 1 {
				return withDS, nil
			}
			return nodata, nil
		},
	)

	if !complete {
		t.Fatal("a consulta de todos os servidores foi marcada como incompleta")
	}
	wantEndpoints := []string{"192.0.2.1:53", "192.0.2.2:53", "192.0.2.3:53"}
	if !reflect.DeepEqual(endpoints, wantEndpoints) {
		t.Fatalf("endpoints consultados = %v, esperados %v", endpoints, wantEndpoints)
	}
	if len(responses) != len(wantEndpoints) {
		t.Fatalf("respostas coletadas = %d, esperadas %d", len(responses), len(wantEndpoints))
	}
	if hasDS, checked := summarizeParentDSResponses(responses, wanted); !hasDS || !checked {
		t.Fatalf("hasDS=%t, checked=%t; esperado true, true", hasDS, checked)
	}
}

func TestParentDSSummaryRequiresValidResponse(t *testing.T) {
	wanted := mdns.Fqdn("child.example.com")
	servfail := &mdns.Msg{MsgHdr: mdns.MsgHdr{Rcode: mdns.RcodeServerFailure}}
	if hasDS, checked := summarizeParentDSResponses([]*mdns.Msg{nil, servfail}, wanted); hasDS || checked {
		t.Fatalf("hasDS=%t, checked=%t; respostas inconclusivas não devem validar o estado de DS", hasDS, checked)
	}
	if hasDS, checked := summarizeParentDSResponses(
		[]*mdns.Msg{{MsgHdr: mdns.MsgHdr{Rcode: mdns.RcodeSuccess}}},
		wanted,
	); hasDS || !checked {
		t.Fatalf("hasDS=%t, checked=%t; NODATA válido deve comprovar a ausência de DS", hasDS, checked)
	}
	dsInAuthority := &mdns.Msg{
		MsgHdr: mdns.MsgHdr{Rcode: mdns.RcodeSuccess},
		Ns: []mdns.RR{&mdns.DS{
			Hdr:        mdns.RR_Header{Name: wanted, Rrtype: mdns.TypeDS, Class: mdns.ClassINET},
			Algorithm:  mdns.RSASHA256,
			DigestType: mdns.SHA256,
		}},
	}
	if hasDS, checked := summarizeParentDSResponses([]*mdns.Msg{dsInAuthority}, wanted); !hasDS || !checked {
		t.Fatalf("hasDS=%t, checked=%t; um DS na seção de autoridade foi ignorado", hasDS, checked)
	}
}

func TestParentServerQueryReportsContextCancellationAsIncomplete(t *testing.T) {
	resolver := New(nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	requests := 0

	responses, complete := resolver.queryParentServers(
		ctx,
		[]string{"192.0.2.1", "192.0.2.2"},
		mdns.Fqdn("child.example.com"),
		mdns.TypeNS,
		func(_ context.Context, _ *mdns.Msg, _ string) (*mdns.Msg, error) {
			requests++
			cancel()
			return &mdns.Msg{MsgHdr: mdns.MsgHdr{Rcode: mdns.RcodeSuccess}}, nil
		},
	)

	if complete {
		t.Fatal("uma coleta cancelada foi marcada como completa")
	}
	if requests != 1 || len(responses) != 1 {
		t.Fatalf("consultas=%d, respostas=%d; esperado 1, 1", requests, len(responses))
	}
}

func TestParentDelegationRequiresConsensusAcrossValidViews(t *testing.T) {
	wanted := mdns.Fqdn("child.example.com")
	first := parentDelegationResponse(wanted, mdns.RcodeSuccess,
		[]string{"ns1.provider.example", "ns2.provider.example"},
		map[string]string{
			"ns1.provider.example":    "192.0.2.10",
			"unrelated.attacker.test": "192.0.2.99",
		},
	)
	second := parentDelegationResponse(wanted, mdns.RcodeSuccess,
		[]string{"NS2.PROVIDER.EXAMPLE.", "ns1.provider.example."},
		nil,
	)

	delegated, glue, verified := summarizeParentDelegationResponses([]*mdns.Msg{first, second}, wanted)
	if !verified {
		t.Fatal("conjuntos NS equivalentes foram tratados como divergentes")
	}
	wantDelegated := []string{"ns1.provider.example", "ns2.provider.example"}
	if !reflect.DeepEqual(delegated, wantDelegated) {
		t.Fatalf("delegação = %v, esperada %v", delegated, wantDelegated)
	}
	if got := glue["ns1.provider.example"]; !reflect.DeepEqual(got, []string{"192.0.2.10"}) {
		t.Fatalf("glue do NS delegado = %v", got)
	}
	if _, exists := glue["unrelated.attacker.test"]; exists {
		t.Fatal("registro adicional não relacionado foi aceito como glue da delegação")
	}
}

func TestParentDelegationRejectsContradictoryNameserverSets(t *testing.T) {
	wanted := mdns.Fqdn("child.example.com")
	first := parentDelegationResponse(wanted, mdns.RcodeSuccess,
		[]string{"ns1.provider.example", "ns2.provider.example"}, nil)
	second := parentDelegationResponse(wanted, mdns.RcodeSuccess,
		[]string{"ns3.provider.example", "ns4.provider.example"}, nil)

	delegated, _, verified := summarizeParentDelegationResponses([]*mdns.Msg{first, second}, wanted)
	if verified {
		t.Fatal("visões autoritativas contraditórias foram marcadas como verificadas")
	}
	want := []string{
		"ns1.provider.example", "ns2.provider.example",
		"ns3.provider.example", "ns4.provider.example",
	}
	if !reflect.DeepEqual(delegated, want) {
		t.Fatalf("conjunto combinado = %v, esperado %v", delegated, want)
	}
}

func TestParentDelegationTreatsValidNegativeViewAsContradiction(t *testing.T) {
	wanted := mdns.Fqdn("child.example.com")
	delegated := parentDelegationResponse(wanted, mdns.RcodeSuccess,
		[]string{"ns1.provider.example", "ns2.provider.example"}, nil)
	nodata := parentDelegationResponse(wanted, mdns.RcodeSuccess, nil, nil)
	servfail := parentDelegationResponse(wanted, mdns.RcodeServerFailure, nil, nil)

	if _, _, verified := summarizeParentDelegationResponses([]*mdns.Msg{delegated, nodata}, wanted); verified {
		t.Fatal("NODATA autoritativo em conflito com uma delegação foi ignorado")
	}
	if _, _, verified := summarizeParentDelegationResponses([]*mdns.Msg{delegated, servfail}, wanted); !verified {
		t.Fatal("SERVFAIL inconclusivo impediu uma delegação válida sem visão contraditória")
	}
}

func parentDelegationResponse(wanted string, rcode int, nameservers []string, glue map[string]string) *mdns.Msg {
	response := &mdns.Msg{MsgHdr: mdns.MsgHdr{Rcode: rcode}}
	for _, nameserver := range nameservers {
		response.Ns = append(response.Ns, &mdns.NS{
			Hdr: mdns.RR_Header{Name: wanted, Rrtype: mdns.TypeNS, Class: mdns.ClassINET},
			Ns:  mdns.Fqdn(nameserver),
		})
	}
	for owner, address := range glue {
		response.Extra = append(response.Extra, &mdns.A{
			Hdr: mdns.RR_Header{Name: mdns.Fqdn(owner), Rrtype: mdns.TypeA, Class: mdns.ClassINET},
			A:   net.ParseIP(address).To4(),
		})
	}
	return response
}
