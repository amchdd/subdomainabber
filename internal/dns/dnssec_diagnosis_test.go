package dns

import (
	"testing"

	mdns "github.com/miekg/dns"
)

func TestDNSSECDiagnosisSeparatesBogus(t *testing.T) {
	normal := &mdns.Msg{MsgHdr: mdns.MsgHdr{Rcode: mdns.RcodeServerFailure}}
	checkingDisabled := &mdns.Msg{MsgHdr: mdns.MsgHdr{Rcode: mdns.RcodeSuccess}}
	result := classifyDNSSEC(normal, checkingDisabled)
	if result.State != "BOGUS" {
		t.Fatalf("diagnóstico = %+v", result)
	}
}

func TestDNSSECDiagnosisKeepsNXDOMAIN(t *testing.T) {
	normal := &mdns.Msg{MsgHdr: mdns.MsgHdr{Rcode: mdns.RcodeNameError}}
	result := classifyDNSSEC(normal, nil)
	if result.State != "NXDOMAIN" {
		t.Fatalf("diagnóstico = %+v", result)
	}
}
