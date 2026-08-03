package evidence

import "testing"

func TestUniqueNamesPreventsNSDoubleCounting(t *testing.T) {
	got := uniqueNames([]string{"NS1.EXAMPLE.", "ns1.example", "ns2.example", "ns2.example."})
	if len(got) != 2 {
		t.Fatalf("unique names = %#v", got)
	}
}

func TestSPFMechanismDoesNotCountAllAsAddressLookup(t *testing.T) {
	if mechanism, _, consumes := spfMechanism("-all"); consumes || mechanism != "" {
		t.Fatalf("-all parsed as lookup: %q %t", mechanism, consumes)
	}
	if mechanism, target, consumes := spfMechanism("include:_spf.example.com"); !consumes || mechanism != "include" || target != "_spf.example.com" {
		t.Fatalf("include parse = %q %q %t", mechanism, target, consumes)
	}
	if mechanism, target, consumes := spfMechanism("redirect=_spf.example.com"); !consumes || mechanism != "redirect" || target != "_spf.example.com" {
		t.Fatalf("redirect parse = %q %q %t", mechanism, target, consumes)
	}
}

func TestProviderTargetOwnershipUsesDNSBoundaries(t *testing.T) {
	if !dnsSuffixMatch("tenant.mail.protection.outlook.com", "mail.protection.outlook.com") {
		t.Fatal("valid provider suffix did not match")
	}
	if dnsSuffixMatch("mail.protection.outlook.com.attacker.test", "mail.protection.outlook.com") {
		t.Fatal("provider suffix crossed a DNS boundary")
	}
	if got := externalTargetOwnership("tenant.mail.protection.outlook.com"); got != "PROVIDER_OWNED" {
		t.Fatalf("ownership = %s", got)
	}
	if got := externalTargetOwnership("mail.external-example.test"); got != "EXTERNAL_UNVERIFIED" {
		t.Fatalf("ownership = %s", got)
	}
}
