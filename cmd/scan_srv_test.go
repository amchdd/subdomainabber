package cmd

import "testing"

func TestParseSRVOwners(t *testing.T) {
	owners, err := parseSRVOwners("_sip._tcp,_minecraft._tcp,_sip._tcp")
	if err != nil || len(owners) != 2 {
		t.Fatalf("owners=%#v err=%v", owners, err)
	}
	for _, invalid := range []string{"sip.tcp", "_sip.example.com", "_sip._http", "_sip._tcp.example.com"} {
		if _, err := parseSRVOwners(invalid); err == nil {
			t.Fatalf("accepted invalid owner %q", invalid)
		}
	}
}
