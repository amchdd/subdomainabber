package platform

import "testing"

func TestTargetFromAsset(t *testing.T) {
	tests := []struct {
		value string
		kind  AssetKind
		host  string
		root  string
	}{
		{"*.Api.Example.com", KindWildcard, "", "api.example.com"},
		{"https://Portal.Example.com/login", KindURL, "portal.example.com", "portal.example.com"},
		{"example.com", KindDomain, "example.com", "example.com"},
		{"192.0.2.10", KindIP, "", ""},
		{"192.0.2.0/24", KindCIDR, "", ""},
	}
	for _, test := range tests {
		asset := NormalizeAsset(test.value, "")
		if asset.Kind != test.kind || asset.Host != test.host || asset.ReconRoot != test.root {
			t.Fatalf("normalização inesperada para %q: %+v", test.value, asset)
		}
	}
}

func TestTestingOpenRejectsNegativeStates(t *testing.T) {
	for _, state := range []string{"inactive", "not open", "closed"} {
		if testingOpen(state) {
			t.Fatalf("estado negativo aceito: %s", state)
		}
	}
}
