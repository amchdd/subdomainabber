package dns

import "testing"

func TestExtractRootDomainUsesPublicSuffixList(t *testing.T) {
	tests := map[string]string{
		"api.example.com":       "example.com",
		"assets.example.co.uk.": "example.co.uk",
		"localhost":             "localhost",
	}
	for input, want := range tests {
		if got := ExtractRootDomain(input); got != want {
			t.Fatalf("ExtractRootDomain(%q) = %q, want %q", input, got, want)
		}
	}
}
