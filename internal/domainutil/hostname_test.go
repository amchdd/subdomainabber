package domainutil

import "testing"

func TestMatchDNSName(t *testing.T) {
	tests := []struct {
		name    string
		target  string
		pattern string
		want    bool
	}{
		{name: "exact", target: "github.io", pattern: "github.io", want: true},
		{name: "subdomain", target: "user.github.io", pattern: "github.io", want: true},
		{name: "suffix collision", target: "evilgithub.io", pattern: "github.io", want: false},
		{name: "parent collision", target: "github.io.evil.com", pattern: "github.io", want: false},
		{name: "short suffix collision", target: "123abc.com", pattern: "abc.com", want: false},
		{name: "trailing dot", target: "cdn.example.com.", pattern: "example.com", want: true},
		{name: "empty pattern", target: "anything.example.com", pattern: "", want: false},
		{name: "single label wildcard", target: "one.example.com", pattern: "*.example.com", want: true},
		{name: "wildcard does not span labels", target: "two.one.example.com", pattern: "*.example.com", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := MatchDNSName(tt.target, tt.pattern); got != tt.want {
				t.Fatalf("MatchDNSName(%q, %q) = %t, want %t", tt.target, tt.pattern, got, tt.want)
			}
		})
	}
}

func TestMatchDNSProviderPatternKeepsSuffixBoundary(t *testing.T) {
	if !MatchDNSProviderPattern("ns-123.awsdns-45.com", "awsdns-*.com") {
		t.Fatal("expected anchored AWS nameserver pattern to match")
	}
	for _, hostile := range []string{
		"ns1.awsdns-evil.attacker.example",
		"awsdns-45.com.attacker.example",
		"evilawsdns-45.com",
	} {
		if MatchDNSProviderPattern(hostile, "awsdns-*.com") {
			t.Fatalf("provider fragment collision matched %q", hostile)
		}
	}
}
