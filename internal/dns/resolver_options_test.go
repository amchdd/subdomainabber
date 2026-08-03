package dns

import (
	"testing"
	"time"
)

func TestWildcardFilteringCanBeDisabled(t *testing.T) {
	resolver := New([]string{"127.0.0.1:53"})
	if !resolver.filterWildcard {
		t.Fatal("wildcard filtering should be enabled by default")
	}
	resolver.SetWildcardFiltering(false)
	if resolver.filterWildcard {
		t.Fatal("SetWildcardFiltering(false) did not disable the discovery filter")
	}
}

func TestResolverTimeoutAppliesToAllDNSOperations(t *testing.T) {
	resolver := New([]string{"127.0.0.1:53"})
	resolver.SetTimeout(125 * time.Millisecond)
	if resolver.client.Timeout != 125*time.Millisecond || resolver.operationTimeout() != 125*time.Millisecond {
		t.Fatalf("timeout was not propagated: client=%s operation=%s", resolver.client.Timeout, resolver.operationTimeout())
	}
}
