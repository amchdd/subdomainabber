package cmd

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestLoadScanDomainsCombinesAndDeduplicatesInputs(t *testing.T) {
	listPath := filepath.Join(t.TempDir(), "hosts.txt")
	if err := os.WriteFile(listPath, []byte("# programa\nAPI.Example.COM.\ncdn.example.com\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	got, err := loadScanDomains(
		[]string{"www.example.com", "api.example.com"},
		listPath,
		strings.NewReader("cdn.example.com\nmail.example.com\n"),
		true,
	)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"www.example.com", "api.example.com", "cdn.example.com", "mail.example.com"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("domains = %#v, want %#v", got, want)
	}
}

func TestLoadScanDomainsRejectsInvalidAndMissingInputs(t *testing.T) {
	if _, err := loadScanDomains([]string{"https://example.com"}, "", nil, false); err == nil {
		t.Fatal("URL was accepted as a DNS target")
	}
	if _, err := loadScanDomains(nil, "", nil, false); err == nil {
		t.Fatal("empty input was accepted")
	}
	if _, err := loadScanDomains(nil, filepath.Join(t.TempDir(), "missing.txt"), nil, false); err == nil {
		t.Fatal("missing list was accepted")
	}
}

func TestValidScanDomainSupportsDNSLabelsButRejectsOutOfScopeSyntax(t *testing.T) {
	for _, domain := range []string{"api.example.com", "_service._tcp.example.com", "xn--bcher-kva.example"} {
		if !validScanDomain(domain) {
			t.Fatalf("valid domain rejected: %q", domain)
		}
	}
	for _, domain := range []string{"example", "example.123", "-api.example.com", "api..example.com", "example.com:443"} {
		if validScanDomain(domain) {
			t.Fatalf("invalid domain accepted: %q", domain)
		}
	}
}

func TestAggressiveAutoClaimRequiresConfirmationAndExactScanAllowlist(t *testing.T) {
	domains := []string{"bucket.example.com", "other.example.com"}
	if _, err := aggressiveClaimTargets(true, false, "bucket.example.com", domains); err == nil {
		t.Fatal("aggressive auto-claim accepted without confirmation")
	}
	if _, err := aggressiveClaimTargets(true, true, "", domains); err == nil {
		t.Fatal("aggressive auto-claim accepted without allowlist")
	}
	if _, err := aggressiveClaimTargets(true, true, "outside.example.com", domains); err == nil {
		t.Fatal("aggressive auto-claim accepted a host outside scan targets")
	}
	allowed, err := aggressiveClaimTargets(true, true, "bucket.example.com", domains)
	if err != nil || !reflect.DeepEqual(allowed, []string{"bucket.example.com"}) {
		t.Fatalf("authorized targets = %#v, %v", allowed, err)
	}
}

func TestAggressiveAutoClaimRejectsDaemonMode(t *testing.T) {
	if err := validateAggressiveRuntime(true, "5m"); err == nil {
		t.Fatal("aggressive auto-claim accepted daemon mode")
	}
	if err := validateAggressiveRuntime(true, ""); err != nil {
		t.Fatalf("single aggressive execution was rejected: %v", err)
	}
	if err := validateAggressiveRuntime(false, "5m"); err != nil {
		t.Fatalf("read-only daemon mode was rejected: %v", err)
	}
}

func TestWhoisPivotRequiresExactRegistrableDomainAllowlist(t *testing.T) {
	if _, err := authorizedWhoisPivotTargets(true, false, "other.example"); err == nil {
		t.Fatal("pivotamento aceitou execução sem confirmação")
	}
	if _, err := authorizedWhoisPivotTargets(true, true, ""); err == nil {
		t.Fatal("pivotamento aceitou execução sem lista permitida")
	}
	if _, err := authorizedWhoisPivotTargets(true, true, "api.other.example"); err == nil {
		t.Fatal("pivotamento aceitou subdomínio no lugar de domínio registrável")
	}
	allowed, err := authorizedWhoisPivotTargets(true, true, "other.example,unused.example")
	if err != nil {
		t.Fatal(err)
	}
	selected := selectDiscoveredWhoisTargets([]string{"outside.example", "OTHER.EXAMPLE.", "other.example"}, allowed)
	if !reflect.DeepEqual(selected, []string{"other.example"}) {
		t.Fatalf("alvos selecionados = %#v", selected)
	}
}

func TestWhoisPivotAuthorizationFlagsRequireFeature(t *testing.T) {
	if _, err := authorizedWhoisPivotTargets(false, true, ""); err == nil {
		t.Fatal("confirmação órfã foi aceita")
	}
	if _, err := authorizedWhoisPivotTargets(false, false, "other.example"); err == nil {
		t.Fatal("lista permitida órfã foi aceita")
	}
}

func TestAppendUniqueDomains(t *testing.T) {
	got := appendUniqueDomains([]string{"example.com", "one.example"}, []string{"one.example", "two.example"})
	want := []string{"example.com", "one.example", "two.example"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("domínios = %#v; esperado %#v", got, want)
	}
}
