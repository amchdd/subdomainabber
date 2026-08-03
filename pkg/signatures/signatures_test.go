package signatures

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func writeFingerprintFixture(t *testing.T, contents string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "fingerprints.json")
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatalf("writing fixture: %v", err)
	}
	return path
}

func TestLoadFromFileRejectsCNAMEFingerprintWithoutValidPattern(t *testing.T) {
	path := writeFingerprintFixture(t, `[
		{"service":"Invalid","cname":[""],"fingerprint":"Not Found","check_type":"cname","vulnerable":true}
	]`)

	if _, err := LoadFromFile(path); err == nil {
		t.Fatal("expected an error for a CNAME fingerprint without a valid CNAME pattern")
	}
}

func TestLoadFromFileSanitizesCNAMEPatterns(t *testing.T) {
	path := writeFingerprintFixture(t, `[
		{"service":"GitHub Pages","cname":["", " GitHub.IO. ", "github.io"],"fingerprint":"There isn't a GitHub Pages site here.","check_type":"cname","vulnerable":true}
	]`)

	loaded, err := LoadFromFile(path)
	if err != nil {
		t.Fatalf("LoadFromFile returned an unexpected error: %v", err)
	}
	if len(loaded) != 1 {
		t.Fatalf("expected one fingerprint, got %d", len(loaded))
	}
	want := []string{"github.io"}
	if !reflect.DeepEqual(loaded[0].CNames, want) {
		t.Fatalf("unexpected normalized CNAME patterns: got %#v, want %#v", loaded[0].CNames, want)
	}
}

func TestLoadEmbeddedDoesNotExposeEmptyCNAMEPatterns(t *testing.T) {
	loaded, err := LoadEmbedded()
	if err != nil {
		t.Fatalf("LoadEmbedded returned an unexpected error: %v", err)
	}
	for _, fingerprint := range loaded {
		for vector, patterns := range map[string][]string{
			"CNAME": fingerprint.CNames, "NS": fingerprint.NSFingerprints,
			"MX": fingerprint.MXFingerprints, "SRV": fingerprint.SRVFingerprints,
			"TXT": fingerprint.TXTFingerprints, "SPF": fingerprint.SPFFingerprints,
			"TLS": fingerprint.TLSFingerprints, "ASN": fingerprint.ASNFingerprints,
		} {
			for _, pattern := range patterns {
				if strings.TrimSpace(pattern) == "" {
					t.Fatalf("o serviço %q expôs um padrão %s vazio em tempo de execução", fingerprint.Service, vector)
				}
			}
		}
	}
}

func TestLoadFromFileRejectsEmptyPatternForDeclaredVector(t *testing.T) {
	for _, fixture := range []string{
		`[{"service":"TXT inválido","check_type":"txt","txt_fingerprints":["  "],"vulnerable":true}]`,
		`[{"service":"TLS inválido","check_type":"tls","tls_fingerprints":[""],"vulnerable":true}]`,
		`[{"service":"ASN inválido","check_type":"a","asn_fingerprints":[""],"vulnerable":true}]`,
	} {
		if _, err := LoadFromFile(writeFingerprintFixture(t, fixture)); err == nil {
			t.Fatalf("uma assinatura sem padrão útil foi aceita: %s", fixture)
		}
	}
}

func TestLoadFromFileRejectsInvalidRegexInsteadOfChangingItsMeaning(t *testing.T) {
	path := writeFingerprintFixture(t, `[
		{"service":"Regex inválida","cname":["provider.example"],"fingerprint":"(","regex":true,"check_type":"cname","vulnerable":true}
	]`)
	if _, err := LoadFromFile(path); err == nil {
		t.Fatal("uma regex inválida foi reinterpretada como texto literal")
	}
}

func TestMergeSignaturesPreservesVectorsForExplicitIdentity(t *testing.T) {
	merged := MergeSignatures(
		[]Fingerprint{{ID: "provider-main", Service: "Provider", CheckType: "cname", CNames: []string{"provider.example"}, Fingerprint: "missing", Vulnerable: true, ActiveVerifier: "provider"}},
		[]Fingerprint{{ID: "provider-main", Service: "Provider", CheckType: "cname", CNames: []string{"provider.example"}, Fingerprint: "missing", Vulnerable: true, TXTFingerprints: []string{"provider-verification="}, ProofRequirements: []string{"controle ativo"}}},
	)
	if len(merged) != 1 || len(merged[0].TXTFingerprints) != 1 || merged[0].ActiveVerifier != "provider" || len(merged[0].ProofRequirements) != 1 {
		t.Fatalf("a mesclagem apagou mecanismos complementares: %#v", merged)
	}
}

func TestMergeSignaturesDoesNotCollapseDistinctRulesSharingFirstCNAME(t *testing.T) {
	merged := MergeSignatures([]Fingerprint{
		{Service: "Provider", CheckType: "cname", CNames: []string{"provider.example", "a.provider.example"}, Fingerprint: "resource a missing", Vulnerable: true},
		{Service: "Provider", CheckType: "cname", CNames: []string{"provider.example", "b.provider.example"}, Fingerprint: "resource b missing", Vulnerable: true},
	})
	if len(merged) != 2 {
		t.Fatalf("regras distintas foram reduzidas pelo primeiro CNAME: %#v", merged)
	}
}

func TestLoadFromFilePrecompilesConditionRegex(t *testing.T) {
	path := writeFingerprintFixture(t, `[
		{"service":"Engine","cname":["provider.example"],"check_type":"cname","vulnerable":true,
		 "engine":{"type":"REGEX","value":"resource [0-9]+ missing"}}
	]`)
	loaded, err := LoadFromFile(path)
	if err != nil {
		t.Fatalf("a assinatura DSL válida foi rejeitada: %v", err)
	}
	if len(loaded) != 1 || loaded[0].Engine == nil || loaded[0].Engine.Compiled == nil {
		t.Fatalf("a regex DSL não foi pré-compilada: %#v", loaded)
	}
}

func TestEmbeddedCorpusCoversNonCNAMEVectorsAndActiveProofMetadata(t *testing.T) {
	loaded, err := LoadEmbedded()
	if err != nil {
		t.Fatalf("LoadEmbedded returned an unexpected error: %v", err)
	}
	counts := map[string]int{}
	hasRoute53Proof := false
	for _, fingerprint := range loaded {
		if len(fingerprint.NSFingerprints) > 0 {
			counts["ns"]++
		}
		if len(fingerprint.MXFingerprints) > 0 {
			counts["mx"]++
		}
		if len(fingerprint.SRVFingerprints) > 0 {
			counts["srv"]++
		}
		if len(fingerprint.TXTFingerprints) > 0 {
			counts["txt"]++
		}
		if len(fingerprint.SPFFingerprints) > 0 {
			counts["spf"]++
		}
		if len(fingerprint.ASNFingerprints) > 0 {
			counts["asn"]++
		}
		if fingerprint.ActiveVerifier == "aws_route53" && len(fingerprint.ProofRequirements) >= 3 {
			hasRoute53Proof = true
		}
	}
	for _, vector := range []string{"ns", "mx", "srv", "txt", "spf", "asn"} {
		if counts[vector] == 0 {
			t.Fatalf("embedded corpus has no %s signatures", vector)
		}
	}
	if !hasRoute53Proof {
		t.Fatal("embedded corpus has no Route53 active-proof metadata")
	}
}

func TestMatchesPatternPreservesDNSBoundaries(t *testing.T) {
	patterns := []string{"mailgun.org", "awsdns-*.com"}
	if !MatchesPattern("mxa.mailgun.org.", patterns) {
		t.Fatal("expected provider subdomain to match")
	}
	if !MatchesPattern("ns-123.awsdns-45.com", patterns) {
		t.Fatal("expected explicit provider wildcard to match")
	}
	for _, hostile := range []string{"mailgun.org.attacker.example", "mxa.mailgun.org.evil", "ns1.awsdns-evil.attacker.example"} {
		if MatchesPattern(hostile, patterns) {
			t.Fatalf("unsafe DNS substring matched: %q", hostile)
		}
	}
}
