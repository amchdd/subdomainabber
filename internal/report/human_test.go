package report

import (
	"strings"
	"testing"

	"github.com/amchdd/subdomainabber/internal/classification"
	"github.com/amchdd/subdomainabber/internal/core"
)

func TestHumanDelegationFindingExplainsUnverifiedClaimability(t *testing.T) {
	analysis := &core.HostAnalysis{
		Host: "dev.example.com", Classification: classification.LevelDelegationTakeoverCandidate,
		Delegation: &core.DelegationCandidate{
			Zone: "dev.example.com", ParentZone: "example.com",
			DelegatedNameservers: []string{"ns1.provider.test", "ns2.provider.test"},
			Lame:                 []string{"ns1.provider.test", "ns2.provider.test"},
			Provider:             "Test DNS", Claimability: core.ClaimabilityNotVerified,
		},
		Evidences: []core.Evidence{{Type: "DELEGATION_TAKEOVER_CANDIDATE"}},
	}
	output := Human(analysis, "HIGH")
	for _, expected := range []string{
		"[REVISÃO DE DELEGAÇÃO]",
		"dev.example.com (zona pai: example.com)",
		"2/2 servidores NS únicos",
		"NÃO COMPROVADA",
		"recriação da zona",
		"Confiança da análise: ALTA",
	} {
		if !strings.Contains(output, expected) {
			t.Fatalf("saída não contém %q:\n%s", expected, output)
		}
	}
	for _, unexpected := range []string{"parent:", "Provider:", "Claimability:", "Analysis confidence:"} {
		if strings.Contains(output, unexpected) {
			t.Fatalf("saída contém label em inglês %q:\n%s", unexpected, output)
		}
	}
}

func TestHumanMXDoesNotClaimTakeover(t *testing.T) {
	analysis := &core.HostAnalysis{Host: "example.com", Classification: classification.LevelMisconfigured, MXCandidates: []core.MXCandidate{{
		Target: "mail.expired.test", DNSStatus: core.DNSStatusNXDomain,
		RegistrableDomain: "expired.test", RegistrationStatus: "NOT_CHECKED", Claimability: core.ClaimabilityNotVerified,
	}}}
	output := Human(analysis, "MEDIUM")
	if !strings.Contains(output, "[MX QUEBRADO]") ||
		!strings.Contains(output, "somente após") ||
		!strings.Contains(output, "NÃO VERIFICADA") ||
		!strings.Contains(output, "NÃO COMPROVADA") ||
		strings.Contains(output, "CONFIRMADO") {
		t.Fatalf("saída MX inesperada:\n%s", output)
	}
}

func TestHumanConsolidatesFindingsAndKeepsCNAMETakeoverFirst(t *testing.T) {
	analysis := &core.HostAnalysis{
		Host: "assets.example.com", Classification: classification.LevelLikelyTakeoverable,
		DNS: core.DNSRecordSet{
			CNAME: []string{"missing.s3.amazonaws.com"},
			MX:    []string{"mail.expired.test"},
		},
		ProviderCandidates: []core.ProviderCandidate{{ProviderID: "aws_s3", Service: "AWS/S3", CNAME: "missing.s3.amazonaws.com"}},
		MXCandidates: []core.MXCandidate{{
			Target: "mail.expired.test", DNSStatus: core.DNSStatusNXDomain,
			RegistrationStatus: "NOT_CHECKED", Claimability: core.ClaimabilityNotVerified,
		}},
		Evidences: []core.Evidence{
			{Type: "CNAME_PROVIDER_MATCH", Source: "AWS/S3"},
			{Type: "HTTP_BODY_MATCH", Source: "AWS/S3", Metadata: map[string]string{"matched_fingerprint": "NoSuchBucket"}},
			{Type: "MX_BROKEN", Source: "DNS"},
		},
	}
	output := Human(analysis, "HIGH")
	if strings.Count(output, "[") != 1 || !strings.HasPrefix(output, "[TAKEOVER PROVÁVEL]") {
		t.Fatalf("esperava um único bloco com takeover CNAME como achado principal:\n%s", output)
	}
	if !strings.Contains(output, "Achado relacionado: MX — mail.expired.test (NXDOMAIN)") {
		t.Fatalf("achado MX não foi consolidado no bloco principal:\n%s", output)
	}
	if !strings.Contains(output, "Fonte: linha de base") {
		t.Fatalf("fonte da linha de base não foi traduzida:\n%s", output)
	}
}

func TestHumanConsolidatesGenericFindings(t *testing.T) {
	analysis := &core.HostAnalysis{
		Host: "app.example.com", Classification: classification.LevelMisconfigured,
		Evidences: []core.Evidence{
			{Type: "DNSSEC_BOGUS", Source: "DNSSEC", Description: "DNSSEC inválido"},
			{Type: "HTTPS_DOWNGRADE_REDIRECT", Source: "https", Description: "downgrade", Metadata: map[string]string{"location": "http://app.example.com"}},
		},
	}
	output := Human(analysis, "HIGH")
	if strings.Count(output, "[") != 1 || !strings.Contains(output, "DNSSEC_BOGUS") || !strings.Contains(output, "Achado relacionado: HTTP —") {
		t.Fatalf("achados genéricos não foram consolidados:\n%s", output)
	}
}

func TestHumanUsesPortugueseAndOptionalANSI(t *testing.T) {
	analysis := &core.HostAnalysis{
		Host: "dev.example.com", Classification: classification.LevelDelegationBroken,
		Delegation: &core.DelegationCandidate{
			Zone: "dev.example.com", ParentZone: "example.com",
			DelegatedNameservers: []string{"ns1.test"}, Lame: []string{"ns1.test"},
			Claimability: core.ClaimabilityNotVerified,
		},
		Evidences: []core.Evidence{{Type: "DELEGATION_BROKEN"}},
	}
	plain := HumanWithOptions(analysis, "HIGH", Options{})
	for _, expected := range []string{"DELEGAÇÃO QUEBRADA", "Vetor", "Confiança da análise", "Próximo passo"} {
		if !strings.Contains(plain, expected) {
			t.Fatalf("saída em português não contém %q:\n%s", expected, plain)
		}
	}
	if strings.Contains(plain, "\x1b[") {
		t.Fatalf("saída sem cores contém ANSI: %q", plain)
	}
	colored := HumanWithOptions(analysis, "HIGH", Options{Color: true})
	if !strings.Contains(colored, "\x1b[") {
		t.Fatalf("saída colorida não contém ANSI: %q", colored)
	}
}

func TestHumanDoesNotBorrowCloudProviderForCNAME(t *testing.T) {
	analysis := &core.HostAnalysis{
		Host: "assets.example.com", Classification: classification.LevelOrphaned,
		DNS: core.DNSRecordSet{CNAME: []string{"missing.vendor.test"}},
		ProviderCandidates: []core.ProviderCandidate{
			{ProviderID: "cloudflare", Service: "Cloudflare", Vector: "A", Resource: "192.0.2.10"},
		},
		Evidences: []core.Evidence{{Type: "CNAME_DANGLING"}},
	}
	output := Human(analysis, "HIGH")
	if strings.Contains(output, "Provedor: Cloudflare") {
		t.Fatalf("CNAME herdou provedor de outro vetor:\n%s", output)
	}
}

func TestHumanFallbackShowsCausalHTTPMisconfiguration(t *testing.T) {
	analysis := &core.HostAnalysis{
		Host: "app.example.com", Classification: classification.LevelMisconfigured,
		Evidences: []core.Evidence{{
			Type: "HTTP_HSTS_MISSING", Source: "HttpSecurity",
			Description: "Strict-Transport-Security header is missing.",
		}},
	}
	output := HumanWithOptions(analysis, "HIGH", Options{})
	for _, expected := range []string{
		"Vetor: HTTP",
		"Evidência principal",
		"HTTP_HSTS_MISSING",
		"cabeçalho Strict-Transport-Security ausente",
		"Confiança da classificação: ALTA",
	} {
		if !strings.Contains(output, expected) {
			t.Fatalf("fallback não contém %q:\n%s", expected, output)
		}
	}
	if strings.Contains(output, "header is missing") {
		t.Fatalf("fallback vazou descrição humana em inglês:\n%s", output)
	}
}

func TestHumanSuppressesDuplicateDelegationWithoutFallbackLeak(t *testing.T) {
	analysis := &core.HostAnalysis{
		Host:           "api.dev.example.com",
		Classification: classification.LevelDelegationTakeoverCandidate,
		Delegation: &core.DelegationCandidate{
			Zone: "dev.example.com", ParentZone: "example.com",
		},
		Evidences: []core.Evidence{{Type: "DELEGATION_TAKEOVER_CANDIDATE"}},
	}
	if output := HumanWithOptions(analysis, "HIGH", Options{SuppressDelegation: true}); output != "" {
		t.Fatalf("delegação suprimida vazou pelo fallback: %q", output)
	}
}

func TestHumanPreservesTechnicalEvidenceIdentifiers(t *testing.T) {
	analysis := &core.HostAnalysis{
		Host:           "app.example.com",
		Classification: classification.LevelMisconfigured,
		Evidences: []core.Evidence{{
			Type:        "HTTP_CSP_MISSING",
			Description: "Content-Security-Policy header is missing.",
		}},
	}
	output := Human(analysis, "LOW")
	if !strings.Contains(output, "HTTP_CSP_MISSING") {
		t.Fatalf("ID técnico da evidência foi alterado:\n%s", output)
	}
	if !strings.Contains(output, "Confiança da classificação: BAIXA") {
		t.Fatalf("confiança não foi apresentada em português:\n%s", output)
	}
}

func TestHumanExplainsSuppressedHTTPResult(t *testing.T) {
	analysis := &core.HostAnalysis{
		Host: "sso.example.test", Classification: classification.LevelInsufficientEvidence,
		ResultState: core.ResultSuppressed,
		Decision: &core.Decision{
			State: core.ResultSuppressed, Rule: "EDGE_BLOCKED_NO_EXPOSURE",
			ReasonCodes:           []string{"HTTP_NO_HTTPS_UPGRADE", "HTTP_STATUS_403", "EDGE_RESPONSE"},
			ObservationConfidence: 100, ClassificationConfidence: 95, ImpactConfidence: 0,
		},
		Evidences: []core.Evidence{{Type: "HTTP_EDGE_BLOCK", Source: "INFERENCE", Confidence: 95}},
	}
	output := Human(analysis, "LOW")
	for _, expected := range []string{
		"[SUPRIMIDO]", "borda bloqueada sem exposição", "HTTP sem upgrade para HTTPS",
		"Confiança da observação: 100%", "Confiança da classificação: 95%", "Confiança do impacto: 0%",
		"Impacto confirmado: não", "nenhuma ação sugerida",
	} {
		if !strings.Contains(output, expected) {
			t.Fatalf("saída suprimida não contém %q:\n%s", expected, output)
		}
	}
}
