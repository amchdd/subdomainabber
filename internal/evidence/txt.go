package evidence

import (
	"context"
	"fmt"
	"strings"

	"github.com/amchdd/subdomainabber/internal/core"
	"github.com/amchdd/subdomainabber/pkg/signatures"
)

type txtTokenRule struct {
	provider string
	prefix   string
}

// Estas são observações de tokens de verificação, não provas de tokens obsoletos.
// Confirmar obsolescência exige uma API do provedor ou uma tentativa controlada de vínculo.
var builtinTXTTokenRules = []txtTokenRule{
	{provider: "Google", prefix: "google-site-verification="},
	{provider: "Microsoft 365", prefix: "ms="},
	{provider: "Atlassian", prefix: "atlassian-domain-verification="},
	{provider: "Facebook", prefix: "facebook-domain-verification="},
	{provider: "GlobalSign", prefix: "globalsign-domain-verification="},
}

type TXTCollector struct{ sigs []signatures.Fingerprint }

func NewTXTCollector(sigs []signatures.Fingerprint) *TXTCollector { return &TXTCollector{sigs: sigs} }

func (c *TXTCollector) Collect(_ context.Context, analysis *core.HostAnalysis) error {
	analysis.AddTestedVector("TXT")
	for _, record := range analysis.DNS.TXT {
		lower := strings.ToLower(strings.TrimSpace(record))
		for _, rule := range builtinTXTTokenRules {
			if strings.HasPrefix(lower, rule.prefix) {
				c.addToken(analysis, rule.provider, rule.prefix, record, 100)
			}
		}
		for _, sig := range c.sigs {
			for _, fingerprint := range sig.TXTFingerprints {
				if strings.Contains(lower, strings.ToLower(fingerprint)) {
					confidence := sig.TXTConfidence
					if confidence == 0 {
						confidence = sig.Confidence
					}
					c.addToken(analysis, sig.Service, fingerprint, record, confidence)
				}
			}
		}
	}
	return nil
}

func (c *TXTCollector) addToken(analysis *core.HostAnalysis, provider, prefix, record string, confidence int) {
	for _, existing := range analysis.TXTCandidates {
		if existing.Provider == provider && existing.Record == record {
			return
		}
	}
	analysis.TXTCandidates = append(analysis.TXTCandidates, core.TXTVerificationCandidate{
		Provider: provider, TokenPrefix: prefix, Record: record,
		State: "OBSERVED", Claimability: core.ClaimabilityNotChecked,
	})
	analysis.AddProviderCandidate(core.ProviderCandidate{
		ProviderID: providerID(provider), Service: provider,
		Vector: "TXT", Resource: analysis.Host,
		Metadata: map[string]string{"token_prefix": prefix},
	})
	analysis.AddEvidence(core.Evidence{
		Type: "TXT_VERIFICATION_TOKEN", Source: provider,
		Description: fmt.Sprintf("Token de verificação %s observado; não foi possível determinar se ele ainda é válido", provider),
		Weight:      1, Confidence: confidence,
		Metadata: map[string]string{
			"token_prefix": prefix, "state": "OBSERVED",
			"claimability": string(core.ClaimabilityNotChecked),
		},
	})
}
