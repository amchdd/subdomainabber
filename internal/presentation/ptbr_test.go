package presentation

import (
	"testing"

	"github.com/amchdd/subdomainabber/internal/classification"
	"github.com/amchdd/subdomainabber/internal/verify"
)

func TestStructuredValuesArePresentedInPortuguese(t *testing.T) {
	tests := map[string]string{
		Classification(classification.LevelHealthy):            "SAUDÁVEL",
		Classification(classification.LevelLikelyTakeoverable): "TAKEOVER PROVÁVEL",
		StateChange(verify.Discovered):                         "DESCOBERTO",
		Severity("critical"):                                   "CRÍTICA",
		Confidence("medium"):                                   "MÉDIA",
		Value("NOT_VERIFIED"):                                  "NÃO COMPROVADA",
		Value("PROVIDER_OWNED"):                                "PERTENCE AO PROVEDOR",
		Value("REPRODUCIBLE_DIFFERENTIAL"):                     "DIFERENCIAL REPRODUZÍVEL",
		Value("NXDOMAIN"):                                      "NXDOMAIN",
	}
	for actual, expected := range tests {
		if actual != expected {
			t.Fatalf("valor apresentado = %q; esperado %q", actual, expected)
		}
	}
}
