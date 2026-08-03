package evidence

import (
	"crypto/sha256"
	"fmt"
	"net/http"
	"strings"
	"unicode"

	"github.com/amchdd/subdomainabber/internal/core"
	"github.com/amchdd/subdomainabber/pkg/signatures"
)

const minimumTakeoverFingerprintSpecificity = 4

var genericHTTPFingerprints = map[string]struct{}{
	"not found":      {},
	"404 not found":  {},
	"page not found": {},
	"site not found": {},
}

func fingerprintRule(signature *signatures.Fingerprint) core.HTTPFingerprintRule {
	providerID := providerID(signature.Service)
	digest := sha256.Sum256([]byte(providerID + "\x00" + strings.Join(signature.CNames, "\x00") + "\x00" + signature.Fingerprint))
	rule := core.HTTPFingerprintRule{
		RuleID: fmt.Sprintf("%s-http-%x", providerID, digest[:6]), ProviderID: providerID,
		CNAMEPatterns: append([]string(nil), signature.CNames...), BodyContains: []string{signature.Fingerprint},
		RequiredHeaders: cloneStringMap(signature.Headers), Claimability: "review_only",
		MinimumSpecificity: minimumTakeoverFingerprintSpecificity,
	}
	if signature.HTTPStatus != nil {
		rule.StatusAnyOf = []int{*signature.HTTPStatus}
	}
	// Vulnerable é o campo estruturado de elegibilidade. Status é apenas texto
	// descritivo do corpus e pode ser localizado sem alterar a classificação.
	if signature.Vulnerable {
		rule.Claimability = "potentially_claimable"
	}
	return rule
}

func eligibleTakeoverFingerprint(signature *signatures.Fingerprint, candidate core.ProviderCandidate, observation core.RawHTTPObservation) (core.HTTPFingerprintRule, bool) {
	rule := fingerprintRule(signature)
	if !observation.Complete || observation.TransportError != "" || observation.ParseError != "" || observation.TimedOut || observation.ConnectionReset {
		return rule, false
	}
	if rule.RuleID == "" || candidate.ProviderID == "" || rule.ProviderID != candidate.ProviderID || rule.Claimability != "potentially_claimable" {
		return rule, false
	}
	if !candidateMatchesSignature(candidate, signature) || isGenericHTTPFingerprint(signature.Fingerprint) || fingerprintSpecificity(signature.Fingerprint) < rule.MinimumSpecificity {
		return rule, false
	}
	if len(rule.StatusAnyOf) > 0 && !containsStatus(rule.StatusAnyOf, observation.StatusCode) {
		return rule, false
	}
	for name, required := range rule.RequiredHeaders {
		values := observation.Headers[http.CanonicalHeaderKey(name)]
		matched := false
		for _, value := range values {
			if strings.Contains(strings.ToLower(value), strings.ToLower(required)) {
				matched = true
				break
			}
		}
		if !matched {
			return rule, false
		}
	}
	return rule, signatures.MatchesFingerprint(string(observation.Body), signature)
}

func isGenericHTTPFingerprint(value string) bool {
	normalized := strings.Join(strings.FieldsFunc(strings.ToLower(value), func(r rune) bool { return !unicode.IsLetter(r) && !unicode.IsDigit(r) }), " ")
	_, generic := genericHTTPFingerprints[normalized]
	if generic {
		return true
	}
	allowed := map[string]struct{}{"404": {}, "error": {}, "page": {}, "site": {}, "not": {}, "found": {}}
	fields := strings.Fields(normalized)
	if len(fields) == 0 {
		return true
	}
	for _, field := range fields {
		if _, ok := allowed[field]; !ok {
			return false
		}
	}
	return strings.Contains(" "+normalized+" ", " not ") && strings.Contains(" "+normalized+" ", " found ")
}

func fingerprintSpecificity(value string) int {
	fields := strings.FieldsFunc(value, func(r rune) bool { return !unicode.IsLetter(r) && !unicode.IsDigit(r) })
	count := 0
	for _, field := range fields {
		if len(field) >= 3 {
			count++
		}
	}
	return count
}

func containsStatus(statuses []int, status int) bool {
	for _, allowed := range statuses {
		if allowed == status {
			return true
		}
	}
	return false
}
func cloneStringMap(source map[string]string) map[string]string {
	if len(source) == 0 {
		return nil
	}
	cloned := make(map[string]string, len(source))
	for key, value := range source {
		cloned[key] = value
	}
	return cloned
}
