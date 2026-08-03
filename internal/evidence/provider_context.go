package evidence

import (
	"strings"
	"unicode"

	"github.com/amchdd/subdomainabber/internal/domainutil"
)

func matchingCNAME(targets, patterns []string) (string, bool) {
	for _, target := range targets {
		for _, pattern := range patterns {
			if domainutil.MatchDNSName(target, pattern) {
				normalized, err := domainutil.NormalizeHostname(target)
				if err != nil {
					return "", false
				}
				return normalized, true
			}
		}
	}
	return "", false
}

func providerID(service string) string {
	var builder strings.Builder
	lastUnderscore := false
	for _, char := range strings.ToLower(strings.TrimSpace(service)) {
		if unicode.IsLetter(char) || unicode.IsDigit(char) {
			builder.WriteRune(char)
			lastUnderscore = false
			continue
		}
		if builder.Len() > 0 && !lastUnderscore {
			builder.WriteByte('_')
			lastUnderscore = true
		}
	}
	return strings.Trim(builder.String(), "_")
}
