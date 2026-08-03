package discovery

import (
	"fmt"
	"strings"
)

// DefaultAlterationWords reúne prefixos e sufixos comuns de ambientes.
var DefaultAlterationWords = []string{
	"dev", "api", "staging", "test", "prod", "v1", "v2", "admin", "app", "web", "internal",
}

// GenerateMutations cria subdomínios permutados a partir de um subdomínio base.
func GenerateMutations(baseDomain, subDomain string, words []string) []string {
	if words == nil {
		words = DefaultAlterationWords
	}

	// Remove o domínio raiz de subDomain, quando presente.
	sub := strings.TrimSuffix(subDomain, "."+baseDomain)
	if sub == baseDomain || sub == "" {
		return nil
	}

	parts := strings.Split(sub, ".")
	var mutations []string

	for _, word := range words {
		// Acrescenta o termo com hífen.
		mutations = append(mutations, fmt.Sprintf("%s-%s.%s", sub, word, baseDomain))
		// Antecede o termo com hífen.
		mutations = append(mutations, fmt.Sprintf("%s-%s.%s", word, sub, baseDomain))

		// Se o subdomínio tiver partes, percorre cada uma delas
		// (ex.: api.dev -> test.api.dev, api.test.dev).
		for i := 0; i <= len(parts); i++ {
			newParts := make([]string, 0, len(parts)+1)
			newParts = append(newParts, parts[:i]...)
			newParts = append(newParts, word)
			newParts = append(newParts, parts[i:]...)
			mutations = append(mutations, fmt.Sprintf("%s.%s", strings.Join(newParts, "."), baseDomain))
		}
	}

	return mutations
}
