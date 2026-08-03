package domainutil

import (
	"fmt"
	"strings"
)

// NormalizeHostname normaliza um hostname DNS ASCII e rejeita valores
// malformados antes que sejam usados como padrões de provedor.
func NormalizeHostname(value string) (string, error) {
	hostname := strings.ToLower(strings.TrimSpace(value))
	hostname = strings.TrimSuffix(hostname, ".")
	if hostname == "" {
		return "", fmt.Errorf("o hostname está vazio")
	}
	if len(hostname) > 253 {
		return "", fmt.Errorf("o hostname excede 253 caracteres")
	}

	for _, label := range strings.Split(hostname, ".") {
		if label == "" {
			return "", fmt.Errorf("o hostname contém um label vazio")
		}
		if len(label) > 63 {
			return "", fmt.Errorf("o label %q do hostname excede 63 caracteres", label)
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return "", fmt.Errorf("o label %q do hostname começa ou termina com hífen", label)
		}
		for _, char := range label {
			if (char < 'a' || char > 'z') && (char < '0' || char > '9') && char != '-' {
				return "", fmt.Errorf("o label %q do hostname contém caractere inválido", label)
			}
		}
	}

	return hostname, nil
}

// NormalizeDNSPattern normaliza um padrão exato de hostname ou um padrão
// curinga explícito de um único label.
func NormalizeDNSPattern(value string) (string, error) {
	pattern := strings.ToLower(strings.TrimSpace(value))
	if strings.HasPrefix(pattern, "*.") {
		suffix, err := NormalizeHostname(strings.TrimPrefix(pattern, "*."))
		if err != nil {
			return "", err
		}
		return "*." + suffix, nil
	}
	return NormalizeHostname(pattern)
}

// MatchDNSName compara um hostname com um domínio exato de provedor, preservando
// os limites dos labels DNS. Um padrão curinga corresponde a exatamente um
// label e deve ser escrito explicitamente como *.example.com.
func MatchDNSName(target, pattern string) bool {
	normalizedTarget, err := NormalizeHostname(target)
	if err != nil {
		return false
	}

	normalizedPattern, err := NormalizeDNSPattern(pattern)
	if err != nil {
		return false
	}
	wildcard := strings.HasPrefix(normalizedPattern, "*.")

	if wildcard {
		normalizedPattern = strings.TrimPrefix(normalizedPattern, "*.")
		if !strings.HasSuffix(normalizedTarget, "."+normalizedPattern) {
			return false
		}
		return len(strings.Split(normalizedTarget, ".")) == len(strings.Split(normalizedPattern, "."))+1
	}

	return normalizedTarget == normalizedPattern || strings.HasSuffix(normalizedTarget, "."+normalizedPattern)
}

// MatchDNSProviderPattern compara sufixos DNS pertencentes ao provedor e permite
// um único '*' dentro de um label (por exemplo, awsdns-*.com). Todos os outros
// labels e o sufixo do domínio permanecem ancorados; assim, nomes controlados
// por um atacante que contenham um fragmento do provedor não correspondem.
func MatchDNSProviderPattern(target, pattern string) bool {
	normalizedTarget, err := NormalizeHostname(target)
	if err != nil {
		return false
	}
	pattern, err = NormalizeDNSProviderPattern(pattern)
	if err != nil {
		return false
	}
	if !strings.Contains(pattern, "*") {
		return MatchDNSName(normalizedTarget, pattern)
	}
	targetLabels := strings.Split(normalizedTarget, ".")
	patternLabels := strings.Split(pattern, ".")
	if len(targetLabels) < len(patternLabels) {
		return false
	}
	targetLabels = targetLabels[len(targetLabels)-len(patternLabels):]
	for index, patternLabel := range patternLabels {
		if strings.Count(patternLabel, "*") > 1 {
			return false
		}
		if !strings.Contains(patternLabel, "*") {
			if targetLabels[index] != patternLabel {
				return false
			}
			continue
		}
		parts := strings.SplitN(patternLabel, "*", 2)
		if !strings.HasPrefix(targetLabels[index], parts[0]) || !strings.HasSuffix(targetLabels[index], parts[1]) {
			return false
		}
		middle := strings.TrimSuffix(strings.TrimPrefix(targetLabels[index], parts[0]), parts[1])
		if middle == "" {
			return false
		}
	}
	return true
}

func NormalizeDNSProviderPattern(value string) (string, error) {
	pattern := strings.ToLower(strings.Trim(strings.TrimSpace(value), "."))
	if pattern == "" || strings.Count(pattern, "*") > 1 {
		return "", fmt.Errorf("padrão DNS de provedor inválido")
	}
	if !strings.Contains(pattern, "*") {
		return NormalizeHostname(pattern)
	}
	if strings.Contains(pattern, "..") {
		return "", fmt.Errorf("o padrão DNS de provedor contém um label vazio")
	}
	if _, err := NormalizeHostname(strings.Replace(pattern, "*", "wildcard", 1)); err != nil {
		return "", err
	}
	return pattern, nil
}
