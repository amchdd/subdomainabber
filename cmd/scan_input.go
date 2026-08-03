package cmd

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/amchdd/subdomainabber/internal/dns"
)

const maxScanInputLine = 1024 * 1024

func stdinHasPipedData(stdin *os.File) bool {
	if stdin == nil {
		return false
	}
	stat, err := stdin.Stat()
	return err == nil && stat.Mode()&os.ModeCharDevice == 0
}

func loadScanDomains(args []string, listPath string, stdin io.Reader, readStdin bool) ([]string, error) {
	var domains []string
	seen := make(map[string]struct{})
	add := func(raw, source string, line int) error {
		domain := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(raw), "."))
		if domain == "" || strings.HasPrefix(domain, "#") {
			return nil
		}
		if !validScanDomain(domain) {
			return fmt.Errorf("alvo inválido em %s:%d: %q", source, line, raw)
		}
		if _, exists := seen[domain]; exists {
			return nil
		}
		seen[domain] = struct{}{}
		domains = append(domains, domain)
		return nil
	}

	for index, value := range args {
		if err := add(value, "argumento", index+1); err != nil {
			return nil, err
		}
	}

	if strings.TrimSpace(listPath) != "" {
		file, err := os.Open(listPath)
		if err != nil {
			return nil, fmt.Errorf("abrindo lista %q: %w", listPath, err)
		}
		defer file.Close()
		if err := scanDomainLines(file, listPath, add); err != nil {
			return nil, err
		}
	}

	if readStdin && stdin != nil {
		if err := scanDomainLines(stdin, "stdin", add); err != nil {
			return nil, err
		}
	}

	if len(domains) == 0 {
		return nil, fmt.Errorf("nenhum alvo fornecido; use argumentos, --list ou a entrada padrão (stdin)")
	}
	return domains, nil
}

func scanDomainLines(reader io.Reader, source string, add func(string, string, int) error) error {
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 0, 64*1024), maxScanInputLine)
	line := 0
	for scanner.Scan() {
		line++
		if err := add(scanner.Text(), source, line); err != nil {
			return err
		}
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("lendo %s: %w", source, err)
	}
	return nil
}

func validScanDomain(domain string) bool {
	if len(domain) == 0 || len(domain) > 253 || strings.ContainsAny(domain, "/\\:@?#%") {
		return false
	}
	labels := strings.Split(domain, ".")
	if len(labels) < 2 {
		return false
	}
	tldHasLetter := false
	for labelIndex, label := range labels {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, char := range label {
			isLetter := char >= 'a' && char <= 'z'
			isDigit := char >= '0' && char <= '9'
			if !isLetter && !isDigit && char != '-' && char != '_' {
				return false
			}
			if labelIndex == len(labels)-1 {
				if char == '_' {
					return false
				}
				if isLetter {
					tldHasLetter = true
				}
			}
		}
	}
	return tldHasLetter
}

func aggressiveClaimTargets(enabled, confirmed bool, rawAllowlist string, scanDomains []string) ([]string, error) {
	rawAllowlist = strings.TrimSpace(rawAllowlist)
	if !enabled {
		if confirmed || rawAllowlist != "" {
			return nil, fmt.Errorf("as flags de reivindicação automática exigem --aggressive")
		}
		return nil, nil
	}
	if !confirmed {
		return nil, fmt.Errorf("--aggressive exige --aggressive-confirm-auto-claim")
	}
	if rawAllowlist == "" {
		return nil, fmt.Errorf("--aggressive exige --aggressive-allowlist")
	}

	content := rawAllowlist
	if data, err := os.ReadFile(rawAllowlist); err == nil {
		content = string(data)
	}
	scanned := make(map[string]struct{}, len(scanDomains))
	for _, domain := range scanDomains {
		scanned[domain] = struct{}{}
	}
	seen := make(map[string]struct{})
	var allowed []string
	for _, item := range strings.FieldsFunc(content, func(char rune) bool { return char == ',' || char == '\n' || char == '\r' }) {
		host := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(item), "."))
		if host == "" || strings.HasPrefix(host, "#") {
			continue
		}
		if !validScanDomain(host) {
			return nil, fmt.Errorf("host inválido na lista permitida agressiva: %q", item)
		}
		if _, included := scanned[host]; !included {
			return nil, fmt.Errorf("o host %q da lista permitida agressiva não está entre os alvos da varredura", host)
		}
		if _, exists := seen[host]; !exists {
			seen[host] = struct{}{}
			allowed = append(allowed, host)
		}
	}
	if len(allowed) == 0 {
		return nil, fmt.Errorf("a lista permitida agressiva está vazia")
	}
	return allowed, nil
}

func authorizedWhoisPivotTargets(enabled, confirmed bool, rawAllowlist string) ([]string, error) {
	rawAllowlist = strings.TrimSpace(rawAllowlist)
	if !enabled {
		if confirmed || rawAllowlist != "" {
			return nil, fmt.Errorf("as opções de autorização do pivotamento exigem --whois-pivot")
		}
		return nil, nil
	}
	if !confirmed {
		return nil, fmt.Errorf("--whois-pivot exige --whois-pivot-confirm")
	}
	if rawAllowlist == "" {
		return nil, fmt.Errorf("--whois-pivot exige --whois-pivot-allowlist")
	}

	content := rawAllowlist
	if data, err := os.ReadFile(rawAllowlist); err == nil {
		content = string(data)
	}
	seen := make(map[string]struct{})
	var targets []string
	for _, item := range strings.FieldsFunc(content, func(char rune) bool { return char == ',' || char == '\n' || char == '\r' }) {
		domain := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(item), "."))
		if domain == "" || strings.HasPrefix(domain, "#") {
			continue
		}
		if !validScanDomain(domain) || dns.ExtractRootDomain(domain) != domain {
			return nil, fmt.Errorf("domínio registrável inválido na lista permitida do pivotamento: %q", item)
		}
		if _, exists := seen[domain]; !exists {
			seen[domain] = struct{}{}
			targets = append(targets, domain)
		}
	}
	if len(targets) == 0 {
		return nil, fmt.Errorf("a lista permitida do pivotamento WHOIS está vazia")
	}
	return targets, nil
}

func selectDiscoveredWhoisTargets(discovered, allowed []string) []string {
	allowedSet := make(map[string]struct{}, len(allowed))
	for _, domain := range allowed {
		allowedSet[domain] = struct{}{}
	}
	var selected []string
	seen := make(map[string]struct{})
	for _, domain := range discovered {
		domain = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(domain), "."))
		if _, ok := allowedSet[domain]; !ok {
			continue
		}
		if _, exists := seen[domain]; !exists {
			seen[domain] = struct{}{}
			selected = append(selected, domain)
		}
	}
	return selected
}

func appendUniqueDomains(existing, additional []string) []string {
	seen := make(map[string]struct{}, len(existing)+len(additional))
	for _, domain := range existing {
		seen[domain] = struct{}{}
	}
	for _, domain := range additional {
		if _, exists := seen[domain]; exists {
			continue
		}
		seen[domain] = struct{}{}
		existing = append(existing, domain)
	}
	return existing
}
