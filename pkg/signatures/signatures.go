package signatures

import (
	"bytes"
	"crypto/sha256"
	"embed"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/amchdd/subdomainabber/internal/domainutil"
)

// Digest retorna uma identidade estável do catálogo efetivamente carregado.
// Campos compilados em memória não participam do cálculo.
func Digest(fingerprints []Fingerprint) (string, error) {
	data, err := json.Marshal(fingerprints)
	if err != nil {
		return "", fmt.Errorf("serializando catálogo de assinaturas: %w", err)
	}
	sum := sha256.Sum256(data)
	return fmt.Sprintf("sha256:%x", sum), nil
}

//go:embed fingerprints.json cdn_signatures.json
var embeddedFS embed.FS

// CDNSignature representa uma regra de detecção de CDN baseada em cabeçalhos HTTP.
type CDNSignature struct {
	Name    string            `json:"name"`
	Headers map[string]string `json:"headers"`
}

// Fingerprint representa uma entrada do catálogo de assinaturas.
// O catálogo aceita regras para CNAME, NS, MX, SRV, TXT, SPF e A/AAAA.
type Fingerprint struct {
	ID             string   `json:"id,omitempty"`
	Service        string   `json:"service"`
	CNames         []string `json:"cname"`
	Fingerprint    string   `json:"fingerprint"`
	HTTPStatus     *int     `json:"http_status"`
	NXDomain       bool     `json:"nxdomain"`
	Vulnerable     bool     `json:"vulnerable"`
	Status         string   `json:"status"`
	Discussion     string   `json:"discussion"`
	Documentation  string   `json:"documentation,omitempty"`
	CICDPass       *bool    `json:"cicd_pass,omitempty"`
	IsRegex        bool     `json:"regex,omitempty"`           // Se true, Fingerprint é tratado como regex
	NSFingerprints []string `json:"ns_fingerprints,omitempty"` // Padrões de nameserver para NS takeover
	MXFingerprints []string `json:"mx_fingerprints,omitempty"` // Padrões de MX para MX takeover
	CheckType      string   `json:"check_type,omitempty"`      // "cname", "ns", "mx", "srv", "txt", "spf", "a" ou "both"
	Confidence     int      `json:"confidence,omitempty"`      // Confiança da regra (0-100)
	MXConfidence   int      `json:"mx_confidence,omitempty"`   // Confiança específica para MX (0-100)

	TXTFingerprints []string `json:"txt_fingerprints,omitempty"` // Padrões de validação SaaS/cloud (ex.: google-site-verification)
	TXTConfidence   int      `json:"txt_confidence,omitempty"`   // Confiança específica para TXT (0-100)

	SRVFingerprints []string `json:"srv_fingerprints,omitempty"` // Padrões de SRV (ex.: sip, ldap)
	SRVConfidence   int      `json:"srv_confidence,omitempty"`   // Confiança específica para SRV (0-100)

	TLSFingerprints []string `json:"tls_fingerprints,omitempty"` // Padrões TLS (Issuer ou Subject)
	TLSConfidence   int      `json:"tls_confidence,omitempty"`   // Confiança específica para TLS (0-100)

	ASNFingerprints []string `json:"asn_fingerprints,omitempty"` // Padrões de ASN/Org Cloud
	ASNConfidence   int      `json:"asn_confidence,omitempty"`   // Confiança específica para ASN (0-100)

	// Força de evidência por tipo (ex.: "CNAME": 80, "TLS": 30, "ASN": 10).
	SPFFingerprints   []string       `json:"spf_fingerprints,omitempty"`
	SPFConfidence     int            `json:"spf_confidence,omitempty"`
	SignatureStrength map[string]int `json:"signature_strength,omitempty"`
	ActiveVerifier    string         `json:"active_verifier,omitempty"`
	ProofRequirements []string       `json:"proof_requirements,omitempty"`

	// Opcional: cabeçalhos personalizados caso a validação HTTP exija.
	Headers map[string]string `json:"headers,omitempty"`

	// Regras DSL opcionais.
	Engine *Condition `json:"engine,omitempty"`

	// CompiledRegex é a expressão regular compilada a partir de Fingerprint quando IsRegex=true.
	// Populado em tempo de carregamento, não serializado.
	CompiledRegex *regexp.Regexp `json:"-"`
}

// LoadEmbedded lê as assinaturas embutidas via go:embed.
func LoadEmbedded() ([]Fingerprint, error) {
	data, err := embeddedFS.ReadFile("fingerprints.json")
	if err != nil {
		return nil, fmt.Errorf("lendo arquivo embutido: %w", err)
	}
	return decode(bytes.NewReader(data), false)
}

// LoadFromFile interpreta assinaturas de um arquivo JSON local.
// Apenas entradas marcadas como vulneráveis são retornadas.
func LoadFromFile(path string) ([]Fingerprint, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("abrindo arquivo de assinaturas local: %w", err)
	}
	defer f.Close()

	return decode(f, true)
}

// LoadFromDir carrega e mescla assinaturas de todos os arquivos *.json em um diretório.
// Cada arquivo deve seguir o mesmo formato do can-i-take-over-xyz.
// Entradas idênticas são combinadas por uma identidade estável que preserva o
// vetor e todos os padrões. Um campo id explícito pode ser usado por catálogos
// externos para atualizar a mesma regra sem apagar mecanismos complementares.
func LoadFromDir(dir string) ([]Fingerprint, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("lendo diretório de assinaturas %q: %w", dir, err)
	}

	var all []Fingerprint
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(strings.ToLower(entry.Name()), ".json") {
			continue
		}

		path := filepath.Join(dir, entry.Name())
		fps, err := LoadFromFile(path)
		if err != nil {
			return nil, fmt.Errorf("carregando arquivo de assinaturas %q: %w", entry.Name(), err)
		}
		all = append(all, fps...)
	}

	if len(all) == 0 {
		return nil, fmt.Errorf("nenhuma assinatura vulnerável encontrada no diretório %q", dir)
	}

	return dedup(all), nil
}

// MergeSignatures combina múltiplas listas sem reduzir uma regra multivetor ao
// primeiro CNAME ou ao primeiro padrão de NS.
func MergeSignatures(sources ...[]Fingerprint) []Fingerprint {
	var combined []Fingerprint
	for _, src := range sources {
		combined = append(combined, src...)
	}
	return dedup(combined)
}

// BuiltinNSSignatures retorna assinaturas de NS incorporadas ao executável.
// Elas cobrem provedores DNS conhecidos e não dependem de arquivos externos.
func BuiltinNSSignatures() []Fingerprint {
	return []Fingerprint{
		{
			Service:        "AWS Route53",
			NSFingerprints: []string{"awsdns-*.com", "awsdns-*.net", "awsdns-*.org", "awsdns-*.co.uk"},
			CheckType:      "ns",
			Vulnerable:     true,
			NXDomain:       false,
			Fingerprint:    "REFUSED/SERVFAIL",
			Status:         "Verificar manualmente",
			Discussion:     "https://github.com/EdOverflow/can-i-take-over-xyz/issues/123",
		},
		{
			Service:        "Azure DNS",
			NSFingerprints: []string{"azure-dns.com", "azure-dns.net", "azure-dns.org", "azure-dns.info"},
			CheckType:      "ns",
			Vulnerable:     true,
			NXDomain:       false,
			Fingerprint:    "REFUSED/SERVFAIL",
			Status:         "Verificar manualmente",
			Discussion:     "https://github.com/EdOverflow/can-i-take-over-xyz/issues/175",
		},
		{
			Service:        "DigitalOcean DNS",
			NSFingerprints: []string{"digitalocean.com"},
			CheckType:      "ns",
			Vulnerable:     true,
			NXDomain:       false,
			Fingerprint:    "REFUSED/SERVFAIL",
			Status:         "Verificar manualmente",
			Discussion:     "https://github.com/EdOverflow/can-i-take-over-xyz",
		},
		{
			Service:        "Google Cloud DNS",
			NSFingerprints: []string{"googledomains.com"},
			CheckType:      "ns",
			Vulnerable:     true,
			NXDomain:       false,
			Fingerprint:    "REFUSED/SERVFAIL",
			Status:         "Verificar manualmente",
			Discussion:     "https://github.com/EdOverflow/can-i-take-over-xyz",
		},
	}
}

// decode lê e filtra os fingerprints do JSON, retornando apenas entradas vulneráveis.
// Também compila expressões regulares para entradas com IsRegex=true e
// define o CheckType padrão como "cname" se não especificado.
func decode(r io.Reader, strict bool) ([]Fingerprint, error) {
	var all []Fingerprint
	dec := json.NewDecoder(r)

	t, err := dec.Token()
	if err != nil {
		return nil, fmt.Errorf("esperado início de array no JSON de assinaturas: %w", err)
	}
	if delim, ok := t.(json.Delim); !ok || delim != '[' {
		return nil, fmt.Errorf("esperado array JSON, obtido %T", t)
	}

	entryIndex := 0
	for dec.More() {
		var fp Fingerprint
		if err := dec.Decode(&fp); err != nil {
			if strict {
				return nil, fmt.Errorf("interpretando a assinatura %d: %w", entryIndex+1, err)
			}
			fmt.Fprintf(os.Stderr, "[AVISO] ignorando assinatura malformada: %v\n", err)
			entryIndex++
			continue
		}
		all = append(all, fp)
		entryIndex++
	}

	_, _ = dec.Token() // Lê o ']' de fechamento.

	vulnerable := make([]Fingerprint, 0, len(all)/2)
	discardedInvalid := 0
	for _, fp := range all {
		if !fp.Vulnerable {
			continue
		}
		fp.Service = strings.TrimSpace(fp.Service)
		fp.ID = strings.TrimSpace(fp.ID)
		fp.CheckType = strings.ToLower(strings.TrimSpace(fp.CheckType))

		var validationErr error
		if fp.Service == "" {
			validationErr = fmt.Errorf("o nome do serviço está vazio")
		}
		if validationErr == nil {
			fp.CNames, validationErr = sanitizeCNAMEPatterns(fp.CNames)
		}
		if validationErr == nil {
			fp.NSFingerprints, validationErr = sanitizeProviderPatterns(fp.NSFingerprints)
		}
		if validationErr == nil {
			fp.MXFingerprints, validationErr = sanitizeProviderPatterns(fp.MXFingerprints)
		}
		if validationErr == nil {
			fp.SRVFingerprints, validationErr = sanitizeProviderPatterns(fp.SRVFingerprints)
		}
		if validationErr == nil {
			fp.SPFFingerprints, validationErr = sanitizeProviderPatterns(fp.SPFFingerprints)
		}
		fp.TXTFingerprints = sanitizeTextPatterns(fp.TXTFingerprints)
		fp.TLSFingerprints = sanitizeTextPatterns(fp.TLSFingerprints)
		fp.ASNFingerprints = sanitizeTextPatterns(fp.ASNFingerprints)

		if fp.CheckType == "" {
			fp.CheckType = inferredCheckType(fp)
		}
		if validationErr == nil {
			validationErr = validateFingerprintSchema(fp)
		}
		if validationErr == nil && fp.IsRegex {
			if strings.TrimSpace(fp.Fingerprint) == "" {
				validationErr = fmt.Errorf("regex ativada sem fingerprint")
			} else if fp.CompiledRegex, validationErr = regexp.Compile("(?i)" + fp.Fingerprint); validationErr != nil {
				validationErr = fmt.Errorf("regex HTTP inválida: %w", validationErr)
			}
		}
		if validationErr == nil && fp.Engine != nil {
			validationErr = compileCondition(fp.Engine)
		}
		if validationErr != nil {
			if strict {
				return nil, fmt.Errorf("assinatura do serviço %q inválida: %w", fp.Service, validationErr)
			}
			discardedInvalid++
			continue
		}

		vulnerable = append(vulnerable, fp)
	}
	if discardedInvalid > 0 {
		fmt.Fprintf(os.Stderr, "[AVISO] %d assinaturas inválidas foram descartadas do catálogo embutido\n", discardedInvalid)
	}

	if len(vulnerable) == 0 {
		return nil, fmt.Errorf("nenhuma assinatura vulnerável encontrada no conjunto de dados")
	}

	return vulnerable, nil
}

func sanitizeCNAMEPatterns(patterns []string) ([]string, error) {
	normalized := make([]string, 0, len(patterns))
	seen := make(map[string]struct{}, len(patterns))
	for _, pattern := range patterns {
		if strings.TrimSpace(pattern) == "" {
			continue
		}
		hostname, err := domainutil.NormalizeDNSPattern(pattern)
		if err != nil {
			return nil, err
		}
		if _, exists := seen[hostname]; exists {
			continue
		}
		seen[hostname] = struct{}{}
		normalized = append(normalized, hostname)
	}
	return normalized, nil
}

func sanitizeProviderPatterns(patterns []string) ([]string, error) {
	normalized := make([]string, 0, len(patterns))
	seen := make(map[string]struct{}, len(patterns))
	for _, pattern := range patterns {
		if strings.TrimSpace(pattern) == "" {
			continue
		}
		value, err := domainutil.NormalizeDNSProviderPattern(pattern)
		if err != nil {
			return nil, fmt.Errorf("padrão DNS de provedor %q: %w", pattern, err)
		}
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		normalized = append(normalized, value)
	}
	return normalized, nil
}

func sanitizeTextPatterns(patterns []string) []string {
	normalized := make([]string, 0, len(patterns))
	seen := make(map[string]struct{}, len(patterns))
	for _, pattern := range patterns {
		pattern = strings.TrimSpace(pattern)
		if pattern == "" {
			continue
		}
		key := strings.ToLower(pattern)
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		normalized = append(normalized, pattern)
	}
	return normalized
}

func inferredCheckType(fingerprint Fingerprint) string {
	switch {
	case len(fingerprint.NSFingerprints) > 0:
		return "ns"
	case len(fingerprint.MXFingerprints) > 0:
		return "mx"
	case len(fingerprint.SRVFingerprints) > 0:
		return "srv"
	case len(fingerprint.TXTFingerprints) > 0:
		return "txt"
	case len(fingerprint.SPFFingerprints) > 0:
		return "spf"
	case len(fingerprint.ASNFingerprints) > 0:
		return "a"
	case len(fingerprint.TLSFingerprints) > 0:
		return "tls"
	default:
		return "cname"
	}
}

func validateFingerprintSchema(fingerprint Fingerprint) error {
	allowedCheckTypes := map[string]bool{
		"cname": true, "both": true, "ns": true, "mx": true, "srv": true,
		"txt": true, "spf": true, "a": true, "aaaa": true, "tls": true,
	}
	if !allowedCheckTypes[fingerprint.CheckType] {
		return fmt.Errorf("check_type não suportado %q", fingerprint.CheckType)
	}
	for field, value := range map[string]int{
		"confidence": fingerprint.Confidence, "mx_confidence": fingerprint.MXConfidence,
		"txt_confidence": fingerprint.TXTConfidence, "srv_confidence": fingerprint.SRVConfidence,
		"tls_confidence": fingerprint.TLSConfidence, "asn_confidence": fingerprint.ASNConfidence,
		"spf_confidence": fingerprint.SPFConfidence,
	} {
		if value < 0 || value > 100 {
			return fmt.Errorf("%s deve estar entre 0 e 100", field)
		}
	}
	for vector, strength := range fingerprint.SignatureStrength {
		if strength < 0 || strength > 100 {
			return fmt.Errorf("signature_strength[%q] deve estar entre 0 e 100", vector)
		}
	}
	if fingerprint.HTTPStatus != nil && (*fingerprint.HTTPStatus < 100 || *fingerprint.HTTPStatus > 599) {
		return fmt.Errorf("http_status deve estar entre 100 e 599")
	}
	if !hasDetectionMechanism(fingerprint) {
		return fmt.Errorf("nenhum mecanismo de detecção foi configurado")
	}
	switch fingerprint.CheckType {
	case "cname", "both":
		if len(fingerprint.CNames) == 0 {
			return fmt.Errorf("check_type=%q exige ao menos um CNAME válido", fingerprint.CheckType)
		}
	case "ns":
		if len(fingerprint.NSFingerprints) == 0 {
			return fmt.Errorf("check_type=ns exige ns_fingerprints")
		}
	case "mx":
		if len(fingerprint.MXFingerprints) == 0 {
			return fmt.Errorf("check_type=mx exige mx_fingerprints")
		}
	case "srv":
		if len(fingerprint.SRVFingerprints) == 0 {
			return fmt.Errorf("check_type=srv exige srv_fingerprints")
		}
	case "txt":
		if len(fingerprint.TXTFingerprints) == 0 {
			return fmt.Errorf("check_type=txt exige txt_fingerprints")
		}
	case "spf":
		if len(fingerprint.SPFFingerprints) == 0 {
			return fmt.Errorf("check_type=spf exige spf_fingerprints")
		}
	case "a", "aaaa":
		if len(fingerprint.ASNFingerprints) == 0 && strings.TrimSpace(fingerprint.Fingerprint) == "" && fingerprint.Engine == nil {
			return fmt.Errorf("check_type=%s exige asn_fingerprints, fingerprint ou engine", fingerprint.CheckType)
		}
	case "tls":
		if len(fingerprint.TLSFingerprints) == 0 {
			return fmt.Errorf("check_type=tls exige tls_fingerprints")
		}
	}
	return nil
}

func hasDetectionMechanism(fingerprint Fingerprint) bool {
	return len(fingerprint.CNames) > 0 || len(fingerprint.NSFingerprints) > 0 ||
		len(fingerprint.MXFingerprints) > 0 || len(fingerprint.SRVFingerprints) > 0 ||
		len(fingerprint.TXTFingerprints) > 0 || len(fingerprint.TLSFingerprints) > 0 ||
		len(fingerprint.ASNFingerprints) > 0 || len(fingerprint.SPFFingerprints) > 0 ||
		strings.TrimSpace(fingerprint.Fingerprint) != "" || fingerprint.Engine != nil
}

// dedup combina apenas regras com a mesma identidade completa. Campos e vetores
// existentes não são apagados por uma entrada parcial posterior.
func dedup(fps []Fingerprint) []Fingerprint {
	seen := make(map[string]int, len(fps)) // chave -> index no resultado
	result := make([]Fingerprint, 0, len(fps))

	for _, fp := range fps {
		key := buildDedupKey(fp)

		if idx, exists := seen[key]; exists {
			result[idx] = mergeFingerprint(result[idx], fp)
		} else {
			seen[key] = len(result)
			result = append(result, fp)
		}
	}

	return result
}

// buildDedupKey gera uma identidade imutável por vetor. Um id explícito tem
// precedência; sem ele, todos os padrões e o mecanismo HTTP compõem a chave.
func buildDedupKey(fp Fingerprint) string {
	if id := strings.ToLower(strings.TrimSpace(fp.ID)); id != "" {
		return "id|" + id
	}
	httpStatus := ""
	if fp.HTTPStatus != nil {
		httpStatus = strconv.Itoa(*fp.HTTPStatus)
	}
	fingerprint := fp.Fingerprint
	if !fp.IsRegex {
		fingerprint = strings.ToLower(fingerprint)
	}
	engine, _ := json.Marshal(fp.Engine)
	return strings.Join([]string{
		strings.ToLower(fp.Service), strings.ToLower(fp.CheckType), canonicalStrings(fp.CNames),
		canonicalStrings(fp.NSFingerprints), canonicalStrings(fp.MXFingerprints),
		canonicalStrings(fp.SRVFingerprints), canonicalStrings(fp.TXTFingerprints),
		canonicalStrings(fp.SPFFingerprints), canonicalStrings(fp.TLSFingerprints),
		canonicalStrings(fp.ASNFingerprints), fingerprint, strconv.FormatBool(fp.IsRegex),
		httpStatus, string(engine),
	}, "|")
}

func canonicalStrings(values []string) string {
	copyValues := make([]string, 0, len(values))
	for _, value := range values {
		copyValues = append(copyValues, strings.ToLower(strings.TrimSpace(value)))
	}
	sort.Strings(copyValues)
	return strings.Join(copyValues, "\x00")
}

func mergeFingerprint(base, overlay Fingerprint) Fingerprint {
	base.CNames = unionStrings(base.CNames, overlay.CNames)
	base.NSFingerprints = unionStrings(base.NSFingerprints, overlay.NSFingerprints)
	base.MXFingerprints = unionStrings(base.MXFingerprints, overlay.MXFingerprints)
	base.SRVFingerprints = unionStrings(base.SRVFingerprints, overlay.SRVFingerprints)
	base.TXTFingerprints = unionStrings(base.TXTFingerprints, overlay.TXTFingerprints)
	base.SPFFingerprints = unionStrings(base.SPFFingerprints, overlay.SPFFingerprints)
	base.TLSFingerprints = unionStrings(base.TLSFingerprints, overlay.TLSFingerprints)
	base.ASNFingerprints = unionStrings(base.ASNFingerprints, overlay.ASNFingerprints)
	base.ProofRequirements = unionStrings(base.ProofRequirements, overlay.ProofRequirements)
	base.Vulnerable = base.Vulnerable || overlay.Vulnerable
	base.NXDomain = base.NXDomain || overlay.NXDomain

	if overlay.ID != "" {
		base.ID = overlay.ID
	}
	if overlay.Service != "" {
		base.Service = overlay.Service
	}
	if overlay.Fingerprint != "" {
		base.Fingerprint = overlay.Fingerprint
	}
	if overlay.HTTPStatus != nil {
		base.HTTPStatus = overlay.HTTPStatus
	}
	if overlay.CheckType != "" {
		base.CheckType = overlay.CheckType
	}
	if overlay.Status != "" {
		base.Status = overlay.Status
	}
	if overlay.Discussion != "" {
		base.Discussion = overlay.Discussion
	}
	if overlay.Documentation != "" {
		base.Documentation = overlay.Documentation
	}
	if overlay.CICDPass != nil {
		base.CICDPass = overlay.CICDPass
	}
	if overlay.ActiveVerifier != "" {
		base.ActiveVerifier = overlay.ActiveVerifier
	}
	if overlay.Engine != nil {
		base.Engine = overlay.Engine
	}
	if overlay.CompiledRegex != nil {
		base.CompiledRegex = overlay.CompiledRegex
	}
	base.IsRegex = overlay.IsRegex
	mergeConfidence := func(current *int, candidate int) {
		if candidate != 0 {
			*current = candidate
		}
	}
	mergeConfidence(&base.Confidence, overlay.Confidence)
	mergeConfidence(&base.MXConfidence, overlay.MXConfidence)
	mergeConfidence(&base.TXTConfidence, overlay.TXTConfidence)
	mergeConfidence(&base.SRVConfidence, overlay.SRVConfidence)
	mergeConfidence(&base.TLSConfidence, overlay.TLSConfidence)
	mergeConfidence(&base.ASNConfidence, overlay.ASNConfidence)
	mergeConfidence(&base.SPFConfidence, overlay.SPFConfidence)
	base.Headers = mergeStringMap(base.Headers, overlay.Headers)
	base.SignatureStrength = mergeIntMap(base.SignatureStrength, overlay.SignatureStrength)
	return base
}

func unionStrings(left, right []string) []string {
	result := append([]string(nil), left...)
	seen := make(map[string]struct{}, len(result)+len(right))
	for _, value := range result {
		seen[strings.ToLower(value)] = struct{}{}
	}
	for _, value := range right {
		key := strings.ToLower(value)
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		result = append(result, value)
	}
	return result
}

func mergeStringMap(base, overlay map[string]string) map[string]string {
	if len(base) == 0 && len(overlay) == 0 {
		return nil
	}
	merged := make(map[string]string, len(base)+len(overlay))
	for key, value := range base {
		merged[key] = value
	}
	for key, value := range overlay {
		merged[key] = value
	}
	return merged
}

func mergeIntMap(base, overlay map[string]int) map[string]int {
	if len(base) == 0 && len(overlay) == 0 {
		return nil
	}
	merged := make(map[string]int, len(base)+len(overlay))
	for key, value := range base {
		merged[key] = value
	}
	for key, value := range overlay {
		merged[key] = value
	}
	return merged
}

// MatchesFingerprint verifica se um corpo de resposta HTTP corresponde à assinatura
// de uma assinatura. Suporta correspondência por string simples, sem diferenciar
// maiúsculas de minúsculas, ou por expressão regular.
func MatchesFingerprint(body string, sig *Fingerprint) bool {
	if sig.Engine != nil {
		return sig.Engine.Evaluate(body)
	}

	if sig.Fingerprint == "" {
		return false
	}

	if sig.IsRegex {
		compiled := sig.CompiledRegex
		if compiled == nil {
			compiled, _ = regexp.Compile("(?i)" + sig.Fingerprint)
		}
		return compiled != nil && compiled.MatchString(body)
	}

	return strings.Contains(
		strings.ToLower(body),
		strings.ToLower(sig.Fingerprint),
	)
}

// MatchesPattern verifica se um nome de host (NS ou MX) corresponde a algum dos padrões fornecidos.
func MatchesPattern(hostname string, patterns []string) bool {
	for _, p := range patterns {
		if domainutil.MatchDNSProviderPattern(hostname, p) {
			return true
		}
	}
	return false
}

// LoadCDNSignatures lê as assinaturas de CDN embutidas.
func LoadCDNSignatures() ([]CDNSignature, error) {
	data, err := embeddedFS.ReadFile("cdn_signatures.json")
	if err != nil {
		return nil, fmt.Errorf("lendo cdn_signatures.json embutido: %w", err)
	}
	var cdns []CDNSignature
	if err := json.Unmarshal(data, &cdns); err != nil {
		return nil, fmt.Errorf("decodificando cdn_signatures.json: %w", err)
	}
	return cdns, nil
}
