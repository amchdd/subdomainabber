package core

import (
	"sync"
	"time"
)

var hostAnalysisMutexInit sync.Mutex

// DNSRecordSet armazena o perfil completo de resolução DNS de um host.
type DNSRecordSet struct {
	A          []string    `json:"a"`
	AAAA       []string    `json:"aaaa"`
	CNAME      []string    `json:"cname"` // Cadeia resolvida.
	NS         []string    `json:"ns"`
	MX         []string    `json:"mx"`
	TXT        []string    `json:"txt"`
	SRV        []string    `json:"srv"`
	SRVRecords []SRVRecord `json:"srv_records,omitempty"`
	SOA        []string    `json:"soa,omitempty"`
	CAA        []string    `json:"caa,omitempty"`
	PTR        []string    `json:"ptr,omitempty"`
}

// Evidence representa uma observação isolada coletada durante a análise.
// Uma assinatura ou fingerprint não comprova vulnerabilidade por si só.
type Evidence struct {
	Type        string            `json:"type"`                  // Ex.: CNAME_MATCH, NXDOMAIN, HTTP_MATCH.
	Source      string            `json:"source"`                // Ex.: Amazon S3 ou GitHub Pages.
	Description string            `json:"description"`           // Texto explicativo da evidência
	Weight      int               `json:"weight"`                // Mede o impacto
	Confidence  int               `json:"confidence"`            // Mede a certeza (0-100)
	IsNegative  bool              `json:"is_negative,omitempty"` // Se true, essa evidência pontua no MitigationScore em vez de RiskScore
	Metadata    map[string]string `json:"metadata,omitempty"`
}

// VerificationResult armazena uma observação ativa do provedor. Verified indica
// que a resposta esperada foi observada; ControlProven só pode ser verdadeiro
// depois de uma operação autorizada que demonstre controle do recurso.
type VerificationResult struct {
	Provider      string `json:"provider"`
	Vector        string `json:"vector,omitempty"`
	Resource      string `json:"resource,omitempty"`
	Verified      bool   `json:"verified"`
	ControlProven bool   `json:"control_proven,omitempty"`
	Confidence    int    `json:"confidence"` // Confiança operacional de 0 a 100
	Evidence      string `json:"evidence"`
}

// HostAnalysis é a entidade central que percorre o fluxo de análise.
type HostAnalysis struct {
	mu              *sync.Mutex  `json:"-"`
	Host            string       `json:"host"`
	DNS             DNSRecordSet `json:"dns_records"`
	Evidences       []Evidence   `json:"evidences"`
	RiskScore       int          `json:"risk_score"`
	MitigationScore int          `json:"mitigation_score"`
	ConfidenceScore int          `json:"confidence_score"`
	Classification  string       `json:"classification"` // Ex: TAKEOVERABLE, ORPHANED, HEALTHY...

	// Metadados e tecnologias HTTP.
	Server             string                     `json:"server,omitempty"`
	ContentLength      int64                      `json:"content_length,omitempty"`
	ResponseTimeMs     int64                      `json:"response_time_ms,omitempty"`
	Technologies       []string                   `json:"technologies,omitempty"`
	CDN                string                     `json:"cdn,omitempty"`
	Headers            map[string][]string        `json:"headers,omitempty"` // Apenas se --headers ativo
	HTTPObservations   map[string]HTTPObservation `json:"http_observations,omitempty"`
	ProviderCandidates []ProviderCandidate        `json:"provider_candidates,omitempty"`
	MutationResults    []MutationResult           `json:"mutation_results,omitempty"`
	Delegation         *DelegationCandidate       `json:"delegation_candidate,omitempty"`
	MXCandidates       []MXCandidate              `json:"mx_candidates,omitempty"`
	SRVCandidates      []SRVCandidate             `json:"srv_candidates,omitempty"`
	TXTCandidates      []TXTVerificationCandidate `json:"txt_verification_candidates,omitempty"`
	SPFCandidates      []SPFCandidate             `json:"spf_candidates,omitempty"`
	CloudIPCandidates  []CloudIPCandidate         `json:"cloud_ip_candidates,omitempty"`
	ScanProfile        *ScanProfile               `json:"scan_profile,omitempty"`

	TestedVectors  []string `json:"tested_vectors,omitempty"` // Lista de módulos que efetivamente executaram
	CoverageScore  float64  `json:"coverage_score"`           // Teto de confiança calculado
	KnowledgeScore float64  `json:"knowledge_score"`          // Profundidade do conhecimento baseado na proveniência da evidência

	UnknownProvider *UnknownProviderEvidence `json:"unknown_provider,omitempty"`

	ParentCookieScope  bool   `json:"parent_cookie_scope,omitempty"`
	ParentCORSWildcard bool   `json:"parent_cors_wildcard,omitempty"`
	OriginIPCandidate  string `json:"origin_ip_candidate,omitempty"`

	VerificationScore  int                 `json:"verification_score"` // 100 = provado, 0 = sem verificação/falhou
	ActiveVerification *VerificationResult `json:"active_verification,omitempty"`

	FirstSeen              time.Time `json:"first_seen"`
	LastSeen               time.Time `json:"last_seen"`
	PreviousClassification string    `json:"previous_classification"`
	LastStateChange        time.Time `json:"last_state_change"`
}

// ScanProfile registra apenas opções reproduzíveis e não secretas da coleta.
// Ele permite que a revalidação detecte diferenças de cobertura em vez de
// anunciar uma correção baseada em um perfil mais fraco.
type ScanProfile struct {
	Version              int      `json:"version"`
	SignatureDigest      string   `json:"signature_digest,omitempty"`
	CheckNS              bool     `json:"check_ns,omitempty"`
	CheckCloud           bool     `json:"check_cloud,omitempty"`
	CheckAXFR            bool     `json:"check_axfr,omitempty"`
	CheckDNSSEC          bool     `json:"check_dnssec,omitempty"`
	CheckEmail           bool     `json:"check_email,omitempty"`
	CheckHeaders         bool     `json:"check_headers,omitempty"`
	CheckShadowIT        bool     `json:"check_shadow_it,omitempty"`
	CheckRedirects       bool     `json:"check_redirects,omitempty"`
	CheckEvasion         bool     `json:"check_evasion,omitempty"`
	CheckFraming         bool     `json:"check_framing,omitempty"`
	Aggressive           bool     `json:"aggressive,omitempty"`
	CheckSRV             bool     `json:"check_srv,omitempty"`
	SRVOwners            []string `json:"srv_owners,omitempty"`
	SRVExhaustive        bool     `json:"srv_exhaustive,omitempty"`
	FollowRedirects      bool     `json:"follow_redirects,omitempty"`
	FetchHeaders         bool     `json:"fetch_headers,omitempty"`
	UserAgent            string   `json:"user_agent,omitempty"`
	RelatedImpactInScope bool     `json:"related_impact_in_scope,omitempty"`
}

type UnknownProviderEvidence struct {
	RootDomain         string    `json:"root_domain"`
	Frequency          int       `json:"frequency"`
	Severity           string    `json:"severity"` // LOW, MEDIUM, HIGH
	FirstSeen          time.Time `json:"first_seen"`
	LastSeen           time.Time `json:"last_seen"`
	ExampleHosts       []string  `json:"example_hosts,omitempty"`
	LastDiscoveryScore float64   `json:"last_discovery_score"`
}

func (h *HostAnalysis) InitMutex() {
	if h == nil {
		return
	}
	hostAnalysisMutexInit.Lock()
	defer hostAnalysisMutexInit.Unlock()
	if h.mu == nil {
		h.mu = &sync.Mutex{}
	}
}

func (h *HostAnalysis) AddEvidence(ev Evidence) {
	h.InitMutex()
	h.mu.Lock()
	defer h.mu.Unlock()
	h.Evidences = append(h.Evidences, ev)
}

func (h *HostAnalysis) AddTestedVector(vector string) {
	h.InitMutex()
	h.mu.Lock()
	defer h.mu.Unlock()
	h.TestedVectors = append(h.TestedVectors, vector)
}

func (h *HostAnalysis) SetHTTPObservation(scheme string, observation HTTPObservation) {
	h.InitMutex()
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.HTTPObservations == nil {
		h.HTTPObservations = make(map[string]HTTPObservation)
	}
	h.HTTPObservations[scheme] = cloneHTTPObservation(observation)
}

func (h *HostAnalysis) HTTPObservation(scheme string) (HTTPObservation, bool) {
	h.InitMutex()
	h.mu.Lock()
	defer h.mu.Unlock()
	observation, ok := h.HTTPObservations[scheme]
	return cloneHTTPObservation(observation), ok
}

func (h *HostAnalysis) AddProviderCandidate(candidate ProviderCandidate) {
	h.InitMutex()
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, existing := range h.ProviderCandidates {
		if existing.ProviderID == candidate.ProviderID && existing.CNAME == candidate.CNAME &&
			existing.Vector == candidate.Vector && existing.Resource == candidate.Resource {
			return
		}
	}
	h.ProviderCandidates = append(h.ProviderCandidates, candidate)
}

func (h *HostAnalysis) ProviderCandidateSnapshot() []ProviderCandidate {
	h.InitMutex()
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]ProviderCandidate(nil), h.ProviderCandidates...)
}

func (h *HostAnalysis) AddMutationResult(result MutationResult) {
	h.InitMutex()
	h.mu.Lock()
	defer h.mu.Unlock()
	h.MutationResults = append(h.MutationResults, result)
}

func cloneHTTPObservation(observation HTTPObservation) HTTPObservation {
	observation.Body = append([]byte(nil), observation.Body...)
	observation.NormalizedBody = append([]byte(nil), observation.NormalizedBody...)
	if observation.Headers != nil {
		headers := make(map[string][]string, len(observation.Headers))
		for name, values := range observation.Headers {
			headers[name] = append([]string(nil), values...)
		}
		observation.Headers = headers
	}
	return observation
}
