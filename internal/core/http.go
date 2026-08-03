package core

import "time"

type HTTPObservation struct {
	Scheme         string              `json:"scheme"`
	StatusCode     int                 `json:"status_code"`
	Headers        map[string][]string `json:"headers,omitempty"`
	Body           []byte              `json:"body,omitempty"`
	NormalizedBody []byte              `json:"normalized_body,omitempty"`
	BodyHash       string              `json:"body_hash,omitempty"`
	Title          string              `json:"title,omitempty"`
	Server         string              `json:"server,omitempty"`
	Complete       bool                `json:"complete"`
	Duration       time.Duration       `json:"duration"`
	TransportError string              `json:"transport_error,omitempty"`
	ParseError     string              `json:"parse_error,omitempty"`
}

type ProviderCandidate struct {
	ProviderID   string            `json:"provider_id"`
	Service      string            `json:"service"`
	CNAME        string            `json:"cname"`
	CNAMEPattern string            `json:"cname_pattern"`
	Vector       string            `json:"vector,omitempty"`
	Resource     string            `json:"resource,omitempty"`
	Metadata     map[string]string `json:"metadata,omitempty"`
}

type BlockDecision struct {
	Blocked    bool     `json:"blocked"`
	Confidence int      `json:"confidence"`
	Reasons    []string `json:"reasons,omitempty"`
	BaselineID string   `json:"baseline_id"`
}

type MutationContext struct {
	DialHost           string
	DialPort           int
	HTTPAuthority      string
	TLSServerName      string
	Scheme             string
	Baseline           HTTPObservation
	ProviderCandidates []ProviderCandidate
	BlockDecision      BlockDecision
}

type RawHTTPObservation struct {
	StatusCode      int                 `json:"status_code"`
	Headers         map[string][]string `json:"headers,omitempty"`
	Body            []byte              `json:"body,omitempty"`
	Complete        bool                `json:"complete"`
	TimedOut        bool                `json:"timed_out,omitempty"`
	ConnectionReset bool                `json:"connection_reset,omitempty"`
	ParseError      string              `json:"parse_error,omitempty"`
	TransportError  string              `json:"transport_error,omitempty"`
	Duration        time.Duration       `json:"duration"`
}

type MutationOutcome string

const (
	MutationNotApplicable               MutationOutcome = "NOT_APPLICABLE"
	MutationNoDifference                MutationOutcome = "NO_DIFFERENCE"
	MutationTransportFailure            MutationOutcome = "TRANSPORT_FAILURE"
	MutationRejected                    MutationOutcome = "REJECTED"
	MutationReproducibleDifferential    MutationOutcome = "REPRODUCIBLE_DIFFERENTIAL"
	MutationRevealedProviderFingerprint MutationOutcome = "REVEALED_PROVIDER_FINGERPRINT"
	MutationFramingDifferential         MutationOutcome = "FRAMING_DIFFERENTIAL"
	MutationFramingRejected             MutationOutcome = "FRAMING_REJECTED"
	MutationFramingTransportFailure     MutationOutcome = "FRAMING_TRANSPORT_FAILURE"
	MutationFramingNoDifference         MutationOutcome = "FRAMING_NO_DIFFERENCE"
)

type HTTPFingerprintRule struct {
	RuleID             string            `json:"rule_id"`
	ProviderID         string            `json:"provider_id"`
	CNAMEPatterns      []string          `json:"cname_patterns"`
	StatusAnyOf        []int             `json:"status_any_of,omitempty"`
	BodyContains       []string          `json:"body_contains,omitempty"`
	RequiredHeaders    map[string]string `json:"required_headers,omitempty"`
	Claimability       string            `json:"claimability"`
	MinimumSpecificity int               `json:"minimum_specificity"`
}

type ExperimentObservations struct {
	ControlBefore  RawHTTPObservation `json:"control_before"`
	MutationFirst  RawHTTPObservation `json:"mutation_first"`
	MutationSecond RawHTTPObservation `json:"mutation_second"`
	ControlAfter   RawHTTPObservation `json:"control_after"`
}

type Difference struct {
	Field  string `json:"field"`
	Before string `json:"before,omitempty"`
	After  string `json:"after,omitempty"`
}

type MutationResult struct {
	Name          string                 `json:"name"`
	BaselineID    string                 `json:"baseline_id"`
	Attempts      int                    `json:"attempts"`
	Confirmations int                    `json:"confirmations"`
	StatusBefore  int                    `json:"status_before"`
	StatusAfter   int                    `json:"status_after"`
	RelevantDiffs []Difference           `json:"relevant_diffs,omitempty"`
	Error         string                 `json:"error,omitempty"`
	Outcome       MutationOutcome        `json:"outcome"`
	Observation   RawHTTPObservation     `json:"observation"`
	Experiment    ExperimentObservations `json:"experiment"`
}

type RevealedProviderFingerprint struct {
	RuleID             string `json:"rule_id"`
	ProviderID         string `json:"provider_id"`
	Service            string `json:"service"`
	CNAME              string `json:"cname"`
	Mutation           string `json:"mutation"`
	BaselineStatus     int    `json:"baseline_status"`
	MutatedStatus      int    `json:"mutated_status"`
	BaselineBodyHash   string `json:"baseline_body_hash"`
	MutatedBodyHash    string `json:"mutated_body_hash"`
	MatchedFingerprint string `json:"matched_fingerprint"`
	Specificity        int    `json:"specificity"`
	Attempts           int    `json:"attempts"`
	Confirmations      int    `json:"confirmations"`
}
