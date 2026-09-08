package core

type RedirectHop struct {
	Index              int       `json:"index"`
	URL                string    `json:"url"`
	Hostname           string    `json:"hostname"`
	Scheme             string    `json:"scheme"`
	StatusCode         int       `json:"status_code,omitempty"`
	Location           string    `json:"location,omitempty"`
	DNSStatus          DNSStatus `json:"dns_status,omitempty"`
	CNAME              []string  `json:"cname,omitempty"`
	Addresses          []string  `json:"addresses,omitempty"`
	Provider           string    `json:"provider,omitempty"`
	ResponseKind       string    `json:"response_kind,omitempty"`
	EdgeProvider       string    `json:"edge_provider,omitempty"`
	MatchedFingerprint string    `json:"matched_fingerprint,omitempty"`
}

type RedirectChain struct {
	Scheme        string        `json:"scheme"`
	Hops          []RedirectHop `json:"hops"`
	FinalURL      string        `json:"final_url"`
	StoppedReason string        `json:"stopped_reason,omitempty"`
}

type WebDependency struct {
	URL        string    `json:"url"`
	Host       string    `json:"host"`
	Kind       string    `json:"kind"`
	Source     string    `json:"source"`
	Directive  string    `json:"directive,omitempty"`
	CNAME      []string  `json:"cname,omitempty"`
	Provider   string    `json:"provider,omitempty"`
	DNSStatus  DNSStatus `json:"dns_status"`
	HTTPStatus int       `json:"http_status,omitempty"`
	Dangling   bool      `json:"dangling,omitempty"`
}
