package core

// ClaimabilityState separa uma referência quebrada observada da prova de que um
// atacante consegue recriar ou vincular o recurso referenciado.
type ClaimabilityState string

const (
	ClaimabilityNotChecked       ClaimabilityState = "NOT_CHECKED"
	ClaimabilityNotVerified      ClaimabilityState = "NOT_VERIFIED"
	ClaimabilityManualReview     ClaimabilityState = "MANUAL_REVIEW"
	ClaimabilityProviderVerified ClaimabilityState = "PROVIDER_VERIFIED"
	ClaimabilityControlConfirmed ClaimabilityState = "CONTROL_CONFIRMED"
	ClaimabilityNotClaimable     ClaimabilityState = "NOT_CLAIMABLE"
)

type DNSStatus string

const (
	DNSStatusResolved DNSStatus = "RESOLVED"
	DNSStatusNoData   DNSStatus = "NO_DATA"
	DNSStatusNXDomain DNSStatus = "NXDOMAIN"
	DNSStatusServFail DNSStatus = "SERVFAIL"
	DNSStatusRefused  DNSStatus = "REFUSED"
	DNSStatusTimeout  DNSStatus = "TIMEOUT"
	DNSStatusError    DNSStatus = "ERROR"
)

type SRVRecord struct {
	Owner    string `json:"owner"`
	Priority uint16 `json:"priority"`
	Weight   uint16 `json:"weight"`
	Port     uint16 `json:"port"`
	Target   string `json:"target"`
}

type DelegationNSObservation struct {
	Nameserver string    `json:"nameserver"`
	Resolvable bool      `json:"resolvable"`
	Status     DNSStatus `json:"status"`
	ProviderID string    `json:"provider_id,omitempty"`
	Service    string    `json:"service,omitempty"`
	Glue       []string  `json:"glue,omitempty"`
}

type DelegationCandidate struct {
	Zone                       string                    `json:"zone"`
	ParentZone                 string                    `json:"parent_zone,omitempty"`
	DelegatedNameservers       []string                  `json:"delegated_nameservers"`
	ParentDelegatedNameservers []string                  `json:"parent_delegated_nameservers,omitempty"`
	Responsive                 []string                  `json:"responsive,omitempty"`
	Lame                       []string                  `json:"lame,omitempty"`
	Unresolvable               []string                  `json:"unresolvable,omitempty"`
	ProviderID                 string                    `json:"provider_id,omitempty"`
	Provider                   string                    `json:"provider,omitempty"`
	ParentHasDS                bool                      `json:"parent_has_ds"`
	ParentDSChecked            bool                      `json:"parent_ds_checked"`
	ParentDelegationVerified   bool                      `json:"parent_delegation_verified"`
	Claimability               ClaimabilityState         `json:"claimability"`
	Nameservers                []DelegationNSObservation `json:"nameserver_observations,omitempty"`
}

type MXCandidate struct {
	Target             string            `json:"target"`
	ProviderID         string            `json:"provider_id,omitempty"`
	Provider           string            `json:"provider,omitempty"`
	DNSStatus          DNSStatus         `json:"dns_status"`
	RegistrableDomain  string            `json:"registrable_domain,omitempty"`
	Ownership          string            `json:"ownership"`
	RegistrationStatus string            `json:"registration_status"`
	Claimability       ClaimabilityState `json:"claimability"`
}

type SRVCandidate struct {
	Record             SRVRecord         `json:"record"`
	ProviderID         string            `json:"provider_id,omitempty"`
	Provider           string            `json:"provider,omitempty"`
	DNSStatus          DNSStatus         `json:"dns_status"`
	RegistrableDomain  string            `json:"registrable_domain,omitempty"`
	Ownership          string            `json:"ownership"`
	RegistrationStatus string            `json:"registration_status"`
	Claimability       ClaimabilityState `json:"claimability"`
}

type TXTVerificationCandidate struct {
	Provider     string            `json:"provider"`
	TokenPrefix  string            `json:"token_prefix"`
	Record       string            `json:"record"`
	State        string            `json:"state"`
	Claimability ClaimabilityState `json:"claimability"`
}

type SPFCandidate struct {
	Domain             string            `json:"domain"`
	Mechanism          string            `json:"mechanism"`
	Chain              []string          `json:"chain"`
	DNSStatus          DNSStatus         `json:"dns_status"`
	RegistrableDomain  string            `json:"registrable_domain,omitempty"`
	Ownership          string            `json:"ownership"`
	RegistrationStatus string            `json:"registration_status"`
	Claimability       ClaimabilityState `json:"claimability"`
}

type CloudIPCandidate struct {
	IP               string            `json:"ip"`
	RecordType       string            `json:"record_type"`
	ASN              string            `json:"asn,omitempty"`
	ProviderID       string            `json:"provider_id,omitempty"`
	Provider         string            `json:"provider,omitempty"`
	Reachability     string            `json:"reachability"`
	HistoricalSignal bool              `json:"historical_signal"`
	Claimability     ClaimabilityState `json:"claimability"`
}
