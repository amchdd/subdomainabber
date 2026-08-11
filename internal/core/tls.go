package core

import "time"

type TLSObservation struct {
	Mode        string    `json:"mode"`
	ServerName  string    `json:"server_name,omitempty"`
	Fingerprint string    `json:"fingerprint"`
	Issuer      string    `json:"issuer,omitempty"`
	Subject     string    `json:"subject,omitempty"`
	SANs        []string  `json:"sans,omitempty"`
	NotAfter    time.Time `json:"not_after,omitempty"`
	Provider    string    `json:"provider,omitempty"`
}
