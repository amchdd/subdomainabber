package platform

import (
	"context"
	"net"
	"net/url"
	"strings"

	"github.com/amchdd/subdomainabber/internal/domainutil"
)

type AssetKind string

const (
	KindDomain   AssetKind = "domain"
	KindWildcard AssetKind = "wildcard"
	KindURL      AssetKind = "url"
	KindIP       AssetKind = "ip"
	KindCIDR     AssetKind = "cidr"
	KindOther    AssetKind = "other"
)

type Rules struct {
	Description      string `json:"description,omitempty"`
	AutomatedTooling int    `json:"automated_tooling,omitempty"`
	UserAgent        string `json:"user_agent,omitempty"`
	RequestHeader    string `json:"request_header,omitempty"`
	SafeHarbour      bool   `json:"safe_harbour,omitempty"`
}

type Asset struct {
	ID          string    `json:"id"`
	Value       string    `json:"value"`
	Type        string    `json:"type,omitempty"`
	Kind        AssetKind `json:"kind"`
	Host        string    `json:"host,omitempty"`
	ReconRoot   string    `json:"recon_root,omitempty"`
	Eligible    bool      `json:"eligible"`
	Bounty      bool      `json:"bounty"`
	Instruction string    `json:"instruction,omitempty"`
	Severity    string    `json:"severity,omitempty"`
	Group       string    `json:"group,omitempty"`
}

type Program struct {
	Platform string  `json:"platform"`
	ID       string  `json:"id"`
	Handle   string  `json:"handle"`
	Name     string  `json:"name"`
	State    string  `json:"state,omitempty"`
	URL      string  `json:"url,omitempty"`
	Bounty   bool    `json:"bounty"`
	Rules    Rules   `json:"rules,omitempty"`
	Assets   []Asset `json:"assets"`
}

func NormalizeAsset(value, hint string) Asset {
	value = strings.TrimSpace(value)
	asset := Asset{Value: value, Type: hint, Kind: KindOther}
	if _, _, err := net.ParseCIDR(value); err == nil {
		asset.Kind = KindCIDR
		return asset
	}
	if net.ParseIP(value) != nil {
		asset.Kind = KindIP
		return asset
	}
	if parsed, err := url.Parse(value); err == nil && parsed.Hostname() != "" && (parsed.Scheme == "http" || parsed.Scheme == "https") {
		host := strings.TrimPrefix(strings.ToLower(parsed.Hostname()), "*.")
		if normalized, err := domainutil.NormalizeHostname(host); err == nil {
			asset.Kind = KindURL
			asset.Host = normalized
			asset.ReconRoot = normalized
			if strings.HasPrefix(parsed.Hostname(), "*.") {
				asset.Kind = KindWildcard
				asset.Host = ""
			}
		}
		return asset
	}
	wildcard := strings.HasPrefix(value, "*.")
	host := strings.TrimPrefix(value, "*.")
	if normalized, err := domainutil.NormalizeHostname(host); err == nil && strings.Contains(normalized, ".") {
		asset.Kind = KindDomain
		asset.Host = normalized
		asset.ReconRoot = normalized
		if wildcard {
			asset.Kind = KindWildcard
			asset.Host = ""
		}
	}
	return asset
}

type Client interface {
	Name() string
	Programs(context.Context) ([]Program, error)
}

func testingOpen(state string) bool {
	state = strings.ToLower(strings.TrimSpace(state))
	if state == "" {
		return true
	}
	switch state {
	case "open", "active", "live", "public", "published", "public_mode":
		return true
	}
	return false
}
