package core

import "sort"

type ReconDNSRecord struct {
	A      []string  `json:"a,omitempty"`
	AAAA   []string  `json:"aaaa,omitempty"`
	CNAME  []string  `json:"cname,omitempty"`
	Status DNSStatus `json:"status"`
}

type ReconOrigin struct {
	Source string `json:"source"`
	Method string `json:"method"`
	Parent string `json:"parent,omitempty"`
	Depth  int    `json:"depth"`
}

type ReconCandidate struct {
	Name     string         `json:"name"`
	Root     string         `json:"root"`
	Resolved bool           `json:"resolved"`
	Wildcard bool           `json:"wildcard,omitempty"`
	DNS      ReconDNSRecord `json:"dns"`
	Origins  []ReconOrigin  `json:"origins"`
}

func (candidate ReconCandidate) SourceNames() []string {
	seen := make(map[string]struct{})
	for _, origin := range candidate.Origins {
		if origin.Source != "" {
			seen[origin.Source] = struct{}{}
		}
	}
	result := make([]string, 0, len(seen))
	for source := range seen {
		result = append(result, source)
	}
	sort.Strings(result)
	return result
}

type ReconCheckpoint struct {
	Round    int      `json:"round"`
	Frontier []string `json:"frontier,omitempty"`
}
