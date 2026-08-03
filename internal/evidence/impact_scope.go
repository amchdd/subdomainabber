package evidence

import (
	"github.com/amchdd/subdomainabber/internal/core"
	"github.com/amchdd/subdomainabber/internal/dns"
	"github.com/amchdd/subdomainabber/internal/domainutil"
)

func explicitRegistrableDomains(hosts []string) map[string]struct{} {
	allowed := make(map[string]struct{})
	for _, host := range hosts {
		normalized, err := domainutil.NormalizeHostname(host)
		if err != nil {
			continue
		}
		root := dns.ExtractRootDomain(normalized)
		if root == normalized {
			allowed[root] = struct{}{}
		}
	}
	return allowed
}

func relatedDomainProbeAllowed(allowed map[string]struct{}, root string) bool {
	_, ok := allowed[root]
	return ok
}

func hasRelatedDomainImpactCandidate(analysis *core.HostAnalysis) bool {
	if analysis == nil {
		return false
	}
	if analysis.ActiveVerification != nil && analysis.ActiveVerification.Verified && analysis.ActiveVerification.ControlProven {
		return true
	}
	for _, evidence := range analysis.Evidences {
		switch evidence.Type {
		case "CNAME_DANGLING", "HTTP_BODY_MATCH", "HTTP_MUTATION_REVEALED_PROVIDER_FINGERPRINT",
			"DELEGATION_BROKEN", "DELEGATION_TAKEOVER_CANDIDATE",
			"DELEGATION_CLAIMABILITY_VERIFIED", "ZONE_CONTROL_CONFIRMED",
			"STALE_CLOUD_IP_CANDIDATE", "CLAIM_SUCCESS":
			return true
		}
	}
	return false
}
