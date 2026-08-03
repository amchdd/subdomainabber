package finding

import (
	"strings"

	"github.com/amchdd/subdomainabber/internal/core"
)

// Context é o contexto causal de apresentação compartilhado pela CLI e pelas notificações.
type Context struct {
	Vector   string
	Resource string
	Evidence core.Evidence
}

// Primary seleciona a evidência causal de maior valor e a associa ao vetor e
// ao recurso afetado. Evidências apenas contextuais ou mitigadoras são usadas
// somente como alternativa, nunca acima das causas da classificação.
func Primary(analysis *core.HostAnalysis) Context {
	result := Context{Vector: "GENERAL"}
	if analysis == nil {
		return result
	}
	result.Resource = analysis.Host

	priorities := []string{
		"CLAIM_SUCCESS", "ZONE_CONTROL_CONFIRMED", "DELEGATION_CLAIMABILITY_VERIFIED",
		"DELEGATION_CLAIMABILITY_NOT_DEMONSTRATED",
		"HTTP_MUTATION_REVEALED_PROVIDER_FINGERPRINT", "HTTP_BODY_MATCH",
		"DELEGATION_TAKEOVER_CANDIDATE", "DNS_AXFR_ALLOWED", "CNAME_DANGLING",
		"DELEGATION_BROKEN", "STALE_CLOUD_IP_CANDIDATE",
		"CLOUD_S3_WRITABLE", "CLOUD_S3_LISTABLE", "CLOUD_AZURE_BLOB_LISTABLE", "CLOUD_GCS_LISTABLE",
		"MX_BROKEN", "MX_DANGLING", "MX_UNRESOLVABLE",
		"SRV_BROKEN", "SRV_DANGLING", "SRV_UNRESOLVABLE",
		"SPF_DANGLING_TAKEOVER", "SPF_BROKEN_INCLUDE", "SPF_INCLUDE_WITHOUT_POLICY",
		"SPF_LOOKUP_LIMIT_EXCEEDED", "SPF_INCLUDE_CYCLE",
		"HTTP_OPEN_REDIRECT", "SHADOW_IT_DETECTED",
		"EMAIL_SPF_PERMISSIVE", "EMAIL_SPF_MISSING", "EMAIL_DMARC_MISSING",
		"HTTP_HSTS_MISSING", "HTTP_CSP_MISSING",
		"NS_ALL_DEAD", "NS_ORPHANED", "LAME_DELEGATION", "NS_REFUSED", "NS_SERVFAIL", "NS_SOA_MISMATCH",
		"TLS_EXPIRED", "TLS_SELF_SIGNED", "TLS_MISMATCH",
	}
	for _, evidenceType := range priorities {
		if evidence := byType(analysis, evidenceType); evidence.Type != "" {
			result.Evidence = evidence
			break
		}
	}
	if result.Evidence.Type == "" {
		for _, evidence := range analysis.Evidences {
			if !evidence.IsNegative {
				result.Evidence = evidence
				break
			}
		}
	}

	selected := result.Evidence
	switch {
	case isDelegationEvidence(selected.Type):
		result.Vector = "NS"
		if analysis.Delegation != nil && analysis.Delegation.Zone != "" {
			result.Resource = analysis.Delegation.Zone
		} else if selected.Metadata["zone"] != "" {
			result.Resource = selected.Metadata["zone"]
		}
	case selected.Type == "DNS_AXFR_ALLOWED":
		result.Vector = "AXFR"
		if selected.Metadata["zone"] != "" {
			result.Resource = selected.Metadata["zone"]
		}
	case strings.HasPrefix(selected.Type, "CNAME_") ||
		selected.Type == "HTTP_BODY_MATCH" ||
		selected.Type == "HTTP_MUTATION_REVEALED_PROVIDER_FINGERPRINT":
		result.Vector = "CNAME"
		if len(analysis.DNS.CNAME) > 0 {
			result.Resource = analysis.DNS.CNAME[len(analysis.DNS.CNAME)-1]
		}
	case strings.HasPrefix(selected.Type, "MX_"):
		result.Vector = "MX"
		if selected.Metadata["mx_target"] != "" {
			result.Resource = selected.Metadata["mx_target"]
		}
	case strings.HasPrefix(selected.Type, "SRV_"):
		result.Vector = "SRV"
		if selected.Metadata["srv_owner"] != "" {
			result.Resource = selected.Metadata["srv_owner"]
		}
	case strings.HasPrefix(selected.Type, "SPF_"):
		result.Vector = "SPF"
		if selected.Metadata["domain"] != "" {
			result.Resource = selected.Metadata["domain"]
		}
	case strings.HasPrefix(selected.Type, "EMAIL_"):
		result.Vector = "EMAIL"
		if selected.Metadata["domain"] != "" {
			result.Resource = selected.Metadata["domain"]
		} else if selected.Metadata["owner"] != "" {
			result.Resource = selected.Metadata["owner"]
		}
	case strings.HasPrefix(selected.Type, "HTTP_"):
		result.Vector = "HTTP"
	case strings.HasPrefix(selected.Type, "TLS_"):
		result.Vector = "TLS"
	case strings.HasPrefix(selected.Type, "CLOUD_") || selected.Type == "STALE_CLOUD_IP_CANDIDATE":
		result.Vector = "CLOUD"
	case selected.Type == "SHADOW_IT_DETECTED":
		result.Vector = "SHADOW_IT"
	}

	if result.Evidence.Type == "" && analysis.ActiveVerification != nil {
		result.Vector = valueOr(analysis.ActiveVerification.Vector, result.Vector)
		result.Resource = valueOr(analysis.ActiveVerification.Resource, result.Resource)
	}
	return result
}

func byType(analysis *core.HostAnalysis, evidenceType string) core.Evidence {
	for _, evidence := range analysis.Evidences {
		if evidence.Type == evidenceType {
			return evidence
		}
	}
	return core.Evidence{}
}

func isDelegationEvidence(evidenceType string) bool {
	return strings.HasPrefix(evidenceType, "DELEGATION_") ||
		strings.HasPrefix(evidenceType, "ZONE_CONTROL_") ||
		strings.HasPrefix(evidenceType, "NS_") ||
		evidenceType == "LAME_DELEGATION"
}

func valueOr(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return value
}
