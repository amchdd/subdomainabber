package evidence

import (
	"context"

	"github.com/amchdd/subdomainabber/internal/core"
)

// Correlator adiciona apenas evidências sintéticas restritas ao provedor. Achados
// administrativos de DNS permanecem independentes e nunca são reclassificados
// como prova de takeover.
type Correlator struct{}

func NewCorrelator() *Correlator {
	return &Correlator{}
}

func (c *Correlator) Collect(_ context.Context, analysis *core.HostAnalysis) error {
	c.correlateCloudIP(analysis)
	for _, cnameEvidence := range analysis.Evidences {
		providerID := cnameEvidence.Metadata["provider_id"]
		matchedCNAME := cnameEvidence.Metadata["matched_cname"]
		if cnameEvidence.Type != "CNAME_PROVIDER_MATCH" || cnameEvidence.Source == "" || providerID == "" || matchedCNAME == "" {
			continue
		}
		for _, httpEvidence := range analysis.Evidences {
			if httpEvidence.Type != "HTTP_BODY_MATCH" || httpEvidence.Source != cnameEvidence.Source ||
				httpEvidence.Metadata["provider_id"] != providerID || httpEvidence.Metadata["matched_cname"] != matchedCNAME ||
				httpEvidence.Metadata["rule_id"] == "" || httpEvidence.Metadata["matched_fingerprint"] == "" {
				continue
			}
			if !hasEvidenceFromSource(analysis.Evidences, "TLS_PROVIDER_MATCH", cnameEvidence.Source) {
				continue
			}
			analysis.AddEvidence(core.Evidence{
				Type:        "CORRELATED_PROVIDER_CONFIRMATION",
				Source:      cnameEvidence.Source,
				Description: "CNAME, TLS e assinatura HTTP estruturada correspondem ao mesmo provedor.",
				Weight:      100,
				Confidence:  95,
				Metadata: map[string]string{
					"provider_id":   providerID,
					"matched_cname": matchedCNAME,
					"rule_id":       httpEvidence.Metadata["rule_id"],
				},
			})
			return nil
		}
	}
	return nil
}

func (c *Correlator) correlateCloudIP(analysis *core.HostAnalysis) {
	if len(analysis.CloudIPCandidates) == 0 || (!hasEvidenceType(analysis.Evidences, "TLS_MISMATCH") && !hasEvidenceType(analysis.Evidences, "TLS_EXPIRED")) {
		return
	}
	httpUnreachable := len(analysis.HTTPObservations) > 0
	for _, observation := range analysis.HTTPObservations {
		if observation.Complete || observation.TransportError == "" {
			httpUnreachable = false
			break
		}
	}
	if !httpUnreachable {
		return
	}
	for index := range analysis.CloudIPCandidates {
		candidate := &analysis.CloudIPCandidates[index]
		if candidate.ProviderID == "" {
			continue
		}
		candidate.Reachability = "HTTP_UNREACHABLE"
		candidate.Claimability = core.ClaimabilityManualReview
		analysis.AddEvidence(core.Evidence{
			Type: "STALE_CLOUD_IP_CANDIDATE", Source: candidate.Provider,
			Description: "O IP de nuvem está inacessível por HTTP e possui sinal TLS de abandono; a possibilidade de realocação não foi comprovada",
			Weight:      20, Confidence: 60,
			Metadata: map[string]string{
				"ip_address": candidate.IP, "record_type": candidate.RecordType,
				"provider_id": candidate.ProviderID, "claimability": string(candidate.Claimability),
			},
		})
	}
}

func hasEvidenceType(evidences []core.Evidence, evidenceType string) bool {
	for _, evidence := range evidences {
		if evidence.Type == evidenceType {
			return true
		}
	}
	return false
}

func hasEvidenceFromSource(evidences []core.Evidence, evidenceType, source string) bool {
	for _, evidence := range evidences {
		if evidence.Type == evidenceType && evidence.Source == source {
			return true
		}
	}
	return false
}
