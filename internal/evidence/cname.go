package evidence

import (
	"context"
	"fmt"
	"strings"

	"github.com/amchdd/subdomainabber/internal/core"
	"github.com/amchdd/subdomainabber/internal/dns"
	"github.com/amchdd/subdomainabber/internal/domainutil"
	"github.com/amchdd/subdomainabber/pkg/signatures"
)

type CNAMECollector struct {
	resolver *dns.Resolver
	sigs     []signatures.Fingerprint
}

func NewCNAMECollector(resolver *dns.Resolver, sigs []signatures.Fingerprint) *CNAMECollector {
	return &CNAMECollector{
		resolver: resolver,
		sigs:     sigs,
	}
}

func (c *CNAMECollector) Phase() CollectorPhase {
	return PhaseProviderDiscovery
}

func (c *CNAMECollector) Collect(ctx context.Context, analysis *core.HostAnalysis) error {
	analysis.AddTestedVector("DNS")

	if len(analysis.DNS.CNAME) == 0 {
		return nil
	}

	var danglingNode string
	var matchedProvider string

	for i, cname := range analysis.DNS.CNAME {
		cnameClean, err := domainutil.NormalizeHostname(cname)
		if err != nil {
			continue
		}

		for _, sig := range c.sigs {
			if sig.CheckType == "ns" || sig.CheckType == "a" || sig.CheckType == "mx" {
				continue
			}

			if _, matched := matchingCNAME([]string{cnameClean}, sig.CNames); matched {
				confidence := sig.Confidence
				if confidence == 0 {
					confidence = 80
				}

				analysis.AddEvidence(core.Evidence{
					Type:        "CNAME_PROVIDER_MATCH",
					Source:      sig.Service,
					Description: "CNAME resolvido aponta para o serviço " + sig.Service,
					Weight:      20,
					Confidence:  confidence,
					Metadata: map[string]string{
						"matched_cname": cnameClean,
						"chain_depth":   fmt.Sprintf("%d", i+1),
						"provider_id":   providerID(sig.Service),
					},
				})
				matchedPattern := ""
				for _, pattern := range sig.CNames {
					if domainutil.MatchDNSName(cnameClean, pattern) {
						matchedPattern = pattern
						break
					}
				}
				analysis.AddProviderCandidate(core.ProviderCandidate{
					ProviderID:   providerID(sig.Service),
					Service:      sig.Service,
					CNAME:        cnameClean,
					CNAMEPattern: matchedPattern,
					Vector:       "CNAME",
					Resource:     cnameClean,
				})
				matchedProvider = sig.Service

				if sig.NXDomain {
					analysis.AddEvidence(core.Evidence{
						Type:        "NXDOMAIN_EXPECTED",
						Source:      sig.Service,
						Description: "Serviço " + sig.Service + " detecta takeover via NXDOMAIN",
						Weight:      0,
						Confidence:  100,
					})
				}
				break
			}
		}

		if i == len(analysis.DNS.CNAME)-1 {
			danglingNode = cnameClean
		}
	}

	if danglingNode == "" {
		return nil
	}
	status := core.DNSStatusResolved
	consensusState := "DISABLED"
	missingAddress := len(analysis.DNS.A) == 0 && len(analysis.DNS.AAAA) == 0
	if missingAddress {
		status = core.DNSStatusError
		if c.resolver != nil {
			status, consensusState = c.resolver.AddressConsensus(ctx, danglingNode)
		}
	}
	analysis.AddEvidence(core.Evidence{
		Type: "CNAME_CHAIN_TRACE", Source: "DNS",
		Description: "A cadeia CNAME foi percorrida até o destino terminal.",
		Weight:      0, Confidence: 100,
		Metadata: map[string]string{
			"chain": strings.Join(analysis.DNS.CNAME, " -> "), "terminal": danglingNode,
			"chain_length": fmt.Sprintf("%d", len(analysis.DNS.CNAME)), "terminal_status": string(status), "consensus": consensusState,
		},
	})

	if missingAddress {
		evType, desc, weight, evidenceConfidence := cnameResolutionEvidence(status, matchedProvider)

		analysis.AddEvidence(core.Evidence{
			Type:        evType,
			Source:      "DNS",
			Description: desc,
			Weight:      weight,
			Confidence:  evidenceConfidence,
			Metadata: map[string]string{
				"cname_target": danglingNode,
				"chain_length": fmt.Sprintf("%d", len(analysis.DNS.CNAME)),
				"dns_status":   string(status),
			},
		})
		if consensusState != "DISABLED" {
			analysis.AddEvidence(core.Evidence{
				Type: "DNS_CONSENSUS_STATE", Source: "DNS",
				Description: "O estado terminal foi comparado entre resolvedores independentes.",
				Confidence:  100, Metadata: map[string]string{"state": consensusState, "target": danglingNode},
			})
		}
	}

	return nil
}

func cnameResolutionEvidence(status core.DNSStatus, matchedProvider string) (string, string, int, int) {
	evType := "CNAME_RESOLUTION_INCONCLUSIVE"
	description := fmt.Sprintf("A ausência de endereço no último CNAME não foi conclusiva (%s)", status)
	weight, evidenceConfidence := 0, 30

	switch status {
	case core.DNSStatusNXDomain:
		evType = "CNAME_NXDOMAIN"
		description = "O último nó da cadeia CNAME retornou NXDOMAIN"
		weight, evidenceConfidence = 30, 90
	case core.DNSStatusNoData:
		evType = "CNAME_UNRESOLVABLE"
		description = "O último nó da cadeia CNAME não possui A nem AAAA"
		weight, evidenceConfidence = 30, 90
	default:
		return evType, description, weight, evidenceConfidence
	}

	if matchedProvider != "" {
		evType = "CNAME_DANGLING"
		description = fmt.Sprintf("CNAME órfão confirmado apontando para provedor conhecido: %s", matchedProvider)
	}
	return evType, description, weight, evidenceConfidence
}
