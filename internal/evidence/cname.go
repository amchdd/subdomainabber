package evidence

import (
	"context"
	"fmt"

	"github.com/amchdd/subdomainabber/internal/core"
	"github.com/amchdd/subdomainabber/internal/dns"
	"github.com/amchdd/subdomainabber/internal/domainutil"
	"github.com/amchdd/subdomainabber/pkg/signatures"
)

// CNAMECollector cruza a cadeia de CNAMEs com o catálogo de assinaturas e
// acrescenta evidências de compatibilidade com o serviço.
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

	// Avalia a cadeia inteira em busca de uma correspondência com o provedor.
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
					confidence = 80 // Base para correspondência de provedor em CNAME
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

				// Registra a expectativa de NXDOMAIN declarada para o serviço.
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

		// O último nó da cadeia é o candidato a referência pendente.
		if i == len(analysis.DNS.CNAME)-1 {
			danglingNode = cnameClean
		}
	}

	// Verifica se o destino final da cadeia possui endereços IP.
	if danglingNode != "" && len(analysis.DNS.A) == 0 && len(analysis.DNS.AAAA) == 0 {
		// Consulta o último nó para preservar o estado DNS exato.
		status := c.resolver.ResolveAddressStatus(ctx, danglingNode)

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
