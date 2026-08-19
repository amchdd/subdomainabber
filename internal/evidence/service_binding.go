package evidence

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/amchdd/subdomainabber/internal/core"
	"github.com/amchdd/subdomainabber/internal/domainutil"
	"github.com/amchdd/subdomainabber/pkg/signatures"
)

type ServiceBindingCollector struct {
	signatures []signatures.Fingerprint
}

func NewServiceBindingCollector(catalog []signatures.Fingerprint) *ServiceBindingCollector {
	return &ServiceBindingCollector{signatures: catalog}
}

func (*ServiceBindingCollector) Phase() CollectorPhase { return PhaseProviderDiscovery }

func (collector *ServiceBindingCollector) Collect(_ context.Context, analysis *core.HostAnalysis) error {
	if analysis == nil {
		return nil
	}
	if len(analysis.DNS.DNAME) > 0 {
		analysis.AddTestedVector("DNAME")
		for _, record := range analysis.DNS.DNAME {
			metadata := map[string]string{"owner": record.Owner, "target": record.Target}
			if alias := synthesizeDNAME(analysis.Host, record); alias != "" {
				metadata["synthesized_alias"] = alias
			}
			analysis.AddEvidence(core.Evidence{Type: "DNAME_ALIAS", Source: "DNS", Description: "O DNS publicou uma substituição DNAME.", Confidence: 100, Metadata: metadata})
		}
	}
	collector.addBindings(analysis, "HTTPS", analysis.DNS.HTTPS)
	collector.addBindings(analysis, "SVCB", analysis.DNS.SVCB)
	return nil
}

func (collector *ServiceBindingCollector) addBindings(analysis *core.HostAnalysis, vector string, bindings []core.ServiceBinding) {
	if len(bindings) == 0 {
		return
	}
	analysis.AddTestedVector(vector)
	for _, binding := range bindings {
		mode := "service"
		if binding.Priority == 0 {
			mode = "alias"
		}
		metadata := map[string]string{"target": binding.Target, "priority": strconv.Itoa(int(binding.Priority)), "mode": mode}
		for key, value := range binding.Params {
			metadata["param_"+key] = value
		}
		analysis.AddEvidence(core.Evidence{
			Type: vector + "_BINDING", Source: "DNS",
			Description: fmt.Sprintf("O DNS publicou um binding %s em modo %s.", vector, mode),
			Confidence:  100, Metadata: metadata,
		})
		collector.matchProvider(analysis, vector, binding.Target)
	}
}

func (collector *ServiceBindingCollector) matchProvider(analysis *core.HostAnalysis, vector, target string) {
	if target == "" || target == "." {
		return
	}
	for _, signature := range collector.signatures {
		if _, matched := matchingCNAME([]string{target}, signature.CNames); !matched {
			continue
		}
		id := providerID(signature.Service)
		analysis.AddEvidence(core.Evidence{
			Type: vector + "_PROVIDER_MATCH", Source: signature.Service,
			Description: "O destino do binding corresponde a um provedor conhecido.",
			Confidence:  80, Metadata: map[string]string{"target": target, "provider_id": id},
		})
		analysis.AddProviderCandidate(core.ProviderCandidate{ProviderID: id, Service: signature.Service, Vector: vector, Resource: target})
		return
	}
}

func synthesizeDNAME(host string, record core.DNAMERecord) string {
	host, err := domainutil.NormalizeHostname(host)
	if err != nil || !domainutil.MatchDNSName(host, record.Owner) || strings.EqualFold(host, record.Owner) {
		return ""
	}
	prefix := strings.TrimSuffix(host, "."+record.Owner)
	if prefix == "" {
		return ""
	}
	return prefix + "." + record.Target
}
