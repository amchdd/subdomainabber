package classification

import (
	"strings"
	"time"

	"github.com/amchdd/subdomainabber/internal/core"
	"github.com/amchdd/subdomainabber/internal/dns"
)

// DetectUnknownProvider registra um provedor externo que ainda não consta no catálogo.
func DetectUnknownProvider(analysis *core.HostAnalysis) {
	// Uma correspondência direta com o catálogo dispensa a descoberta.
	hasKnownProvider := false
	orphanSignals := 0

	for _, ev := range analysis.Evidences {
		if strings.Contains(ev.Type, "PROVIDER_MATCH") {
			// ASN e nuvem fornecem contexto, mas não identificam o serviço de forma conclusiva.
			if ev.Type != "CLOUD_PROVIDER_MATCH" && ev.Type != "ASN_PROVIDER_MATCH" {
				hasKnownProvider = true
			}
		}

		if ev.Type == "CNAME_DANGLING" || ev.Type == "CNAME_UNRESOLVABLE" || ev.Type == "MX_BROKEN" || ev.Type == "SRV_BROKEN" || ev.Type == "NS_ORPHANED" || ev.Type == "CNAME_NXDOMAIN" {
			orphanSignals++
		}
	}

	if hasKnownProvider {
		return
	}

	// Usa o último CNAME ou, na ausência dele, o primeiro servidor NS externo.
	var unknownTarget string
	if len(analysis.DNS.CNAME) > 0 {
		unknownTarget = analysis.DNS.CNAME[len(analysis.DNS.CNAME)-1]
	} else if len(analysis.DNS.NS) > 0 {
		unknownTarget = analysis.DNS.NS[0]
	}

	if unknownTarget == "" {
		return
	}

	unknownRoot := dns.ExtractRootDomain(unknownTarget)
	hostRoot := dns.ExtractRootDomain(analysis.Host)

	// Um provedor desconhecido precisa pertencer a outro domínio registrável.
	if unknownRoot != "" && unknownRoot != hostRoot {
		severity := "LOW"

		// Um sinal de abandono eleva a prioridade da revisão manual.
		if orphanSignals > 0 {
			severity = "HIGH"
		} else {
			// Provedores externos sem sinal de abandono ainda podem ampliar o catálogo.
			severity = "MEDIUM"
		}

		analysis.UnknownProvider = &core.UnknownProviderEvidence{
			RootDomain:   unknownRoot,
			Frequency:    1,
			Severity:     severity,
			FirstSeen:    time.Now(),
			LastSeen:     time.Now(),
			ExampleHosts: []string{analysis.Host},
		}
	}
}
