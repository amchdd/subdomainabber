package evidence

import (
	"context"
	"fmt"
	"net"
	"strings"

	"github.com/amchdd/subdomainabber/internal/core"
	"github.com/amchdd/subdomainabber/internal/dns"
	"github.com/amchdd/subdomainabber/pkg/signatures"
)

type IPCollector struct {
	resolver *dns.Resolver
	sigs     []signatures.Fingerprint
}

var cloudASNProviders = map[string]struct{ id, name string }{
	"16509":  {"aws", "Amazon Web Services"},
	"14618":  {"aws", "Amazon Web Services"},
	"8075":   {"microsoft-azure", "Microsoft Azure"},
	"15169":  {"google-cloud", "Google Cloud"},
	"396982": {"google-cloud", "Google Cloud"},
	"13335":  {"cloudflare", "Cloudflare"},
}

func NewIPCollector(resolver *dns.Resolver, sigs []signatures.Fingerprint) *IPCollector {
	return &IPCollector{resolver: resolver, sigs: sigs}
}

func (c *IPCollector) Collect(ctx context.Context, analysis *core.HostAnalysis) error {
	analysis.AddTestedVector("A_AAAA_ASN")
	c.processIPs(ctx, analysis, analysis.DNS.A, "A")
	c.processIPs(ctx, analysis, analysis.DNS.AAAA, "AAAA")
	return nil
}

func (c *IPCollector) processIPs(ctx context.Context, analysis *core.HostAnalysis, ips []string, recordType string) {
	for _, ipString := range ips {
		ip := net.ParseIP(ipString)
		if ip == nil || ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsUnspecified() {
			continue
		}
		asnData, err := c.lookupASN(ctx, ipString, recordType)
		if err != nil || asnData == "" {
			continue
		}
		asn := strings.TrimSpace(strings.Split(asnData, "|")[0])
		candidate := core.CloudIPCandidate{
			IP: ipString, RecordType: recordType, ASN: asn,
			Reachability: "NOT_TESTED", Claimability: core.ClaimabilityManualReview,
		}
		if provider, ok := cloudASNProviders[asn]; ok {
			candidate.ProviderID, candidate.Provider = provider.id, provider.name
		}
		for _, sig := range c.sigs {
			for _, fingerprint := range sig.ASNFingerprints {
				if strings.Contains(strings.ToLower(asnData), strings.ToLower(fingerprint)) {
					candidate.Provider, candidate.ProviderID = sig.Service, providerID(sig.Service)
					break
				}
			}
		}
		metadata := map[string]string{
			"ip_address": ipString, "record_type": recordType, "asn": asn,
			"asn_data": asnData, "reachability": candidate.Reachability,
			"claimability": string(candidate.Claimability),
		}
		if candidate.ProviderID != "" {
			metadata["provider_id"] = candidate.ProviderID
			analysis.AddProviderCandidate(core.ProviderCandidate{
				ProviderID: candidate.ProviderID, Service: candidate.Provider,
				Vector: recordType, Resource: ipString,
				Metadata: map[string]string{"asn": asn, "reachability": candidate.Reachability},
			})
			analysis.AddEvidence(core.Evidence{
				Type: "CLOUD_IP_CONTEXT", Source: candidate.Provider,
				Description: fmt.Sprintf("O registro %s aponta para %s no ASN de nuvem %s; não há evidência de que o endereço possa ser realocado", recordType, ipString, asn),
				Weight:      1, Confidence: 90, Metadata: metadata,
			})
		} else {
			analysis.AddEvidence(core.Evidence{
				Type: "ASN_MATCH", Source: "Team Cymru",
				Description: fmt.Sprintf("O IP %s pertence ao ASN %s", ipString, asn),
				Weight:      1, Confidence: 60, Metadata: metadata,
			})
		}
		analysis.CloudIPCandidates = append(analysis.CloudIPCandidates, candidate)
	}
}

func (c *IPCollector) lookupASN(ctx context.Context, ipString, recordType string) (string, error) {
	ip := net.ParseIP(ipString)
	if ip == nil {
		return "", fmt.Errorf("IP inválido")
	}
	var owner string
	if recordType == "A" {
		owner = reverseIPv4(ip.To4()) + ".origin.asn.cymru.com"
	} else {
		owner = reverseIPv6(ip.To16()) + ".origin6.asn.cymru.com"
	}
	txts, err := c.resolver.ResolveTXT(ctx, owner)
	if err != nil || len(txts) == 0 {
		return "", err
	}
	return txts[0], nil
}

func reverseIPv4(ip net.IP) string { return fmt.Sprintf("%d.%d.%d.%d", ip[3], ip[2], ip[1], ip[0]) }

func reverseIPv6(ip net.IP) string {
	hex := fmt.Sprintf("%032x", ip)
	var reversed strings.Builder
	for index := len(hex) - 1; index >= 0; index-- {
		reversed.WriteByte(hex[index])
		if index > 0 {
			reversed.WriteByte('.')
		}
	}
	return reversed.String()
}
