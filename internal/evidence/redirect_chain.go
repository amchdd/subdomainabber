package evidence

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/amchdd/subdomainabber/internal/core"
	"github.com/amchdd/subdomainabber/pkg/signatures"
)

const maxRedirectDepth = 20

type webResolver interface {
	ResolveCNAMEChain(context.Context, string) ([]string, error)
	ResolveAddressStatus(context.Context, string) core.DNSStatus
}

type webAddressResolver interface {
	ResolveA(context.Context, string) ([]string, error)
	ResolveAAAA(context.Context, string) ([]string, error)
}

type RedirectCollector struct {
	resolver webResolver
	client   *http.Client
	depth    int
	sigs     []signatures.Fingerprint
}

func NewRedirectCollector(resolver webResolver, client *http.Client, depth int) *RedirectCollector {
	if depth < 1 {
		depth = 10
	}
	if depth > maxRedirectDepth {
		depth = maxRedirectDepth
	}
	return &RedirectCollector{
		resolver: resolver,
		client:   noRedirectClient(client),
		depth:    depth,
	}
}

func (collector *RedirectCollector) Phase() CollectorPhase { return PhaseImpact }

func (collector *RedirectCollector) SetSignatures(sigs []signatures.Fingerprint) {
	collector.sigs = append([]signatures.Fingerprint(nil), sigs...)
}

func (collector *RedirectCollector) Collect(ctx context.Context, analysis *core.HostAnalysis) error {
	if analysis == nil || collector.client == nil {
		return nil
	}
	analysis.AddTestedVector("REDIRECT_CHAIN")
	for _, scheme := range []string{"http", "https"} {
		observation, ok := analysis.HTTPObservation(scheme)
		if !ok || !observation.Complete || !isRedirectStatus(observation.StatusCode) {
			continue
		}
		collector.collectScheme(ctx, analysis, scheme)
	}
	return nil
}

func (collector *RedirectCollector) collectScheme(ctx context.Context, analysis *core.HostAnalysis, scheme string) {
	current := &url.URL{Scheme: scheme, Host: analysis.Host, Path: "/"}
	chain := core.RedirectChain{Scheme: scheme, FinalURL: current.String()}
	seen := make(map[string]struct{})
	details := make(map[string]core.RedirectHop)

	for index := 0; index < collector.depth; index++ {
		identity := *current
		identity.Scheme = strings.ToLower(identity.Scheme)
		identity.Host = strings.ToLower(identity.Host)
		identity.Fragment, identity.RawFragment = "", ""
		key := identity.String()
		if _, duplicate := seen[key]; duplicate {
			chain.StoppedReason = "REDIRECT_LOOP"
			break
		}
		seen[key] = struct{}{}

		hop := collector.redirectHop(ctx, analysis, index, current, details)
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, current.String(), nil)
		if err != nil {
			chain.StoppedReason = "INVALID_URL"
			break
		}
		response, err := collector.client.Do(request)
		if err != nil {
			chain.Hops = append(chain.Hops, hop)
			chain.StoppedReason = "TRANSPORT_ERROR"
			analysis.AddEvidence(core.Evidence{
				Type: "REDIRECT_DESTINATION_TRANSPORT_ERROR", Source: scheme,
				Description: "A coleta do destino da cadeia falhou no transporte.",
				Weight:      0, Confidence: 100,
				Metadata: map[string]string{"target_url": current.String(), "target_host": hop.Hostname},
			})
			break
		}
		var body []byte
		if response.Body != nil {
			body, _ = io.ReadAll(io.LimitReader(response.Body, 32<<10))
			_ = response.Body.Close()
		}

		location := response.Header.Get("Location")
		hop.StatusCode = response.StatusCode
		hop.Location = location
		hop.ResponseKind = responseKind(response.StatusCode, response.Header, body)
		hop.EdgeProvider = edgeProvider(response.Header, body)
		hop.Provider, hop.MatchedFingerprint = collector.redirectFingerprint(hop, response, body)
		chain.Hops = append(chain.Hops, hop)
		chain.FinalURL = current.String()
		if !isRedirectStatus(response.StatusCode) || location == "" {
			chain.StoppedReason = "FINAL_RESPONSE"
			if hop.MatchedFingerprint != "" {
				chain.StoppedReason = "DESTINATION_PROVIDER_ERROR"
				analysis.AddEvidence(core.Evidence{
					Type: "REDIRECT_DESTINATION_PROVIDER_ERROR", Source: scheme,
					Description: "O destino final apresentou uma assinatura específica de recurso ausente no provedor.",
					Weight:      0, Confidence: 95,
					Metadata: map[string]string{
						"target_url": hop.URL, "target_host": hop.Hostname, "provider": hop.Provider,
						"matched_fingerprint": hop.MatchedFingerprint, "http_status": strconv.Itoa(hop.StatusCode),
					},
				})
			}
			break
		}

		next, err := current.Parse(location)
		if err != nil || next.Hostname() == "" || next.User != nil {
			chain.StoppedReason = "INVALID_LOCATION"
			break
		}
		if next.Scheme != "http" && next.Scheme != "https" {
			chain.FinalURL = next.String()
			chain.StoppedReason = "UNSUPPORTED_PROTOCOL"
			analysis.AddEvidence(core.Evidence{
				Type: "REDIRECT_UNSUPPORTED_PROTOCOL", Source: scheme,
				Description: "O cabeçalho Location usa um protocolo que o analisador HTTP não acompanha.",
				Weight:      0, Confidence: 100,
				Metadata: map[string]string{"target_url": next.String(), "scheme": next.Scheme},
			})
			break
		}
		nextHost := normalizeWebHost(next.Hostname())
		nextHop := collector.redirectHop(ctx, analysis, index+1, next, details)
		if nextHop.DNSStatus != core.DNSStatusResolved {
			chain.Hops = append(chain.Hops, nextHop)
			chain.FinalURL = next.String()
			chain.StoppedReason = "DESTINATION_" + string(nextHop.DNSStatus)
			analysis.AddEvidence(core.Evidence{
				Type: "REDIRECT_DESTINATION_" + string(nextHop.DNSStatus), Source: scheme,
				Description: "O destino publicado no cabeçalho Location não possui resolução DNS utilizável.",
				Weight:      0, Confidence: 100,
				Metadata: map[string]string{
					"target_url": next.String(), "target_host": nextHost,
					"dns_status": string(nextHop.DNSStatus), "cname": strings.Join(nextHop.CNAME, ","),
				},
			})
			break
		}
		current = next
		if index == collector.depth-1 {
			chain.FinalURL = next.String()
			chain.StoppedReason = "MAX_DEPTH"
			analysis.AddEvidence(core.Evidence{
				Type: "REDIRECT_DEPTH_LIMIT", Source: scheme,
				Description: fmt.Sprintf("A cadeia atingiu o limite configurado de %d hops.", collector.depth),
				Weight:      0, Confidence: 100,
				Metadata: map[string]string{"depth": strconv.Itoa(collector.depth), "target_url": next.String()},
			})
		}
	}

	for _, hop := range chain.Hops {
		analysis.AddEvidence(core.Evidence{
			Type: "HTTP_REDIRECT_HOP", Source: scheme,
			Description: fmt.Sprintf("Hop %d registrou o destino %s.", hop.Index, hop.URL),
			Weight:      0, Confidence: 100,
			Metadata: map[string]string{
				"index": strconv.Itoa(hop.Index), "url": hop.URL,
				"hostname": hop.Hostname, "scheme": hop.Scheme,
				"status": strconv.Itoa(hop.StatusCode), "location": hop.Location,
				"dns_status": string(hop.DNSStatus), "provider": hop.Provider,
				"cname": strings.Join(hop.CNAME, ","), "addresses": strings.Join(hop.Addresses, ","),
				"response_kind": hop.ResponseKind, "edge_provider": hop.EdgeProvider,
				"matched_fingerprint": hop.MatchedFingerprint,
			},
		})
	}
	analysis.SetRedirectChain(scheme, chain)
}

func (collector *RedirectCollector) redirectFingerprint(hop core.RedirectHop, response *http.Response, body []byte) (string, string) {
	if response == nil || len(body) == 0 {
		return hop.Provider, ""
	}
	hosts := append([]string{hop.Hostname}, hop.CNAME...)
	for index := range collector.sigs {
		signature := &collector.sigs[index]
		if signature.Fingerprint == "" || isGenericHTTPFingerprint(signature.Fingerprint) || fingerprintSpecificity(signature.Fingerprint) < minimumTakeoverFingerprintSpecificity {
			continue
		}
		if _, matched := matchingCNAME(hosts, signature.CNames); !matched {
			continue
		}
		if signature.HTTPStatus != nil && *signature.HTTPStatus != response.StatusCode {
			continue
		}
		headersMatch := true
		for name, value := range signature.Headers {
			observed := response.Header.Get(name)
			if observed == "" || (value != "" && !strings.Contains(strings.ToLower(observed), strings.ToLower(value))) {
				headersMatch = false
				break
			}
		}
		if headersMatch && signatures.MatchesFingerprint(string(body), signature) {
			return signature.Service, signature.Fingerprint
		}
	}
	return hop.Provider, ""
}

func (collector *RedirectCollector) redirectHop(ctx context.Context, analysis *core.HostAnalysis, index int, target *url.URL, cache map[string]core.RedirectHop) core.RedirectHop {
	host := normalizeWebHost(target.Hostname())
	hop := core.RedirectHop{Index: index, URL: target.String(), Hostname: host, Scheme: strings.ToLower(target.Scheme)}
	if cached, ok := cache[host]; ok {
		hop.DNSStatus = cached.DNSStatus
		hop.CNAME = append([]string(nil), cached.CNAME...)
		hop.Addresses = append([]string(nil), cached.Addresses...)
		hop.Provider = cached.Provider
		return hop
	}
	if sameWebHost(host, analysis.Host) {
		hop.DNSStatus = core.DNSStatusResolved
		hop.CNAME = append([]string(nil), analysis.DNS.CNAME...)
		hop.Addresses = append(append([]string(nil), analysis.DNS.A...), analysis.DNS.AAAA...)
	} else if collector.resolver != nil {
		hop.CNAME, _ = collector.resolver.ResolveCNAMEChain(ctx, host)
		finalHost := host
		if len(hop.CNAME) > 0 {
			finalHost = hop.CNAME[len(hop.CNAME)-1]
		}
		hop.DNSStatus = collector.resolver.ResolveAddressStatus(ctx, finalHost)
		if resolver, ok := collector.resolver.(webAddressResolver); ok && hop.DNSStatus == core.DNSStatusResolved {
			ipv4, _ := resolver.ResolveA(ctx, finalHost)
			ipv6, _ := resolver.ResolveAAAA(ctx, finalHost)
			hop.Addresses = append(ipv4, ipv6...)
		}
	}
	for _, candidate := range analysis.ProviderCandidates {
		if sameWebHost(candidate.CNAME, host) || containsWebHost(hop.CNAME, candidate.CNAME) {
			hop.Provider = candidate.Service
			break
		}
	}
	if hop.Provider == "" {
		for index := range collector.sigs {
			if collector.sigs[index].Service == "" {
				continue
			}
			if _, matched := matchingCNAME(append([]string{host}, hop.CNAME...), collector.sigs[index].CNames); matched {
				hop.Provider = collector.sigs[index].Service
				break
			}
		}
	}
	cache[host] = hop
	return hop
}

func noRedirectClient(client *http.Client) *http.Client {
	if client == nil {
		return nil
	}
	copy := *client
	copy.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &copy
}

func normalizedHostSet(hosts []string) map[string]struct{} {
	set := make(map[string]struct{}, len(hosts))
	for _, host := range hosts {
		if normalized := normalizeWebHost(host); normalized != "" {
			set[normalized] = struct{}{}
		}
	}
	return set
}

func normalizeWebHost(host string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
}

func containsWebHost(hosts []string, target string) bool {
	for _, host := range hosts {
		if sameWebHost(host, target) {
			return true
		}
	}
	return false
}

func sameWebHost(left, right string) bool {
	return normalizeWebHost(left) == normalizeWebHost(right)
}

func isRedirectStatus(status int) bool {
	return status == http.StatusMovedPermanently || status == http.StatusFound ||
		status == http.StatusSeeOther || status == http.StatusTemporaryRedirect || status == http.StatusPermanentRedirect
}
