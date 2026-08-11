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
)

const maxRedirectDepth = 20

type webResolver interface {
	ResolveCNAMEChain(context.Context, string) ([]string, error)
	ResolveAddressStatus(context.Context, string) core.DNSStatus
}

type RedirectCollector struct {
	resolver webResolver
	client   *http.Client
	depth    int
	allowed  map[string]struct{}
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
		allowed:  make(map[string]struct{}),
	}
}

func (collector *RedirectCollector) Phase() CollectorPhase { return PhaseImpact }

func (collector *RedirectCollector) SetAllowedHosts(hosts []string) {
	collector.allowed = normalizedHostSet(hosts)
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
	followed := false

	for index := 0; index < collector.depth; index++ {
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, current.String(), nil)
		if err != nil {
			chain.StoppedReason = "INVALID_URL"
			break
		}
		response, err := collector.client.Do(request)
		if err != nil {
			chain.StoppedReason = "TRANSPORT_ERROR"
			break
		}
		if response.Body != nil {
			_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 32<<10))
			_ = response.Body.Close()
		}

		location := response.Header.Get("Location")
		chain.Hops = append(chain.Hops, core.RedirectHop{
			Index: index + 1, URL: current.String(), StatusCode: response.StatusCode, Location: location,
		})
		chain.FinalURL = current.String()
		if !isRedirectStatus(response.StatusCode) || location == "" {
			if followed && (response.StatusCode == http.StatusNotFound || response.StatusCode == http.StatusGone) {
				collector.addDanglingEvidence(analysis, normalizeWebHost(current.Hostname()), current.String(), core.DNSStatusResolved, response.StatusCode)
			}
			break
		}

		next, err := current.Parse(location)
		if err != nil || (next.Scheme != "http" && next.Scheme != "https") || next.Hostname() == "" || next.User != nil {
			chain.StoppedReason = "INVALID_LOCATION"
			break
		}
		nextHost := normalizeWebHost(next.Hostname())
		if !sameWebHost(nextHost, analysis.Host) {
			if _, ok := collector.allowed[nextHost]; !ok {
				chain.FinalURL = next.String()
				chain.StoppedReason = "OUT_OF_SCOPE"
				analysis.AddEvidence(core.Evidence{
					Type: "REDIRECT_TARGET_OUT_OF_SCOPE", Source: scheme,
					Description: "A cadeia apontou para um hostname não autorizado para sondagem adicional.",
					Weight:      0, Confidence: 100,
					Metadata: map[string]string{"target_url": next.String(), "target_host": nextHost},
				})
				break
			}
			status := collector.targetStatus(ctx, nextHost)
			if status == core.DNSStatusNXDomain || status == core.DNSStatusNoData {
				chain.FinalURL = next.String()
				chain.StoppedReason = "DANGLING_TARGET"
				collector.addDanglingEvidence(analysis, nextHost, next.String(), status, 0)
				break
			}
		}
		followed = true
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
			Description: fmt.Sprintf("Hop %d respondeu com HTTP %d.", hop.Index, hop.StatusCode),
			Weight:      0, Confidence: 100,
			Metadata: map[string]string{
				"index": strconv.Itoa(hop.Index), "url": hop.URL,
				"status": strconv.Itoa(hop.StatusCode), "location": hop.Location,
			},
		})
	}
	analysis.SetRedirectChain(scheme, chain)
}

func (collector *RedirectCollector) targetStatus(ctx context.Context, host string) core.DNSStatus {
	if collector.resolver == nil {
		return core.DNSStatusError
	}
	chain, _ := collector.resolver.ResolveCNAMEChain(ctx, host)
	if len(chain) > 0 {
		host = chain[len(chain)-1]
	}
	return collector.resolver.ResolveAddressStatus(ctx, host)
}

func (collector *RedirectCollector) addDanglingEvidence(analysis *core.HostAnalysis, host, target string, status core.DNSStatus, httpStatus int) {
	metadata := map[string]string{"target_host": host, "target_url": target, "dns_status": string(status)}
	if httpStatus != 0 {
		metadata["http_status"] = strconv.Itoa(httpStatus)
	}
	analysis.AddEvidence(core.Evidence{
		Type: "DANGLING_REDIRECT", Source: "HTTP",
		Description: "O destino permitido da cadeia não possui resolução utilizável ou responde como recurso removido.",
		Weight:      20, Confidence: 90, Metadata: metadata,
	})
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

func sameWebHost(left, right string) bool {
	return normalizeWebHost(left) == normalizeWebHost(right)
}

func isRedirectStatus(status int) bool {
	return status == http.StatusMovedPermanently || status == http.StatusFound ||
		status == http.StatusSeeOther || status == http.StatusTemporaryRedirect || status == http.StatusPermanentRedirect
}
