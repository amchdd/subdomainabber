package evidence

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/amchdd/subdomainabber/internal/core"
	"github.com/amchdd/subdomainabber/internal/domainutil"
	"github.com/amchdd/subdomainabber/pkg/signatures"
	"golang.org/x/net/html"
)

const maxWebDependencies = 32

type dependencyRef struct {
	URL       string
	Host      string
	Kind      string
	Source    string
	Directive string
}

type WebDependencyCollector struct {
	resolver webResolver
	client   *http.Client
	allowed  map[string]struct{}
	sigs     []signatures.Fingerprint
}

func NewWebDependencyCollector(resolver webResolver, client *http.Client) *WebDependencyCollector {
	return &WebDependencyCollector{resolver: resolver, client: noRedirectClient(client), allowed: make(map[string]struct{})}
}

func (*WebDependencyCollector) Phase() CollectorPhase { return PhaseImpact }

func (collector *WebDependencyCollector) SetAllowedHosts(hosts []string) {
	collector.allowed = normalizedHostSet(hosts)
}

func (collector *WebDependencyCollector) SetSignatures(sigs []signatures.Fingerprint) {
	collector.sigs = append([]signatures.Fingerprint(nil), sigs...)
}

func (collector *WebDependencyCollector) Collect(ctx context.Context, analysis *core.HostAnalysis) error {
	if analysis == nil || collector.resolver == nil {
		return nil
	}
	analysis.AddTestedVector("WEB_DEPENDENCIES")
	refs := collector.references(analysis)
	for index, ref := range refs {
		if index >= maxWebDependencies {
			break
		}
		if _, ok := collector.allowed[ref.Host]; !ok {
			continue
		}
		collector.inspect(ctx, analysis, ref)
	}
	return nil
}

func (collector *WebDependencyCollector) references(analysis *core.HostAnalysis) []dependencyRef {
	seen := make(map[string]struct{})
	var refs []dependencyRef
	appendRef := func(ref dependencyRef) {
		if ref.Host == "" || sameWebHost(ref.Host, analysis.Host) {
			return
		}
		key := ref.Source + "|" + ref.Kind + "|" + ref.URL
		if _, ok := seen[key]; ok {
			return
		}
		seen[key] = struct{}{}
		refs = append(refs, ref)
	}

	for _, scheme := range []string{"https", "http"} {
		observation, ok := analysis.HTTPObservation(scheme)
		if !ok || !observation.Complete {
			continue
		}
		base, _ := url.Parse(scheme + "://" + analysis.Host + "/")
		for _, ref := range extractHTMLDependencies(base, observation.Body) {
			appendRef(ref)
		}
		for _, value := range headerValues(observation.Headers, "Content-Security-Policy") {
			for _, ref := range collector.extractCSPDependencies(scheme, value) {
				appendRef(ref)
			}
		}
	}
	return refs
}

func (collector *WebDependencyCollector) inspect(ctx context.Context, analysis *core.HostAnalysis, ref dependencyRef) {
	chain, _ := collector.resolver.ResolveCNAMEChain(ctx, ref.Host)
	target := ref.Host
	if len(chain) > 0 {
		target = chain[len(chain)-1]
	}
	status := collector.resolver.ResolveAddressStatus(ctx, target)
	dependency := core.WebDependency{
		URL: ref.URL, Host: ref.Host, Kind: ref.Kind, Source: ref.Source,
		Directive: ref.Directive, CNAME: chain, DNSStatus: status,
	}
	dependency.Provider = collector.provider(ref.Host, chain)
	if dependency.Provider != "" && (status == core.DNSStatusNXDomain || status == core.DNSStatusNoData) {
		dependency.Dangling = true
		collector.addBrokenDependency(analysis, dependency)
		analysis.AddWebDependency(dependency)
		return
	}
	if status == core.DNSStatusResolved && ref.Source == "HTML" && isAssetKind(ref.Kind) && collector.client != nil {
		dependency.HTTPStatus = collector.assetStatus(ctx, ref.URL)
		if dependency.HTTPStatus == http.StatusNotFound || dependency.HTTPStatus == http.StatusGone {
			analysis.AddEvidence(core.Evidence{
				Type: "DEAD_ASSET_HTTP", Source: ref.Kind,
				Description: "Uma página observada referencia um asset permitido que responde como removido.",
				Weight:      0, Confidence: 90,
				Metadata: dependencyMetadata(dependency),
			})
		}
	}
	analysis.AddWebDependency(dependency)
}

func (collector *WebDependencyCollector) provider(host string, chain []string) string {
	names := append([]string{host}, chain...)
	for _, sig := range collector.sigs {
		if sig.CheckType == "ns" || sig.CheckType == "a" || sig.CheckType == "mx" {
			continue
		}
		if _, ok := matchingCNAME(names, sig.CNames); ok {
			return sig.Service
		}
	}
	return ""
}

func (collector *WebDependencyCollector) addBrokenDependency(analysis *core.HostAnalysis, dependency core.WebDependency) {
	evidenceType := "SUBRESOURCE_DANGLING"
	description := "Uma página observada referencia um subdomínio permitido sem resolução utilizável."
	if dependency.Source == "CSP" {
		evidenceType = "CSP_DANGLING_DEPENDENCY"
		description = "A política CSP confia em um subdomínio permitido sem resolução utilizável."
	}
	metadata := dependencyMetadata(dependency)
	analysis.AddEvidence(core.Evidence{
		Type: evidenceType, Source: dependency.Source, Description: description,
		Weight: 20, Confidence: 90, Metadata: metadata,
	})
	if dependency.Source == "HTML" && isAssetKind(dependency.Kind) {
		analysis.AddEvidence(core.Evidence{
			Type: "DEAD_ASSET_REFERENCE", Source: dependency.Kind,
			Description: "Uma página observada referencia um asset hospedado em um subdomínio dangling.",
			Weight:      20, Confidence: 90, Metadata: metadata,
		})
	}
}

func (collector *WebDependencyCollector) assetStatus(ctx context.Context, target string) int {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return 0
	}
	response, err := collector.client.Do(request)
	if err != nil {
		return 0
	}
	if response.Body != nil {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 32<<10))
		_ = response.Body.Close()
	}
	return response.StatusCode
}

func extractHTMLDependencies(base *url.URL, body []byte) []dependencyRef {
	document, err := html.Parse(strings.NewReader(string(body)))
	if err != nil {
		return nil
	}
	var refs []dependencyRef
	var walk func(*html.Node)
	walk = func(node *html.Node) {
		if node.Type == html.ElementNode {
			attribute, kind := dependencyAttribute(node)
			if attribute != "" {
				for _, item := range node.Attr {
					if strings.EqualFold(item.Key, attribute) {
						if ref, ok := dependencyURL(base, item.Val, kind, "HTML", ""); ok {
							refs = append(refs, ref)
						}
					}
				}
			}
		}
		for child := node.FirstChild; child != nil; child = child.NextSibling {
			walk(child)
		}
	}
	walk(document)
	return refs
}

func dependencyAttribute(node *html.Node) (string, string) {
	switch strings.ToLower(node.Data) {
	case "script":
		return "src", "script"
	case "link":
		if linkAsset(node) {
			return "href", "stylesheet"
		}
	case "img":
		return "src", "image"
	case "iframe", "frame":
		return "src", "frame"
	case "source", "audio", "video":
		return "src", "media"
	case "object":
		return "data", "object"
	default:
		return "", ""
	}
	return "", ""
}

func (collector *WebDependencyCollector) extractCSPDependencies(scheme, policy string) []dependencyRef {
	var refs []dependencyRef
	for _, rawDirective := range strings.Split(policy, ";") {
		fields := strings.Fields(rawDirective)
		if len(fields) < 2 || !trackedCSPDirective(fields[0]) {
			continue
		}
		for _, source := range fields[1:] {
			if strings.HasPrefix(source, "*.") {
				for host := range collector.allowed {
					if domainutil.MatchDNSName(host, source) {
						refs = append(refs, dependencyRef{URL: scheme + "://" + host, Host: host, Kind: "csp", Source: "CSP", Directive: fields[0]})
					}
				}
				continue
			}
			if ref, ok := dependencyURL(nil, normalizeCSPSource(scheme, source), "csp", "CSP", fields[0]); ok {
				refs = append(refs, ref)
			}
		}
	}
	return refs
}

func normalizeCSPSource(scheme, source string) string {
	source = strings.TrimSpace(source)
	if source == "" || strings.HasPrefix(source, "'") || source == "*" ||
		strings.HasSuffix(source, ":") || strings.HasPrefix(source, "data:") || strings.HasPrefix(source, "blob:") {
		return ""
	}
	if strings.HasPrefix(source, "//") {
		return scheme + ":" + source
	}
	if !strings.Contains(source, "://") && strings.Contains(source, ".") && !strings.Contains(source, "/") {
		return scheme + "://" + source
	}
	return source
}

func dependencyURL(base *url.URL, raw, kind, source, directive string) (dependencyRef, bool) {
	if strings.TrimSpace(raw) == "" {
		return dependencyRef{}, false
	}
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return dependencyRef{}, false
	}
	if base != nil {
		parsed = base.ResolveReference(parsed)
	}
	if (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Hostname() == "" || parsed.User != nil {
		return dependencyRef{}, false
	}
	parsed.Fragment = ""
	host := normalizeWebHost(parsed.Hostname())
	return dependencyRef{URL: parsed.String(), Host: host, Kind: kind, Source: source, Directive: directive}, true
}

func trackedCSPDirective(directive string) bool {
	switch strings.ToLower(directive) {
	case "default-src", "script-src", "style-src", "img-src", "font-src", "connect-src", "frame-src", "child-src", "worker-src", "media-src":
		return true
	default:
		return false
	}
}

func headerValues(headers map[string][]string, name string) []string {
	for key, values := range headers {
		if strings.EqualFold(key, name) {
			return values
		}
	}
	return nil
}

func isAssetKind(kind string) bool {
	switch kind {
	case "script", "stylesheet", "image", "media":
		return true
	default:
		return false
	}
}

func dependencyMetadata(dependency core.WebDependency) map[string]string {
	return map[string]string{
		"url": dependency.URL, "host": dependency.Host, "kind": dependency.Kind,
		"source": dependency.Source, "directive": dependency.Directive,
		"provider":   dependency.Provider,
		"dns_status": string(dependency.DNSStatus), "http_status": strconv.Itoa(dependency.HTTPStatus),
		"cname_chain": strings.Join(dependency.CNAME, ","),
	}
}

func linkAsset(node *html.Node) bool {
	for _, attr := range node.Attr {
		if !strings.EqualFold(attr.Key, "rel") {
			continue
		}
		for _, rel := range strings.Fields(strings.ToLower(attr.Val)) {
			switch rel {
			case "stylesheet", "icon", "manifest", "preload", "modulepreload":
				return true
			}
		}
	}
	return false
}
