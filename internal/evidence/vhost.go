package evidence

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/amchdd/subdomainabber/internal/core"
	"github.com/amchdd/subdomainabber/internal/dns"
)

type VHostCollector struct {
	client       *http.Client
	generateName func(string) string
}

func NewVHostCollector(client *http.Client) *VHostCollector {
	return &VHostCollector{client: noRedirectClient(client), generateName: randomVHostName}
}

func (*VHostCollector) Phase() CollectorPhase { return PhaseImpact }

func (collector *VHostCollector) SetNameGenerator(generator func(string) string) {
	if generator != nil {
		collector.generateName = generator
	}
}

func (collector *VHostCollector) Collect(ctx context.Context, analysis *core.HostAnalysis) error {
	if analysis == nil || collector.client == nil {
		return nil
	}
	analysis.AddTestedVector("VHOST")
	root := dns.ExtractRootDomain(analysis.Host)
	if root == "" {
		root = analysis.Host
	}

	for _, scheme := range []string{"https", "http"} {
		baseline, ok := analysis.HTTPObservation(scheme)
		if !ok || !baseline.Complete {
			continue
		}
		firstName := collector.generateName(root)
		secondName := collector.generateName(root)
		first := collector.probe(ctx, analysis.Host, firstName, scheme)
		second := collector.probe(ctx, analysis.Host, secondName, scheme)
		if !first.Complete || !second.Complete || !sameHTTPResponse(first, second) {
			continue
		}

		metadata := map[string]string{
			"scheme": scheme, "first_host": firstName, "second_host": secondName,
			"baseline_status": statusNumber(baseline.StatusCode), "variant_status": statusNumber(first.StatusCode),
			"baseline_body_hash": baseline.BodyHash, "variant_body_hash": first.BodyHash,
		}
		if sameHTTPResponse(baseline, first) {
			analysis.AddEvidence(core.Evidence{
				Type: "HTTP_WILDCARD_DETECTED", Source: scheme,
				Description: "Dois hostnames inexistentes reproduziram a resposta do hostname analisado.",
				Weight:      0, Confidence: 95, Metadata: metadata,
			})
			continue
		}
		analysis.AddEvidence(core.Evidence{
			Type: "VHOST_DIFFERENTIAL", Source: scheme,
			Description: "Dois valores benignos de Host reproduziram um backend padrão diferente da aplicação.",
			Weight:      0, Confidence: 95, Metadata: metadata,
		})
	}
	return nil
}

func (collector *VHostCollector) probe(ctx context.Context, dialHost, authority, scheme string) core.HTTPObservation {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, scheme+"://"+dialHost+"/", nil)
	if err != nil {
		return newHTTPObservation(scheme, 0, nil, nil, false, 0, err.Error(), "")
	}
	request.Host = authority
	request.Header.Set("User-Agent", "SubdomainAbber/VHost")
	started := time.Now()
	response, err := collector.client.Do(request)
	if err != nil {
		return newHTTPObservation(scheme, 0, nil, nil, false, time.Since(started), err.Error(), "")
	}
	body, readErr := io.ReadAll(io.LimitReader(response.Body, maxBodySize+1))
	closeErr := response.Body.Close()
	complete := readErr == nil && closeErr == nil && len(body) <= maxBodySize
	if len(body) > maxBodySize {
		body = body[:maxBodySize]
	}
	parseError := ""
	if readErr != nil {
		parseError = readErr.Error()
	} else if closeErr != nil {
		parseError = closeErr.Error()
	}
	return newHTTPObservation(scheme, response.StatusCode, response.Header, body, complete, time.Since(started), "", parseError)
}

func sameHTTPResponse(left, right core.HTTPObservation) bool {
	return left.StatusCode == right.StatusCode && left.BodyHash != "" && left.BodyHash == right.BodyHash
}

func statusNumber(status int) string { return strconv.Itoa(status) }

func randomVHostName(root string) string {
	buffer := make([]byte, 8)
	if _, err := rand.Read(buffer); err != nil {
		return "subdomainabber-probe." + root
	}
	return hex.EncodeToString(buffer) + "." + root
}
