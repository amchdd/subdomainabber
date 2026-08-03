package evidence

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/amchdd/subdomainabber/internal/core"
	"github.com/amchdd/subdomainabber/pkg/signatures"
)

type controlledApplicationRouteProbe struct{}

func (controlledApplicationRouteProbe) Name() string { return "ControlledApplicationRouteProbe" }
func (controlledApplicationRouteProbe) Description() string {
	return "single-request controlled application route probe"
}
func (controlledApplicationRouteProbe) Applicability(ctx core.MutationContext) bool {
	return probeApplicable(ctx)
}
func (controlledApplicationRouteProbe) BuildControl(ctx core.MutationContext) ([]byte, error) {
	return buildRawRequest("GET", "/blocked", standardRawHeaders(ctx.HTTPAuthority, "close"), nil)
}
func (controlledApplicationRouteProbe) BuildMutation(ctx core.MutationContext) ([]byte, error) {
	return buildRawRequest("GET", "/provider/aws-s3", standardRawHeaders(ctx.HTTPAuthority, "close"), nil)
}

func TestControlledApplicationLabReturnsFingerprintOnlyForExplicitValidRoute(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method == http.MethodGet && request.URL.Path == "/provider/aws-s3" {
			writer.WriteHeader(http.StatusNotFound)
			fmt.Fprint(writer, "The specified bucket does not exist")
			return
		}
		writer.WriteHeader(http.StatusForbidden)
		fmt.Fprint(writer, "Access denied")
	}))
	defer server.Close()
	authority := server.Listener.Addr().String()
	analysis := &core.HostAnalysis{Host: authority}
	analysis.AddProviderCandidate(core.ProviderCandidate{ProviderID: "aws_s3", Service: "AWS/S3", CNAME: "bucket.s3.amazonaws.com"})
	analysis.SetHTTPObservation("http", newHTTPObservation("http", 403, nil, []byte("Access denied"), true, 0, "", ""))
	collector := NewHTTPMutatorCollector([]signatures.Fingerprint{awsSignature()}, time.Second)
	collector.SetMutations([]HTTPMutation{controlledApplicationRouteProbe{}})
	if err := collector.Collect(context.Background(), analysis); err != nil {
		t.Fatal(err)
	}
	if _, found := findEvidence(analysis, "HTTP_MUTATION_REVEALED_PROVIDER_FINGERPRINT"); !found {
		t.Fatalf("explicit application response was not correlated: %#v", analysis.Evidences)
	}
	result := analysis.MutationResults[0]
	if string(result.Experiment.ControlBefore.Body) != "Access denied" || string(result.Experiment.MutationFirst.Body) != "The specified bucket does not exist" {
		t.Fatalf("unexpected application observations: %#v", result.Experiment)
	}
}
