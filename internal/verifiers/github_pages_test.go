package verifiers

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/amchdd/subdomainabber/internal/core"
)

type verifierRoundTripFunc func(*http.Request) (*http.Response, error)

func (fn verifierRoundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return fn(request)
}

func TestGitHubPagesVerifierRequiresDNSLabelBoundary(t *testing.T) {
	requests := 0
	client := &http.Client{Transport: verifierRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		requests++
		return &http.Response{
			StatusCode: http.StatusNotFound,
			Body:       io.NopCloser(strings.NewReader("There isn't a GitHub Pages site here.")),
			Header:     make(http.Header),
			Request:    request,
		}, nil
	})}
	verifier := NewGitHubPagesVerifier(Config{Client: client})

	hostile := &core.HostAnalysis{Host: "target.example", DNS: core.DNSRecordSet{CNAME: []string{"evilgithub.io"}}}
	result, err := verifier.Verify(context.Background(), hostile)
	if err != nil || result != nil || requests != 0 {
		t.Fatalf("suffix collision reached GitHub verifier: result=%#v requests=%d err=%v", result, requests, err)
	}

	legitimate := &core.HostAnalysis{Host: "target.example", DNS: core.DNSRecordSet{CNAME: []string{"owner.github.io."}}}
	result, err = verifier.Verify(context.Background(), legitimate)
	if err != nil || result == nil || !result.Verified || requests != 1 {
		t.Fatalf("legitimate GitHub endpoint was not verified: result=%#v requests=%d err=%v", result, requests, err)
	}
}
