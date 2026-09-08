package evidence

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/amchdd/subdomainabber/internal/core"
)

func TestVHostDefaultBackend(t *testing.T) {
	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusNotFound,
			Header:     make(http.Header),
			Body:       io.NopCloser(strings.NewReader("default backend")),
			Request:    request,
		}, nil
	})}
	analysis := &core.HostAnalysis{Host: "app.example.test"}
	analysis.SetHTTPObservation("https", newHTTPObservation("https", http.StatusOK, nil, []byte("application"), true, 0, "", ""))
	collector := NewVHostCollector(client)
	collector.SetNameGenerator(sequenceNames("one.example.test", "two.example.test"))

	if err := collector.Collect(context.Background(), analysis); err != nil {
		t.Fatal(err)
	}
	if !hasEvidenceType(analysis.Evidences, "VHOST_DIFFERENTIAL") {
		t.Fatalf("default backend não detectado: %+v", analysis.Evidences)
	}
}

func TestVHostWildcard(t *testing.T) {
	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     make(http.Header),
			Body:       io.NopCloser(strings.NewReader("application")),
			Request:    request,
		}, nil
	})}
	analysis := &core.HostAnalysis{Host: "app.example.test"}
	analysis.SetHTTPObservation("http", newHTTPObservation("http", http.StatusOK, nil, []byte("application"), true, 0, "", ""))
	collector := NewVHostCollector(client)
	collector.SetNameGenerator(sequenceNames("one.example.test", "two.example.test"))

	if err := collector.Collect(context.Background(), analysis); err != nil {
		t.Fatal(err)
	}
	if !hasEvidenceType(analysis.Evidences, "HTTP_WILDCARD_DETECTED") {
		t.Fatalf("wildcard HTTP não detectado: %+v", analysis.Evidences)
	}
}

func sequenceNames(names ...string) func(string) string {
	index := 0
	return func(string) string {
		name := names[index]
		index++
		return name
	}
}
