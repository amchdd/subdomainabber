package discovery

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestWhoisPivotReturnsOnlyRegistrableSiblingDomains(t *testing.T) {
	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		body := `[{"name_value":"api.other.example\n*.other.example\napi.target.example"}]`
		if request.URL.Host == "rdap.org" {
			body = `{"entities":[{"roles":["registrant"],"vcardArray":["vcard",[["org",{},"text","Example Org"]]]}]}`
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     make(http.Header),
			Body:       io.NopCloser(strings.NewReader(body)),
			Request:    request,
		}, nil
	})}

	got, err := NewWhoisPivotService(client).Pivot(context.Background(), "target.example")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0] != "other.example" {
		t.Fatalf("domínios relacionados = %#v", got)
	}
}

func TestWhoisPivotRejectsOversizedResponse(t *testing.T) {
	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     make(http.Header),
			Body:       io.NopCloser(strings.NewReader(strings.Repeat("x", maxWhoisPivotResponseBytes+1))),
			Request:    request,
		}, nil
	})}

	_, err := NewWhoisPivotService(client).Pivot(context.Background(), "target.example")
	if err == nil || !strings.Contains(err.Error(), "excedeu o limite") {
		t.Fatalf("resposta excessiva não foi rejeitada corretamente: %v", err)
	}
}
