package verifiers

import (
	"context"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/amchdd/subdomainabber/internal/core"
)

type countingTransport struct {
	calls atomic.Int32
}

func (transport *countingTransport) RoundTrip(*http.Request) (*http.Response, error) {
	transport.calls.Add(1)
	return &http.Response{
		StatusCode: http.StatusNoContent,
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader("")),
	}, nil
}

func TestProviderVerifiersRequireDNSLabelBoundaries(t *testing.T) {
	tests := []struct {
		name     string
		positive string
		hostile  []string
		new      func(Config) Verifier
	}{
		{
			name:     "AWS S3",
			positive: "Bucket.S3.US-EAST-1.AMAZONAWS.COM.",
			hostile: []string{
				"bucket.s3.amazonaws.com.attacker.example",
				"bucket.evils3.amazonaws.com",
				"s3-website.attacker.example",
			},
			new: func(config Config) Verifier { return NewAWSVerifier(config) },
		},
		{
			name:     "Azure Blob",
			positive: "account.blob.core.windows.net.",
			hostile:  []string{"account.blob.core.windows.net.attacker.example", "evilblob.core.windows.net"},
			new:      func(config Config) Verifier { return NewAzureBlobVerifier(config) },
		},
		{
			name:     "Azure",
			positive: "app.azurewebsites.net.",
			hostile:  []string{"app.azurewebsites.net.attacker.example", "evilazurewebsites.net"},
			new:      func(config Config) Verifier { return NewAzureVerifier(config) },
		},
		{
			name:     "Fastly",
			positive: "service.fastly.net.",
			hostile:  []string{"service.fastly.net.attacker.example", "evilfastly.net"},
			new:      func(config Config) Verifier { return NewFastlyVerifier(config) },
		},
		{
			name:     "Zendesk",
			positive: "mail.zendesk.com.",
			hostile:  []string{"mail.zendesk.com.attacker.example", "evilzendesk.com"},
			new:      func(config Config) Verifier { return NewZendeskVerifier(config) },
		},
		{
			name:     "Google Cloud Storage",
			positive: "bucket.storage.googleapis.com.",
			hostile:  []string{"bucket.storage.googleapis.com.attacker.example", "evilstorage.googleapis.com"},
			new:      func(config Config) Verifier { return NewGCSBucketVerifier(config) },
		},
		{
			name:     "Heroku",
			positive: "app.herokudns.com.",
			hostile:  []string{"app.herokuapp.com.attacker.example", "evilherokuapp.com"},
			new:      func(config Config) Verifier { return NewHerokuVerifier(config) },
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			for _, cname := range test.hostile {
				transport := &countingTransport{}
				verifier := test.new(Config{Client: &http.Client{Transport: transport}})
				analysis := &core.HostAnalysis{
					Host: "target.example",
					DNS:  core.DNSRecordSet{CNAME: []string{cname}},
				}
				if _, err := verifier.Verify(context.Background(), analysis); err != nil {
					t.Fatalf("Verify() com CNAME hostil %q retornou erro: %v", cname, err)
				}
				if got := transport.calls.Load(); got != 0 {
					t.Fatalf("CNAME hostil %q iniciou %d requisição(ões) HTTP", cname, got)
				}
			}

			transport := &countingTransport{}
			verifier := test.new(Config{Client: &http.Client{Transport: transport}})
			analysis := &core.HostAnalysis{
				Host: "target.example",
				DNS:  core.DNSRecordSet{CNAME: []string{test.positive}},
			}
			if _, err := verifier.Verify(context.Background(), analysis); err != nil {
				t.Fatalf("Verify() com CNAME válido retornou erro: %v", err)
			}
			if got := transport.calls.Load(); got == 0 {
				t.Fatal("o CNAME válido não iniciou a verificação HTTP")
			}
		})
	}
}

func TestS3EndpointRecognitionIsProviderBound(t *testing.T) {
	tests := []struct {
		host string
		want bool
	}{
		{host: "bucket.s3.amazonaws.com", want: true},
		{host: "bucket.s3.us-east-1.amazonaws.com", want: true},
		{host: "bucket.s3.dualstack.eu-west-1.amazonaws.com", want: true},
		{host: "bucket.s3-us-west-2.amazonaws.com", want: true},
		{host: "bucket.s3-website-us-east-1.amazonaws.com", want: true},
		{host: "bucket.s3-website.ap-southeast-2.amazonaws.com", want: true},
		{host: "s3.amazonaws.com", want: false},
		{host: "bucket.s3.amazonaws.com.attacker.example", want: false},
		{host: "bucket.evils3.amazonaws.com", want: false},
		{host: "bucket.s3.invalid-region.amazonaws.com", want: false},
	}

	for _, test := range tests {
		if got := isS3Endpoint(test.host); got != test.want {
			t.Errorf("isS3Endpoint(%q) = %t; esperado %t", test.host, got, test.want)
		}
	}
}

func TestProviderRedirectMatchesDNSHostAndPath(t *testing.T) {
	tests := []struct {
		name     string
		location string
		want     bool
	}{
		{name: "provedor exato", location: "https://ghost.org/signup", want: true},
		{name: "subdomínio do provedor", location: "https://account.ghost.org/signup/project", want: true},
		{name: "colisão de sufixo", location: "https://evilghost.org/signup", want: false},
		{name: "provedor na consulta", location: "https://attacker.example/?next=ghost.org/signup", want: false},
		{name: "provedor antes do domínio real", location: "https://ghost.org.attacker.example/signup", want: false},
		{name: "caminho diferente", location: "https://ghost.org/not-signup", want: false},
		{name: "URL relativa", location: "/signup", want: false},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := providerRedirectMatches(test.location, "/signup", "ghost.org"); got != test.want {
				t.Fatalf("providerRedirectMatches(%q) = %t; esperado %t", test.location, got, test.want)
			}
		})
	}
}
