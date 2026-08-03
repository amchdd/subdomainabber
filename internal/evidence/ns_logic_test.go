package evidence

import (
	"testing"

	"github.com/amchdd/subdomainabber/internal/core"
)

func TestUniformDelegationProviderRejectsMixedOrUnknownNameservers(t *testing.T) {
	tests := []struct {
		name         string
		observations []core.DelegationNSObservation
		wantID       string
	}{
		{
			name: "uniform",
			observations: []core.DelegationNSObservation{
				{ProviderID: "aws_route53", Service: "AWS Route53"},
				{ProviderID: "aws_route53", Service: "AWS Route53"},
			},
			wantID: "aws_route53",
		},
		{
			name: "mixed",
			observations: []core.DelegationNSObservation{
				{ProviderID: "aws_route53", Service: "AWS Route53"},
				{ProviderID: "azure_dns", Service: "Azure DNS"},
			},
		},
		{
			name: "partially unknown",
			observations: []core.DelegationNSObservation{
				{ProviderID: "aws_route53", Service: "AWS Route53"},
				{},
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			id, _ := uniformDelegationProvider(test.observations)
			if id != test.wantID {
				t.Fatalf("provider = %q, want %q", id, test.wantID)
			}
		})
	}
}
