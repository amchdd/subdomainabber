package claim

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/route53"
	"github.com/aws/aws-sdk-go-v2/service/route53/types"
)

type fakeRoute53API struct {
	assigned    []string
	deleteCalls int
	created     *types.HostedZone
	omitID      bool
}

func (fake *fakeRoute53API) CreateHostedZone(_ context.Context, input *route53.CreateHostedZoneInput, _ ...func(*route53.Options)) (*route53.CreateHostedZoneOutput, error) {
	fake.created = &types.HostedZone{
		Id: aws.String("/hostedzone/ZTEST"), Name: aws.String("dev.example.com."),
		CallerReference: input.CallerReference,
	}
	if fake.omitID {
		fake.created.Id = nil
	}
	return &route53.CreateHostedZoneOutput{
		HostedZone:    fake.created,
		DelegationSet: &types.DelegationSet{NameServers: append([]string(nil), fake.assigned...)},
	}, nil
}

func (fake *fakeRoute53API) GetHostedZone(context.Context, *route53.GetHostedZoneInput, ...func(*route53.Options)) (*route53.GetHostedZoneOutput, error) {
	return &route53.GetHostedZoneOutput{DelegationSet: &types.DelegationSet{NameServers: append([]string(nil), fake.assigned...)}}, nil
}

func (fake *fakeRoute53API) ListHostedZonesByName(context.Context, *route53.ListHostedZonesByNameInput, ...func(*route53.Options)) (*route53.ListHostedZonesByNameOutput, error) {
	output := &route53.ListHostedZonesByNameOutput{MaxItems: aws.Int32(100)}
	if fake.created != nil {
		output.HostedZones = []types.HostedZone{*fake.created}
	}
	return output, nil
}

func (fake *fakeRoute53API) DeleteHostedZone(context.Context, *route53.DeleteHostedZoneInput, ...func(*route53.Options)) (*route53.DeleteHostedZoneOutput, error) {
	fake.deleteCalls++
	return &route53.DeleteHostedZoneOutput{}, nil
}

func TestRoute53ProviderProvesExactDelegationAndReleases(t *testing.T) {
	nameservers := []string{"ns-1.awsdns-10.com", "ns-2.awsdns-20.net", "ns-3.awsdns-30.org", "ns-4.awsdns-40.co.uk"}
	fake := &fakeRoute53API{assigned: nameservers}
	provider := newAWSRoute53ProviderWithClient(fake)
	request := Request{
		Vector: "NS", Resource: "dev.example.com", ProofToken: "proof",
		Metadata: map[string]string{"delegated_nameservers": "ns-4.awsdns-40.co.uk,ns-2.awsdns-20.net,ns-1.awsdns-10.com,ns-3.awsdns-30.org"},
	}
	receipt, err := provider.Claim(context.Background(), request)
	if err != nil {
		t.Fatalf("claim failed: %v", err)
	}
	proof, err := provider.VerifyControl(context.Background(), receipt)
	if err != nil || !proof.Controlled {
		t.Fatalf("control proof = %#v, %v", proof, err)
	}
	if _, err := provider.Release(context.Background(), receipt); err != nil {
		t.Fatalf("release failed: %v", err)
	}
	if fake.deleteCalls != 1 {
		t.Fatalf("delete calls = %d, want 1", fake.deleteCalls)
	}
}

func TestRoute53ProviderRejectsAndCleansUpMismatchedDelegation(t *testing.T) {
	fake := &fakeRoute53API{assigned: []string{"ns-9.awsdns-90.com"}}
	provider := newAWSRoute53ProviderWithClient(fake)
	_, err := provider.Claim(context.Background(), Request{
		Vector: "NS", Resource: "dev.example.com", ProofToken: "proof",
		Metadata: map[string]string{"delegated_nameservers": "ns-1.awsdns-10.com"},
	})
	if err == nil || !errors.Is(err, ErrClaimNotMatched) || fake.deleteCalls != 1 {
		t.Fatalf("expected mismatch and cleanup, err=%v deletes=%d", err, fake.deleteCalls)
	}
}

func TestRoute53ProviderReturnsRecoverableFailureWhenCreateOmitsID(t *testing.T) {
	fake := &fakeRoute53API{assigned: []string{"ns-1.awsdns-10.com"}, omitID: true}
	provider := newAWSRoute53ProviderWithClient(fake)
	_, err := provider.Claim(context.Background(), Request{
		Vector: "NS", Resource: "dev.example.com", ProofToken: "proof",
		Metadata: map[string]string{"delegated_nameservers": "ns-1.awsdns-10.com"},
	})
	var failure *ClaimFailure
	if !errors.As(err, &failure) || failure.Receipt.ProviderID != awsRoute53ProviderID {
		t.Fatalf("missing hosted-zone ID was not recoverable: %#v, %v", failure, err)
	}
	if fake.deleteCalls != 0 {
		t.Fatalf("provider attempted an unaddressable deletion: %d", fake.deleteCalls)
	}
}

func TestRoute53ProviderRecoversOnlyMatchingCallerReference(t *testing.T) {
	nameservers := []string{"ns-1.awsdns-10.com", "ns-2.awsdns-20.net"}
	fake := &fakeRoute53API{assigned: nameservers}
	provider := newAWSRoute53ProviderWithClient(fake)
	_, err := provider.Claim(context.Background(), Request{
		Vector: "NS", Resource: "dev.example.com", ProofToken: "proof",
		Metadata: map[string]string{"delegated_nameservers": strings.Join(nameservers, ",")},
	})
	if err != nil {
		t.Fatalf("a criação da zona de teste falhou: %v", err)
	}
	recovered, found, err := provider.RecoverClaim(context.Background(), provisionalReceipt(provider.ProviderID(), Request{
		Vector: "NS", Resource: "dev.example.com", ProofToken: "proof",
		Metadata: map[string]string{"delegated_nameservers": strings.Join(nameservers, ",")},
	}))
	if err != nil || !found || recovered.ExternalID != "/hostedzone/ZTEST" {
		t.Fatalf("recuperação inesperada: recibo=%#v encontrado=%t erro=%v", recovered, found, err)
	}

	fake.created.CallerReference = aws.String("outra-tentativa")
	if _, found, err := provider.RecoverClaim(context.Background(), provisionalReceipt(provider.ProviderID(), Request{
		Vector: "NS", Resource: "dev.example.com", ProofToken: "proof",
	})); err != nil || found {
		t.Fatalf("uma zona de outra tentativa foi aceita: encontrado=%t erro=%v", found, err)
	}
}
