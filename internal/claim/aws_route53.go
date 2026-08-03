package claim

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/route53"

	"github.com/amchdd/subdomainabber/internal/core"
)

const awsRoute53ProviderID = "aws_route53"

type route53API interface {
	CreateHostedZone(context.Context, *route53.CreateHostedZoneInput, ...func(*route53.Options)) (*route53.CreateHostedZoneOutput, error)
	GetHostedZone(context.Context, *route53.GetHostedZoneInput, ...func(*route53.Options)) (*route53.GetHostedZoneOutput, error)
	ListHostedZonesByName(context.Context, *route53.ListHostedZonesByNameInput, ...func(*route53.Options)) (*route53.ListHostedZonesByNameOutput, error)
	DeleteHostedZone(context.Context, *route53.DeleteHostedZoneInput, ...func(*route53.Options)) (*route53.DeleteHostedZoneOutput, error)
}

type AWSRoute53Provider struct {
	client route53API
}

func NewAWSRoute53Provider(ctx context.Context, region, accessKey, secretKey, sessionToken string) (*AWSRoute53Provider, error) {
	if strings.TrimSpace(region) == "" {
		region = "us-east-1"
	}
	options := []func(*awsconfig.LoadOptions) error{awsconfig.WithRegion(region)}
	if strings.TrimSpace(accessKey) != "" || strings.TrimSpace(secretKey) != "" {
		if strings.TrimSpace(accessKey) == "" || strings.TrimSpace(secretKey) == "" {
			return nil, fmt.Errorf("SABBER_AWS_ACCESS_KEY e SABBER_AWS_SECRET_KEY são obrigatórias em conjunto")
		}
		options = append(options, awsconfig.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(accessKey, secretKey, sessionToken)))
	}
	configuration, err := awsconfig.LoadDefaultConfig(ctx, options...)
	if err != nil {
		return nil, fmt.Errorf("carregando configuração da AWS para o Route 53: %w", err)
	}
	if _, err := configuration.Credentials.Retrieve(ctx); err != nil {
		return nil, fmt.Errorf("obtendo credenciais da AWS para o Route 53: %w", err)
	}
	return &AWSRoute53Provider{client: route53.NewFromConfig(configuration)}, nil
}

func newAWSRoute53ProviderWithClient(client route53API) *AWSRoute53Provider {
	return &AWSRoute53Provider{client: client}
}

func (*AWSRoute53Provider) ProviderID() string { return awsRoute53ProviderID }

func (*AWSRoute53Provider) Supports(candidate core.ProviderCandidate) bool {
	return strings.EqualFold(candidate.Vector, "NS") &&
		strings.EqualFold(strings.TrimSpace(candidate.ProviderID), awsRoute53ProviderID)
}

func (provider *AWSRoute53Provider) Claim(ctx context.Context, request Request) (Receipt, error) {
	zone := normalizeHost(request.Resource)
	if zone == "" {
		zone = normalizeHost(request.Metadata["zone"])
	}
	delegated := splitNameservers(request.Metadata["delegated_nameservers"])
	if zone == "" || len(delegated) == 0 {
		return Receipt{}, fmt.Errorf("a validação do Route 53 exige uma zona e os servidores NS delegados pela zona pai")
	}
	output, err := provider.client.CreateHostedZone(ctx, &route53.CreateHostedZoneInput{
		Name: aws.String(zone), CallerReference: aws.String("subdomainabber-" + request.ProofToken),
	})
	if err != nil {
		return Receipt{}, fmt.Errorf("criando a zona hospedada temporária %q no Route 53: %w", zone, err)
	}
	assigned := []string(nil)
	if output.DelegationSet != nil {
		assigned = append(assigned, output.DelegationSet.NameServers...)
	}
	if output.HostedZone == nil || aws.ToString(output.HostedZone.Id) == "" {
		return Receipt{}, &ClaimFailure{
			Receipt: Receipt{
				ProviderID: provider.ProviderID(), ClaimedAt: time.Now().UTC(),
				Metadata: map[string]string{
					"zone": zone, "delegated_nameservers": strings.Join(delegated, ","),
					"assigned_nameservers": strings.Join(splitNameservers(strings.Join(assigned, ",")), ","),
				},
			},
			Err: fmt.Errorf("o Route 53 confirmou a criação, mas não retornou o identificador da zona hospedada"),
		}
	}
	hostedZoneID := aws.ToString(output.HostedZone.Id)
	receipt := Receipt{
		ProviderID: provider.ProviderID(), ExternalID: hostedZoneID, ClaimedAt: time.Now().UTC(),
		Metadata: map[string]string{
			"zone": zone, "delegated_nameservers": strings.Join(delegated, ","),
			"assigned_nameservers": strings.Join(splitNameservers(strings.Join(assigned, ",")), ","),
		},
	}
	if !sameNameserverSet(delegated, assigned) {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if _, cleanupErr := provider.client.DeleteHostedZone(cleanupCtx, &route53.DeleteHostedZoneInput{Id: aws.String(hostedZoneID)}); cleanupErr != nil {
			return Receipt{}, &ClaimFailure{
				Receipt: receipt,
				Err:     fmt.Errorf("os servidores NS do Route 53 não correspondem à delegação e a limpeza imediata falhou: %w", cleanupErr),
			}
		}
		return Receipt{}, fmt.Errorf("%w: os servidores NS atribuídos pelo Route 53 não correspondem exatamente à delegação publicada pela zona pai", ErrClaimNotMatched)
	}
	return receipt, nil
}

func (provider *AWSRoute53Provider) VerifyControl(ctx context.Context, receipt Receipt) (ControlProof, error) {
	if receipt.ExternalID == "" {
		return ControlProof{}, fmt.Errorf("recibo do Route 53 incompleto")
	}
	output, err := provider.client.GetHostedZone(ctx, &route53.GetHostedZoneInput{Id: aws.String(receipt.ExternalID)})
	if err != nil {
		return ControlProof{}, fmt.Errorf("lendo a zona hospedada temporária no Route 53: %w", err)
	}
	assigned := []string(nil)
	if output.DelegationSet != nil {
		assigned = append(assigned, output.DelegationSet.NameServers...)
	}
	delegated := splitNameservers(receipt.Metadata["delegated_nameservers"])
	if !sameNameserverSet(delegated, assigned) {
		return ControlProof{Details: "A zona temporária existe, mas seus servidores NS não correspondem mais à delegação pai"}, nil
	}
	return ControlProof{
		Controlled: true,
		Details:    "A zona temporária do Route 53 foi criada e seu conjunto completo de servidores NS correspondeu exatamente à delegação publicada pela zona pai",
	}, nil
}

// RecoverClaim procura a zona pelo nome e pela CallerReference derivada do
// token durável da tentativa. Zonas homônimas criadas por outro processo não
// são consideradas e nunca são removidas.
func (provider *AWSRoute53Provider) RecoverClaim(ctx context.Context, provisional Receipt) (Receipt, bool, error) {
	zone := normalizeHost(provisional.Metadata["request_resource"])
	if zone == "" {
		zone = normalizeHost(provisional.Metadata["zone"])
	}
	token := strings.TrimSpace(provisional.Metadata["proof_token"])
	if zone == "" || token == "" {
		return Receipt{}, false, fmt.Errorf("registro preventivo do Route 53 incompleto")
	}
	callerReference := "subdomainabber-" + token
	dnsName := aws.String(zone)
	var hostedZoneID *string

	for {
		output, err := provider.client.ListHostedZonesByName(ctx, &route53.ListHostedZonesByNameInput{
			DNSName: dnsName, HostedZoneId: hostedZoneID, MaxItems: aws.Int32(100),
		})
		if err != nil {
			return Receipt{}, false, fmt.Errorf("procurando a zona temporária no Route 53: %w", err)
		}
		for _, hostedZone := range output.HostedZones {
			currentZone := normalizeHost(aws.ToString(hostedZone.Name))
			if currentZone != zone {
				return Receipt{}, false, nil
			}
			if aws.ToString(hostedZone.CallerReference) != callerReference {
				continue
			}
			id := aws.ToString(hostedZone.Id)
			if id == "" {
				return Receipt{}, false, fmt.Errorf("a zona recuperada do Route 53 não possui identificador")
			}
			details, err := provider.client.GetHostedZone(ctx, &route53.GetHostedZoneInput{Id: aws.String(id)})
			if err != nil {
				return Receipt{}, false, fmt.Errorf("lendo a zona temporária recuperada no Route 53: %w", err)
			}
			assigned := []string(nil)
			if details.DelegationSet != nil {
				assigned = append(assigned, details.DelegationSet.NameServers...)
			}
			return Receipt{
				ProviderID: provider.ProviderID(), ExternalID: id, ClaimedAt: provisional.ClaimedAt,
				Metadata: map[string]string{
					"zone":                  zone,
					"delegated_nameservers": provisional.Metadata["delegated_nameservers"],
					"assigned_nameservers":  strings.Join(splitNameservers(strings.Join(assigned, ",")), ","),
				},
			}, true, nil
		}
		if !output.IsTruncated || output.NextDNSName == nil || output.NextHostedZoneId == nil {
			return Receipt{}, false, nil
		}
		dnsName = output.NextDNSName
		hostedZoneID = output.NextHostedZoneId
	}
}

func (provider *AWSRoute53Provider) Release(ctx context.Context, receipt Receipt) (ReleaseReceipt, error) {
	if receipt.ExternalID == "" {
		return ReleaseReceipt{}, fmt.Errorf("recibo do Route 53 incompleto")
	}
	if _, err := provider.client.DeleteHostedZone(ctx, &route53.DeleteHostedZoneInput{Id: aws.String(receipt.ExternalID)}); err != nil {
		return ReleaseReceipt{}, fmt.Errorf("excluindo a zona hospedada temporária no Route 53: %w", err)
	}
	return ReleaseReceipt{ReleasedAt: time.Now().UTC(), Details: "A zona hospedada temporária do Route 53 foi excluída"}, nil
}

func splitNameservers(value string) []string {
	var result []string
	for _, item := range strings.Split(value, ",") {
		item = strings.ToLower(strings.Trim(strings.TrimSpace(item), "."))
		if item != "" {
			result = append(result, item)
		}
	}
	sort.Strings(result)
	return result
}

func sameNameserverSet(left, right []string) bool {
	left = splitNameservers(strings.Join(left, ","))
	right = splitNameservers(strings.Join(right, ","))
	if len(left) == 0 || len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}
