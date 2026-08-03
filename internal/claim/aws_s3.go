package claim

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"
	smithyhttp "github.com/aws/smithy-go/transport/http"

	"github.com/amchdd/subdomainabber/internal/core"
)

const awsS3ProviderID = "aws_s3"

type s3API interface {
	HeadBucket(context.Context, *s3.HeadBucketInput, ...func(*s3.Options)) (*s3.HeadBucketOutput, error)
	CreateBucket(context.Context, *s3.CreateBucketInput, ...func(*s3.Options)) (*s3.CreateBucketOutput, error)
	PutObject(context.Context, *s3.PutObjectInput, ...func(*s3.Options)) (*s3.PutObjectOutput, error)
	HeadObject(context.Context, *s3.HeadObjectInput, ...func(*s3.Options)) (*s3.HeadObjectOutput, error)
	DeleteObject(context.Context, *s3.DeleteObjectInput, ...func(*s3.Options)) (*s3.DeleteObjectOutput, error)
	DeleteBucket(context.Context, *s3.DeleteBucketInput, ...func(*s3.Options)) (*s3.DeleteBucketOutput, error)
}

type AWSS3Provider struct {
	client s3API
	region string
}

func NewAWSS3Provider(ctx context.Context, region, accessKey, secretKey, sessionToken string) (*AWSS3Provider, error) {
	region = strings.TrimSpace(region)
	accessKey = strings.TrimSpace(accessKey)
	secretKey = strings.TrimSpace(secretKey)
	sessionToken = strings.TrimSpace(sessionToken)
	if region == "" {
		region = "us-east-1"
	}
	if sessionToken != "" && (accessKey == "" || secretKey == "") {
		return nil, fmt.Errorf("SABBER_AWS_SESSION_TOKEN exige SABBER_AWS_ACCESS_KEY e SABBER_AWS_SECRET_KEY")
	}
	loadOptions := []func(*awsconfig.LoadOptions) error{awsconfig.WithRegion(region)}
	if accessKey != "" || secretKey != "" {
		if accessKey == "" || secretKey == "" {
			return nil, fmt.Errorf("SABBER_AWS_ACCESS_KEY e SABBER_AWS_SECRET_KEY são obrigatórias em conjunto")
		}
		loadOptions = append(loadOptions, awsconfig.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(accessKey, secretKey, sessionToken)))
	}
	configuration, err := awsconfig.LoadDefaultConfig(ctx, loadOptions...)
	if err != nil {
		return nil, fmt.Errorf("carregando configuração AWS: %w", err)
	}
	if _, err := configuration.Credentials.Retrieve(ctx); err != nil {
		return nil, fmt.Errorf("obtendo credenciais AWS: %w", err)
	}
	return &AWSS3Provider{client: s3.NewFromConfig(configuration), region: region}, nil
}

func newAWSS3ProviderWithClient(client s3API, region string) *AWSS3Provider {
	return &AWSS3Provider{client: client, region: region}
}

func (*AWSS3Provider) ProviderID() string { return awsS3ProviderID }

func (*AWSS3Provider) Supports(candidate core.ProviderCandidate) bool {
	if !strings.EqualFold(strings.TrimSpace(candidate.ProviderID), awsS3ProviderID) {
		return false
	}
	resource := candidate.Resource
	if resource == "" {
		resource = candidate.CNAME
	}
	_, err := s3BucketFromEndpoint(resource)
	return err == nil
}

func (provider *AWSS3Provider) Claim(ctx context.Context, request Request) (Receipt, error) {
	resource := request.Resource
	if resource == "" {
		resource = request.Candidate.Resource
	}
	if resource == "" {
		resource = request.Candidate.CNAME
	}
	bucket, endpointRegion, err := parseS3Endpoint(resource)
	if err != nil {
		return Receipt{}, err
	}
	if endpointRegion != "" && !strings.EqualFold(endpointRegion, provider.region) {
		return Receipt{}, fmt.Errorf("o endpoint S3 exige a região %s, mas a execução está configurada para %s; ajuste SABBER_AWS_REGION antes da validação ativa", endpointRegion, provider.region)
	}
	if request.ProofToken == "" {
		return Receipt{}, fmt.Errorf("o token de prova é obrigatório")
	}
	if _, err := provider.client.HeadBucket(ctx, &s3.HeadBucketInput{Bucket: aws.String(bucket)}); err == nil {
		return Receipt{}, fmt.Errorf("o bucket S3 %q já existe ou já possui proprietário; recusando tratá-lo como uma nova reivindicação", bucket)
	} else if !s3ObjectAlreadyAbsent(err) {
		return Receipt{}, fmt.Errorf("não foi possível provar que o bucket S3 %q está ausente antes da reivindicação: %w", bucket, err)
	}
	createInput := &s3.CreateBucketInput{Bucket: aws.String(bucket)}
	if provider.region != "" && provider.region != "us-east-1" {
		createInput.CreateBucketConfiguration = &types.CreateBucketConfiguration{LocationConstraint: types.BucketLocationConstraint(provider.region)}
	}
	if _, err := provider.client.CreateBucket(ctx, createInput); err != nil {
		return Receipt{}, fmt.Errorf("criando bucket S3 %q: %w", bucket, err)
	}

	proofKey := ".well-known/subdomainabber-" + request.ProofToken
	receipt := Receipt{
		ProviderID: provider.ProviderID(),
		ExternalID: bucket,
		ClaimedAt:  time.Now().UTC(),
		Metadata: map[string]string{
			"region":      provider.region,
			"proof_key":   proofKey,
			"proof_token": request.ProofToken,
			"resource":    normalizeHost(resource),
		},
	}
	_, err = provider.client.PutObject(ctx, &s3.PutObjectInput{
		Bucket:   aws.String(bucket),
		Key:      aws.String(proofKey),
		Body:     strings.NewReader("Prova de controle autorizada do SubdomainAbber\n"),
		Metadata: map[string]string{"subdomainabber-proof": request.ProofToken},
	})
	if err != nil {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if _, cleanupErr := provider.client.DeleteBucket(cleanupCtx, &s3.DeleteBucketInput{Bucket: aws.String(bucket)}); cleanupErr != nil && !s3ObjectAlreadyAbsent(cleanupErr) {
			return Receipt{}, &ClaimFailure{Receipt: receipt, Err: fmt.Errorf("a gravação do objeto de controle S3 falhou e a limpeza imediata também falhou: %w", cleanupErr)}
		}
		return Receipt{}, fmt.Errorf("gravando objeto de controle S3: %w", err)
	}
	return receipt, nil
}

func (provider *AWSS3Provider) VerifyControl(ctx context.Context, receipt Receipt) (ControlProof, error) {
	proofKey, token := receipt.Metadata["proof_key"], receipt.Metadata["proof_token"]
	if receipt.ExternalID == "" || proofKey == "" || token == "" {
		return ControlProof{}, fmt.Errorf("recibo de reivindicação S3 incompleto")
	}
	output, err := provider.client.HeadObject(ctx, &s3.HeadObjectInput{Bucket: aws.String(receipt.ExternalID), Key: aws.String(proofKey)})
	if err != nil {
		return ControlProof{}, fmt.Errorf("lendo objeto de controle S3: %w", err)
	}
	if output == nil {
		return ControlProof{}, fmt.Errorf("o S3 retornou uma resposta vazia ao consultar o objeto de prova")
	}
	if output.Metadata["subdomainabber-proof"] != token {
		return ControlProof{Details: "Os metadados da prova S3 não corresponderam"}, nil
	}
	return ControlProof{Controlled: true, Details: "Os metadados do objeto privado de prova S3 corresponderam ao token gerado"}, nil
}

// RecoverClaim localiza somente o bucket que contém o objeto privado com o
// token gravado antes da criação. Um bucket homônimo sem essa prova nunca é
// considerado pertencente à tentativa e, portanto, nunca é removido.
func (provider *AWSS3Provider) RecoverClaim(ctx context.Context, provisional Receipt) (Receipt, bool, error) {
	bucket, resourceErr := s3BucketFromEndpoint(provisional.Metadata["request_resource"])
	token := strings.TrimSpace(provisional.Metadata["proof_token"])
	if resourceErr != nil || token == "" {
		return Receipt{}, false, fmt.Errorf("registro preventivo S3 incompleto")
	}
	if _, err := provider.client.HeadBucket(ctx, &s3.HeadBucketInput{Bucket: aws.String(bucket)}); err != nil {
		if s3BucketDefinitelyAbsent(err) {
			return Receipt{}, false, nil
		}
		return Receipt{}, false, fmt.Errorf("não foi possível determinar se o bucket S3 %q pertence à tentativa interrompida: %w", bucket, err)
	}
	proofKey := ".well-known/subdomainabber-" + token
	output, err := provider.client.HeadObject(ctx, &s3.HeadObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(proofKey),
	})
	if err != nil {
		return Receipt{}, false, fmt.Errorf("o bucket S3 %q existe, mas o objeto de prova não pôde ser confirmado; inspecione a conta e faça a limpeza manual antes de prosseguir: %w", bucket, err)
	}
	if output == nil {
		return Receipt{}, false, fmt.Errorf("o bucket S3 %q existe, mas a consulta ao objeto de prova retornou uma resposta vazia", bucket)
	}
	if output.Metadata["subdomainabber-proof"] != token {
		return Receipt{}, false, fmt.Errorf("o bucket S3 %q existe, mas o objeto não contém o token desta tentativa; a limpeza automática foi recusada", bucket)
	}
	return Receipt{
		ProviderID: provider.ProviderID(),
		ExternalID: bucket,
		ClaimedAt:  provisional.ClaimedAt,
		Metadata: map[string]string{
			"region":      provider.region,
			"proof_key":   proofKey,
			"proof_token": token,
		},
	}, true, nil
}

func (provider *AWSS3Provider) Release(ctx context.Context, receipt Receipt) (ReleaseReceipt, error) {
	proofKey := receipt.Metadata["proof_key"]
	if receipt.ExternalID == "" || proofKey == "" {
		return ReleaseReceipt{}, fmt.Errorf("recibo de reivindicação S3 incompleto")
	}
	if _, err := provider.client.DeleteObject(ctx, &s3.DeleteObjectInput{Bucket: aws.String(receipt.ExternalID), Key: aws.String(proofKey)}); err != nil && !s3ObjectAlreadyAbsent(err) {
		return ReleaseReceipt{}, fmt.Errorf("excluindo objeto de prova S3: %w", err)
	}
	if _, err := provider.client.DeleteBucket(ctx, &s3.DeleteBucketInput{Bucket: aws.String(receipt.ExternalID)}); err != nil && !s3ObjectAlreadyAbsent(err) {
		return ReleaseReceipt{}, fmt.Errorf("excluindo bucket S3: %w", err)
	}
	return ReleaseReceipt{ReleasedAt: time.Now().UTC(), Details: "O objeto de prova e o bucket S3 foram excluídos"}, nil
}

func s3ObjectAlreadyAbsent(err error) bool {
	var apiError smithy.APIError
	if errors.As(err, &apiError) {
		if apiError.ErrorCode() == "NoSuchBucket" || apiError.ErrorCode() == "NoSuchKey" || apiError.ErrorCode() == "NotFound" {
			return true
		}
	}
	var responseError *smithyhttp.ResponseError
	return errors.As(err, &responseError) && responseError.HTTPStatusCode() == 404
}

func s3BucketDefinitelyAbsent(err error) bool {
	var apiError smithy.APIError
	if errors.As(err, &apiError) && apiError.ErrorCode() == "NoSuchBucket" {
		return true
	}
	var responseError *smithyhttp.ResponseError
	return errors.As(err, &responseError) && responseError.HTTPStatusCode() == http.StatusNotFound
}

func validS3BucketName(bucket string) bool {
	if len(bucket) < 3 || len(bucket) > 63 || strings.Contains(bucket, "..") || net.ParseIP(bucket) != nil {
		return false
	}
	for index, char := range bucket {
		isLetter := char >= 'a' && char <= 'z'
		isDigit := char >= '0' && char <= '9'
		if !isLetter && !isDigit && char != '-' && char != '.' {
			return false
		}
		if (index == 0 || index == len(bucket)-1) && !isLetter && !isDigit {
			return false
		}
	}
	return true
}

// s3BucketFromEndpoint extrai somente o bucket codificado no hostname virtual
// do S3. O hostname analisado nunca é usado como substituto, pois um CNAME como
// assets.example.com -> old-bucket.s3.amazonaws.com reivindica old-bucket, não
// assets.example.com.
func s3BucketFromEndpoint(resource string) (string, error) {
	bucket, _, err := parseS3Endpoint(resource)
	return bucket, err
}

func parseS3Endpoint(resource string) (string, string, error) {
	host := normalizeHost(resource)
	labels := strings.Split(host, ".")
	if host == "" || len(labels) < 4 {
		return "", "", fmt.Errorf("o recurso %q não é um endpoint virtual-hosted do Amazon S3", resource)
	}

	awsIndex := len(labels) - 2
	if labels[len(labels)-2] != "amazonaws" || labels[len(labels)-1] != "com" {
		if len(labels) < 5 || labels[len(labels)-3] != "amazonaws" || labels[len(labels)-2] != "com" || labels[len(labels)-1] != "cn" {
			return "", "", fmt.Errorf("o recurso %q não pertence a um endpoint DNS do Amazon S3", resource)
		}
		awsIndex = len(labels) - 3
	}

	serviceIndex := -1
	for index := awsIndex - 1; index >= 1; index-- {
		if labels[index] == "s3" || strings.HasPrefix(labels[index], "s3-") {
			serviceIndex = index
			break
		}
	}
	if serviceIndex < 1 {
		return "", "", fmt.Errorf("o recurso %q não usa um endpoint virtual-hosted reconhecido do Amazon S3", resource)
	}
	endpointRegion, valid := s3RegionFromServiceLabels(labels[serviceIndex:awsIndex])
	if !valid {
		return "", "", fmt.Errorf("o recurso %q não usa um endpoint virtual-hosted reconhecido do Amazon S3", resource)
	}

	bucket := strings.Join(labels[:serviceIndex], ".")
	if !validS3BucketName(bucket) {
		return "", "", fmt.Errorf("o recurso %q contém um nome de bucket S3 inválido", resource)
	}
	return bucket, endpointRegion, nil
}

func s3RegionFromServiceLabels(labels []string) (string, bool) {
	if len(labels) == 0 {
		return "", false
	}
	service := labels[0]
	suffix := labels[1:]
	switch {
	case service == "s3":
		switch {
		case len(suffix) == 0:
			return "", true
		case len(suffix) == 1 && validAWSRegionLabel(suffix[0]):
			return suffix[0], true
		case len(suffix) == 2 && suffix[0] == "dualstack" && validAWSRegionLabel(suffix[1]):
			return suffix[1], true
		default:
			return "", false
		}
	case service == "s3-website":
		return regionIfValid(suffix, "")
	case strings.HasPrefix(service, "s3-website-"):
		return regionIfValid(suffix, strings.TrimPrefix(service, "s3-website-"))
	case strings.HasPrefix(service, "s3-"):
		return regionIfValid(suffix, strings.TrimPrefix(service, "s3-"))
	default:
		return "", false
	}
}

func regionIfValid(suffix []string, embedded string) (string, bool) {
	if embedded == "" {
		if len(suffix) == 1 && validAWSRegionLabel(suffix[0]) {
			return suffix[0], true
		}
		return "", false
	}
	return embedded, len(suffix) == 0 && validAWSRegionLabel(embedded)
}

func validAWSRegionLabel(value string) bool {
	parts := strings.Split(value, "-")
	if len(parts) < 3 {
		return false
	}
	for _, part := range parts[:len(parts)-1] {
		if part == "" {
			return false
		}
		for _, char := range part {
			if (char < 'a' || char > 'z') && (char < '0' || char > '9') {
				return false
			}
		}
	}
	ordinal := parts[len(parts)-1]
	if ordinal == "" {
		return false
	}
	for _, char := range ordinal {
		if char < '0' || char > '9' {
			return false
		}
	}
	return true
}
