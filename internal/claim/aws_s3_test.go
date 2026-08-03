package claim

import (
	"context"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/smithy-go"

	"github.com/amchdd/subdomainabber/internal/core"
)

type fakeS3Client struct {
	createInput   *s3.CreateBucketInput
	putInput      *s3.PutObjectInput
	headOutput    *s3.HeadObjectOutput
	headBucketErr error
	headObjectErr error
	putErr        error
	deletes       []string
}

func (client *fakeS3Client) HeadBucket(context.Context, *s3.HeadBucketInput, ...func(*s3.Options)) (*s3.HeadBucketOutput, error) {
	if client.headBucketErr == nil {
		return &s3.HeadBucketOutput{}, nil
	}
	return nil, client.headBucketErr
}

func (client *fakeS3Client) CreateBucket(_ context.Context, input *s3.CreateBucketInput, _ ...func(*s3.Options)) (*s3.CreateBucketOutput, error) {
	client.createInput = input
	return &s3.CreateBucketOutput{}, nil
}
func (client *fakeS3Client) PutObject(_ context.Context, input *s3.PutObjectInput, _ ...func(*s3.Options)) (*s3.PutObjectOutput, error) {
	client.putInput = input
	return &s3.PutObjectOutput{}, client.putErr
}
func (client *fakeS3Client) HeadObject(context.Context, *s3.HeadObjectInput, ...func(*s3.Options)) (*s3.HeadObjectOutput, error) {
	return client.headOutput, client.headObjectErr
}
func (client *fakeS3Client) DeleteObject(_ context.Context, input *s3.DeleteObjectInput, _ ...func(*s3.Options)) (*s3.DeleteObjectOutput, error) {
	client.deletes = append(client.deletes, "object:"+aws.ToString(input.Key))
	return &s3.DeleteObjectOutput{}, nil
}
func (client *fakeS3Client) DeleteBucket(_ context.Context, input *s3.DeleteBucketInput, _ ...func(*s3.Options)) (*s3.DeleteBucketOutput, error) {
	client.deletes = append(client.deletes, "bucket:"+aws.ToString(input.Bucket))
	return &s3.DeleteBucketOutput{}, nil
}

func TestAWSS3ProviderClaimsVerifiesAndReleasesCreatedBucket(t *testing.T) {
	client := &fakeS3Client{headBucketErr: &smithy.GenericAPIError{Code: "NoSuchBucket", Message: "absent"}, headOutput: &s3.HeadObjectOutput{Metadata: map[string]string{"subdomainabber-proof": "token123"}}}
	provider := newAWSS3ProviderWithClient(client, "us-east-1")
	receipt, err := provider.Claim(context.Background(), Request{
		Host: "assets.example.com", Resource: "bucket-name.s3.amazonaws.com", ProofToken: "token123",
	})
	if err != nil {
		t.Fatal(err)
	}
	if aws.ToString(client.createInput.Bucket) != "bucket-name" || client.putInput.Metadata["subdomainabber-proof"] != "token123" {
		t.Fatalf("claim inputs = create:%#v put:%#v", client.createInput, client.putInput)
	}
	proof, err := provider.VerifyControl(context.Background(), receipt)
	if err != nil || !proof.Controlled {
		t.Fatalf("proof = %#v, %v", proof, err)
	}
	if _, err := provider.Release(context.Background(), receipt); err != nil {
		t.Fatal(err)
	}
	if len(client.deletes) != 2 || client.deletes[1] != "bucket:bucket-name" {
		t.Fatalf("release calls = %#v", client.deletes)
	}
}

func TestAWSS3ProviderRollsBackBucketWhenProofObjectFails(t *testing.T) {
	client := &fakeS3Client{headBucketErr: &smithy.GenericAPIError{Code: "NoSuchBucket", Message: "absent"}, putErr: errors.New("put failed")}
	provider := newAWSS3ProviderWithClient(client, "us-east-1")
	if _, err := provider.Claim(context.Background(), Request{Host: "assets.example.com", Resource: "bucket-name.s3.amazonaws.com", ProofToken: "token123"}); err == nil {
		t.Fatal("PutObject failure was hidden")
	}
	if len(client.deletes) != 1 || client.deletes[0] != "bucket:bucket-name" {
		t.Fatalf("failed claim did not roll back bucket: %#v", client.deletes)
	}
}

func TestAWSS3ProviderRejectsUnsafeBucketNames(t *testing.T) {
	provider := newAWSS3ProviderWithClient(&fakeS3Client{headBucketErr: &smithy.GenericAPIError{Code: "NoSuchBucket", Message: "absent"}}, "us-east-1")
	for _, resource := range []string{"bad_name.s3.amazonaws.com", "192.0.2.1.s3.amazonaws.com", "a.s3.amazonaws.com", "bucket.s3.amazonaws.com.attacker.example", "s3.amazonaws.com", "bucket.example.com"} {
		if _, err := provider.Claim(context.Background(), Request{Host: "assets.example.com", Resource: resource, ProofToken: "token"}); err == nil {
			t.Fatalf("unsafe S3 resource accepted: %q", resource)
		}
	}
}

func TestAWSS3ProviderRefusesPreexistingBucket(t *testing.T) {
	client := &fakeS3Client{}
	provider := newAWSS3ProviderWithClient(client, "us-east-1")
	if _, err := provider.Claim(context.Background(), Request{Host: "assets.example.com", Resource: "bucket-name.s3.amazonaws.com", ProofToken: "token"}); err == nil {
		t.Fatal("preexisting bucket was treated as a new claim")
	}
	if client.createInput != nil || client.putInput != nil || len(client.deletes) != 0 {
		t.Fatalf("preexisting bucket was mutated: %#v", client)
	}
}

func TestAWSS3ProviderRequiresConfiguredEndpointRegion(t *testing.T) {
	client := &fakeS3Client{headBucketErr: &smithy.GenericAPIError{Code: "NoSuchBucket", Message: "absent"}}
	provider := newAWSS3ProviderWithClient(client, "us-east-1")
	_, err := provider.Claim(context.Background(), Request{
		Host: "assets.example.com", Resource: "bucket-name.s3.eu-west-1.amazonaws.com", ProofToken: "token",
	})
	if err == nil {
		t.Fatal("regional endpoint was claimed in a different configured region")
	}
	if client.createInput != nil {
		t.Fatalf("region mismatch created a bucket: %#v", client.createInput)
	}
}

func TestAWSS3ProviderRejectsIncompleteTemporaryCredentials(t *testing.T) {
	if _, err := NewAWSS3Provider(context.Background(), "us-east-1", "", "", "session-only"); err == nil {
		t.Fatal("session token without access key and secret was accepted")
	}
	if _, err := NewAWSS3Provider(context.Background(), "us-east-1", "access-only", "", ""); err == nil {
		t.Fatal("partial static credentials were accepted")
	}
}

func TestS3BucketFromEndpointRecognizesOnlyVirtualHostedEndpoints(t *testing.T) {
	tests := map[string]string{
		"bucket-name.s3.amazonaws.com":                        "bucket-name",
		"bucket.with.dots.s3.us-west-2.amazonaws.com":         "bucket.with.dots",
		"bucket-name.s3-us-gov-west-1.amazonaws.com":          "bucket-name",
		"bucket-name.s3.dualstack.eu-central-1.amazonaws.com": "bucket-name",
		"bucket-name.s3-website-us-east-1.amazonaws.com":      "bucket-name",
		"bucket-name.s3-website.ap-southeast-2.amazonaws.com": "bucket-name",
		"bucket-name.s3.cn-north-1.amazonaws.com.cn":          "bucket-name",
		"my.s3-test.s3.us-east-1.amazonaws.com":               "my.s3-test",
	}
	for endpoint, expected := range tests {
		bucket, err := s3BucketFromEndpoint(endpoint)
		if err != nil || bucket != expected {
			t.Errorf("s3BucketFromEndpoint(%q) = %q, %v; want %q", endpoint, bucket, err, expected)
		}
	}
}

func TestAWSS3ProviderSupportsRequiresBoundProviderAndEndpoint(t *testing.T) {
	provider := newAWSS3ProviderWithClient(&fakeS3Client{}, "us-east-1")
	valid := core.ProviderCandidate{ProviderID: awsS3ProviderID, Resource: "bucket-name.s3.amazonaws.com"}
	if !provider.Supports(valid) {
		t.Fatal("provider-bound S3 endpoint was rejected")
	}
	for _, candidate := range []core.ProviderCandidate{
		{ProviderID: "attacker", Service: "AWS/S3", Resource: "bucket-name.s3.amazonaws.com"},
		{ProviderID: awsS3ProviderID, Resource: "bucket.s3.amazonaws.com.attacker.example"},
		{ProviderID: awsS3ProviderID, Resource: "s3.amazonaws.com"},
	} {
		if provider.Supports(candidate) {
			t.Fatalf("unsafe candidate accepted: %#v", candidate)
		}
	}
}

func TestAWSS3RecoveryDistinguishesAbsentBucketFromMissingProof(t *testing.T) {
	provider := newAWSS3ProviderWithClient(&fakeS3Client{
		headBucketErr: &smithy.GenericAPIError{Code: "NoSuchBucket", Message: "absent"},
	}, "us-east-1")
	provisional := provisionalReceipt(provider.ProviderID(), Request{
		Resource: "bucket-name.s3.amazonaws.com", ProofToken: "token123",
	})
	if _, found, err := provider.RecoverClaim(context.Background(), provisional); err != nil || found {
		t.Fatalf("absent bucket should be safe to close: found=%t err=%v", found, err)
	}

	provider = newAWSS3ProviderWithClient(&fakeS3Client{
		headObjectErr: &smithy.GenericAPIError{Code: "NoSuchKey", Message: "missing proof"},
	}, "us-east-1")
	if _, found, err := provider.RecoverClaim(context.Background(), provisional); err == nil || found {
		t.Fatalf("existing bucket without proof was treated as absent: found=%t err=%v", found, err)
	}
}
