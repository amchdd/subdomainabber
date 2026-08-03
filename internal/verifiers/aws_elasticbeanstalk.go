package verifiers

import (
	"context"
	"github.com/amchdd/subdomainabber/internal/core"
)

type AWSElasticBeanstalkVerifier struct{}

func NewAWSElasticBeanstalkVerifier(cfg Config) *AWSElasticBeanstalkVerifier {
	return &AWSElasticBeanstalkVerifier{}
}

func (v *AWSElasticBeanstalkVerifier) Name() string {
	return "AWS Elastic Beanstalk"
}

func (v *AWSElasticBeanstalkVerifier) Verify(ctx context.Context, analysis *core.HostAnalysis) (*core.VerificationResult, error) {
	if len(analysis.DNS.A) == 0 && len(analysis.DNS.CNAME) > 0 {
		return &core.VerificationResult{
			Provider:   v.Name(),
			Verified:   true,
			Confidence: 100,
			Evidence:   "O destino do Amazon Elastic Beanstalk retornou NXDOMAIN; a possibilidade de reivindicação não foi comprovada.",
		}, nil
	}
	return nil, nil
}
