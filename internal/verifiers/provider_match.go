package verifiers

import (
	"net/url"
	"strings"

	"github.com/amchdd/subdomainabber/internal/core"
	"github.com/amchdd/subdomainabber/internal/domainutil"
)

func providerRedirectMatches(rawLocation, pathPrefix string, providerDomains ...string) bool {
	location, err := url.Parse(strings.TrimSpace(rawLocation))
	if err != nil || !location.IsAbs() || (location.Scheme != "http" && location.Scheme != "https") {
		return false
	}

	hostMatches := false
	for _, providerDomain := range providerDomains {
		if domainutil.MatchDNSName(location.Hostname(), providerDomain) {
			hostMatches = true
			break
		}
	}
	if !hostMatches {
		return false
	}
	if pathPrefix == "" {
		return true
	}
	return location.Path == pathPrefix || strings.HasPrefix(location.Path, strings.TrimSuffix(pathPrefix, "/")+"/")
}

func hasProviderCNAME(analysis *core.HostAnalysis, patterns ...string) bool {
	if analysis == nil {
		return false
	}
	for _, cname := range analysis.DNS.CNAME {
		for _, pattern := range patterns {
			if domainutil.MatchDNSName(cname, pattern) {
				return true
			}
		}
	}
	return false
}

func hasS3CNAME(analysis *core.HostAnalysis) bool {
	if analysis == nil {
		return false
	}
	for _, cname := range analysis.DNS.CNAME {
		if isS3Endpoint(cname) {
			return true
		}
	}
	return false
}

// isS3Endpoint reconhece somente endpoints virtual-hosted do S3 controlados
// pela AWS. A fronteira final amazonaws.com é obrigatória; portanto, nomes de
// terceiros que apenas contêm um fragmento do S3 não ativam o verificador.
func isS3Endpoint(host string) bool {
	normalized, err := domainutil.NormalizeHostname(host)
	if err != nil || !domainutil.MatchDNSName(normalized, "amazonaws.com") {
		return false
	}

	labels := strings.Split(normalized, ".")
	if len(labels) < 4 {
		return false
	}
	awsIndex := len(labels) - 2
	for index := awsIndex - 1; index >= 1; index-- {
		service := labels[index]
		suffix := labels[index+1 : awsIndex]
		switch {
		case service == "s3":
			return len(suffix) == 0 ||
				(len(suffix) == 1 && validAWSRegionLabel(suffix[0])) ||
				(len(suffix) == 2 && suffix[0] == "dualstack" && validAWSRegionLabel(suffix[1]))
		case service == "s3-website":
			return len(suffix) == 1 && validAWSRegionLabel(suffix[0])
		case strings.HasPrefix(service, "s3-website-"):
			return len(suffix) == 0 && validAWSRegionLabel(strings.TrimPrefix(service, "s3-website-"))
		case strings.HasPrefix(service, "s3-"):
			return len(suffix) == 0 && validAWSRegionLabel(strings.TrimPrefix(service, "s3-"))
		}
	}
	return false
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
