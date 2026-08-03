package verifiers

import (
	"context"
	"net/http"
	"strings"
	"sync"
	"unicode"

	"github.com/amchdd/subdomainabber/internal/core"
	"github.com/amchdd/subdomainabber/internal/domainutil"
)

// Verifier define o contrato para módulos de verificação ativa.
type Verifier interface {
	Name() string
	Verify(ctx context.Context, analysis *core.HostAnalysis) (*core.VerificationResult, error)
}

// Config reúne as dependências compartilhadas pelos verificadores.
type Config struct {
	// Cliente HTTP personalizado para testes e controle de transporte.
	Client *http.Client

	// Opções.
	CheckCloud bool
}

// Engine seleciona e executa os verificadores compatíveis com cada alvo.
type Engine struct {
	takeoverVerifiers []Verifier
	cloudVerifiers    []Verifier
	// Verificadores de configuração que atendem ao mesmo contrato.
	config Config
}

var verifierCNAMEHints = map[string][]string{
	"githubpages":         {"github.io"},
	"azure":               {"azurewebsites.net", "cloudapp.net", "trafficmanager.net"},
	"fastly":              {"fastly.net"},
	"heroku":              {"herokuapp.com", "herokudns.com"},
	"zendesk":             {"zendesk.com"},
	"shopify":             {"myshopify.com"},
	"netlify":             {"netlify.app", "netlify.com"},
	"vercel":              {"vercel.app", "now.sh"},
	"wordpress":           {"wordpress.com"},
	"tumblr":              {"tumblr.com"},
	"bitbucket":           {"bitbucket.io"},
	"ghost":               {"ghost.io"},
	"readmeio":            {"readme.io"},
	"surgesh":             {"surge.sh"},
	"pantheon":            {"pantheonsite.io"},
	"cargocollective":     {"cargocollective.com"},
	"intercom":            {"intercom.help", "custom.intercom.help"},
	"statuspage":          {"statuspage.io"},
	"flyio":               {"fly.dev"},
	"awselasticbeanstalk": {"elasticbeanstalk.com"},
	"awscloudfront":       {"cloudfront.net"},
	"unbounce":            {"unbouncepages.com"},
	"googlecloud":         {"storage.googleapis.com", "web.app", "firebaseapp.com"},
	"awss3":               {"s3.amazonaws.com"},
	"azureblobstorage":    {"blob.core.windows.net"},
	"googlecloudstorage":  {"storage.googleapis.com", "storage.cloud.google.com"},
}

var verifierProviderAliases = map[string][]string{
	"githubpages":        {"github", "githubtakeoverdetection"},
	"azure":              {"microsoftazure"},
	"googlecloud":        {"gcs", "firebasehosting", "googlecloudstorage"},
	"googlecloudstorage": {"gcs", "googlecloud"},
	"awss3":              {"awsbucket"},
}

// NewEngine inicializa o motor de verificação com os provedores padrão, sem autenticação.
func NewEngine(cfg Config) *Engine {
	return &Engine{
		config: cfg,
		takeoverVerifiers: []Verifier{
			NewGitHubPagesVerifier(cfg),
			NewAzureVerifier(cfg),
			NewFastlyVerifier(cfg),
			NewHerokuVerifier(cfg),
			NewZendeskVerifier(cfg),
			NewShopifyVerifier(cfg),
			NewNetlifyVerifier(cfg),
			NewVercelVerifier(cfg),
			NewWordPressVerifier(cfg),
			NewTumblrVerifier(cfg),
			NewBitbucketVerifier(cfg),
			NewGhostVerifier(cfg),
			NewReadmeVerifier(cfg),
			NewSurgeVerifier(cfg),
			NewPantheonVerifier(cfg),
			NewCargoVerifier(cfg),
			NewIntercomVerifier(cfg),
			NewStatusPageVerifier(cfg),
			NewFlyioVerifier(cfg),
			NewAWSElasticBeanstalkVerifier(cfg),
			NewAWSCloudFrontVerifier(cfg),
			NewUnbounceVerifier(cfg),
			NewGoogleCloudVerifier(cfg), // NoSuchBucket (Takeover)
		},
		cloudVerifiers: []Verifier{
			NewAWSVerifier(cfg),
			NewAzureBlobVerifier(cfg),
			NewGCSBucketVerifier(cfg),
		},
	}
}

// Run executa os verificadores em camadas conforme as classificações parciais do host.
func (e *Engine) Run(ctx context.Context, analysis *core.HostAnalysis) {
	if e.config.CheckCloud {
		analysis.AddTestedVector("CLOUD")
	}
	// Camada 1: verificadores de takeover, executados para suspeitos e órfãos.
	if analysis.Classification == "TAKEOVERABLE" || analysis.Classification == "LIKELY_TAKEOVERABLE" || analysis.Classification == "ORPHANED" {
		ctx, cancel := context.WithCancel(ctx)
		defer cancel()

		var wg sync.WaitGroup
		var mu sync.Mutex

		for _, v := range matchingVerifiers(e.takeoverVerifiers, analysis) {
			v := v
			wg.Add(1)
			go func() {
				defer wg.Done()
				res, err := v.Verify(ctx, analysis)
				if err == nil && res != nil && res.Verified {
					mu.Lock()
					if analysis.ActiveVerification == nil {
						// Os verificadores HTTP confirmam uma assinatura do provedor,
						// não a capacidade de reivindicar o recurso. Somente um
						// adaptador de prova pode marcar ControlProven.
						if !res.ControlProven && res.Confidence > 90 {
							res.Confidence = 90
						}
						analysis.ActiveVerification = res
						analysis.VerificationScore = res.Confidence
						cancel() // Interrompe os demais verificadores após encontrar uma correspondência.
					}
					mu.Unlock()
				}
			}()
		}
		wg.Wait()
	}

	// Camada 2: verificadores de exposição em nuvem, executados quando há CNAMEs de provedores de nuvem.
	hasCloudCname := hasProviderCNAME(analysis, "amazonaws.com", "core.windows.net", "googleapis.com")

	// Também verifica se já existe alguma evidência de provedor de nuvem.
	for _, ev := range analysis.Evidences {
		if ev.Type == "CLOUD_PROVIDER_MATCH" {
			hasCloudCname = true
			break
		}
	}

	if hasCloudCname && e.config.CheckCloud {
		var wg sync.WaitGroup
		for _, v := range matchingVerifiers(e.cloudVerifiers, analysis) {
			v := v
			wg.Add(1)
			go func() {
				defer wg.Done()
				_, _ = v.Verify(ctx, analysis)
			}()
		}
		wg.Wait()
	}
}

func matchingVerifiers(available []Verifier, analysis *core.HostAnalysis) []Verifier {
	matched := make([]Verifier, 0, len(available))
	for _, verifier := range available {
		if verifierMatchesAnalysis(verifier.Name(), analysis) {
			matched = append(matched, verifier)
		}
	}
	return matched
}

func verifierMatchesAnalysis(verifierName string, analysis *core.HostAnalysis) bool {
	verifierKey := normalizedProviderText(verifierName)
	if verifierKey == "" {
		return false
	}
	for _, candidate := range analysis.ProviderCandidateSnapshot() {
		if providerTextMatches(verifierKey, candidate.Service) || providerTextMatches(verifierKey, candidate.ProviderID) {
			return true
		}
	}
	for _, evidence := range analysis.Evidences {
		if providerTextMatches(verifierKey, evidence.Source) {
			return true
		}
	}
	for _, cname := range analysis.DNS.CNAME {
		if verifierKey == "awss3" && isS3Endpoint(cname) {
			return true
		}
		for _, hint := range verifierCNAMEHints[verifierKey] {
			if domainutil.MatchDNSName(cname, hint) {
				return true
			}
		}
	}
	return false
}

func providerTextMatches(verifierKey, value string) bool {
	valueKey := normalizedProviderText(value)
	if valueKey == "" {
		return false
	}
	if valueKey == verifierKey {
		return true
	}
	for _, alias := range verifierProviderAliases[verifierKey] {
		if valueKey == alias {
			return true
		}
	}
	return false
}

func normalizedProviderText(value string) string {
	return strings.Map(func(char rune) rune {
		if unicode.IsLetter(char) || unicode.IsDigit(char) {
			return unicode.ToLower(char)
		}
		return -1
	}, value)
}
