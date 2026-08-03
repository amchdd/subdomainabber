package discovery

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/amchdd/subdomainabber/internal/dns"
	"github.com/amchdd/subdomainabber/internal/domainutil"
)

const maxWhoisPivotResponseBytes = 4 << 20

// WhoisPivotService usa dados WHOIS reversos para localizar domínios relacionados.
type WhoisPivotService struct {
	client *http.Client
}

func NewWhoisPivotService(clients ...*http.Client) *WhoisPivotService {
	var client *http.Client
	if len(clients) > 0 {
		client = clients[0]
	}
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	return &WhoisPivotService{client: client}
}

func (s *WhoisPivotService) Pivot(ctx context.Context, targetDomain string) ([]string, error) {
	targetDomain, err := domainutil.NormalizeHostname(targetDomain)
	if err != nil {
		return nil, fmt.Errorf("domínio inválido para pivot WHOIS: %w", err)
	}
	targetRoot := dns.ExtractRootDomain(targetDomain)
	if targetRoot == "" {
		return nil, fmt.Errorf("não foi possível determinar o domínio registrável de %q", targetDomain)
	}
	// Obtém pelo RDAP a organização associada ao registrante.
	rdapURL := fmt.Sprintf("https://rdap.org/domain/%s", targetRoot)
	req, err := http.NewRequestWithContext(ctx, "GET", rdapURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/rdap+json")

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("consulta RDAP falhou: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("consulta RDAP retornou status HTTP %d", resp.StatusCode)
	}

	var rdapData struct {
		Entities []struct {
			Roles      []string      `json:"roles"`
			VcardArray []interface{} `json:"vcardArray"`
		} `json:"entities"`
	}
	if err := decodeLimitedJSON(resp.Body, &rdapData, "RDAP"); err != nil {
		return nil, err
	}

	var orgName string
	for _, entity := range rdapData.Entities {
		isRegistrant := false
		for _, role := range entity.Roles {
			if strings.EqualFold(role, "registrant") {
				isRegistrant = true
				break
			}
		}
		if isRegistrant && len(entity.VcardArray) > 1 {
			if vcards, ok := entity.VcardArray[1].([]interface{}); ok {
				for _, prop := range vcards {
					if p, ok := prop.([]interface{}); ok && len(p) >= 4 {
						if name, ok := p[0].(string); ok && name == "org" {
							if val, ok := p[3].(string); ok {
								orgName = val
								break
							}
						}
					}
				}
			}
		}
	}

	if orgName == "" || strings.Contains(strings.ToLower(orgName), "redacted") || strings.Contains(strings.ToLower(orgName), "privacy") {
		return nil, fmt.Errorf("nenhuma organização de registrante utilizável foi encontrada no RDAP (ausente ou ocultada por GDPR)")
	}

	// Pesquisa no crt.sh os certificados associados à organização encontrada.
	// O filtro de organização usa o formato ?q=O="Org Name".
	crtshURL := fmt.Sprintf("https://crt.sh/?q=%s&output=json", url.QueryEscape(`O="`+orgName+`"`))
	reqCrt, err := http.NewRequestWithContext(ctx, "GET", crtshURL, nil)
	if err != nil {
		return nil, err
	}

	respCrt, err := s.client.Do(reqCrt)
	if err != nil {
		return nil, fmt.Errorf("pivot no crt.sh falhou: %w", err)
	}
	defer respCrt.Body.Close()

	if respCrt.StatusCode != 200 {
		return nil, fmt.Errorf("crt.sh retornou status HTTP %d", respCrt.StatusCode)
	}

	var crtData []struct {
		NameValue string `json:"name_value"`
	}
	if err := decodeLimitedJSON(respCrt.Body, &crtData, "crt.sh"); err != nil {
		return nil, err
	}

	uniqueDomains := make(map[string]bool)
	var siblings []string

	for _, entry := range crtData {
		for _, sub := range strings.Split(entry.NameValue, "\n") {
			sub = strings.ToLower(strings.TrimSpace(sub))
			sub = strings.TrimPrefix(sub, "*.")
			if _, err := domainutil.NormalizeHostname(sub); err != nil {
				continue
			}
			root := dns.ExtractRootDomain(sub)
			if root != "" && root != targetRoot && !uniqueDomains[root] {
				uniqueDomains[root] = true
				siblings = append(siblings, root)
			}
		}
	}

	return siblings, nil
}

func decodeLimitedJSON(reader io.Reader, destination interface{}, source string) error {
	data, err := io.ReadAll(io.LimitReader(reader, maxWhoisPivotResponseBytes+1))
	if err != nil {
		return fmt.Errorf("falha ao ler a resposta de %s: %w", source, err)
	}
	if len(data) > maxWhoisPivotResponseBytes {
		return fmt.Errorf("a resposta de %s excedeu o limite de %d bytes", source, maxWhoisPivotResponseBytes)
	}
	if err := json.Unmarshal(data, destination); err != nil {
		return fmt.Errorf("falha ao decodificar JSON de %s: %w", source, err)
	}
	return nil
}
