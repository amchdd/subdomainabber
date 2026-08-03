package fingerprint

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/amchdd/subdomainabber/internal/domainutil"
	"github.com/amchdd/subdomainabber/pkg/signatures"
)

type ValidationReport struct {
	TotalServices int
	SchemaErrors  int
	Duplicates    int
	RegexErrors   int
	Collisions    int
	ConfidenceErr int
	Errors        []string
	Warnings      []string
	CollisionInfo []string
}

func Validate(sigs []signatures.Fingerprint) *ValidationReport {
	report := &ValidationReport{
		TotalServices: len(sigs),
	}

	cnameMap := make(map[string]string)
	serviceMap := make(map[string]bool)
	fingerprintMap := make(map[string]string) // Mapeia fingerprint_string para serviceName.

	for _, sig := range sigs {
		// Valida os campos obrigatórios da assinatura.
		if sig.Service == "" {
			report.SchemaErrors++
			report.Errors = append(report.Errors, "Entrada sem o campo obrigatório 'service'")
		}
		validCNAMEs := 0
		for _, cname := range sig.CNames {
			if strings.TrimSpace(cname) == "" {
				continue
			}
			if _, err := domainutil.NormalizeDNSPattern(cname); err == nil {
				validCNAMEs++
			}
		}
		if validCNAMEs == 0 && (sig.CheckType == "" || sig.CheckType == "cname" || sig.CheckType == "both") {
			report.SchemaErrors++
			report.Errors = append(report.Errors, fmt.Sprintf("Serviço '%s' sem CNAME válido", sig.Service))
		}
		if !hasDetectionMechanism(sig) {
			report.SchemaErrors++
			report.Errors = append(report.Errors, fmt.Sprintf("Serviço '%s' sem campo obrigatório 'fingerprint'", sig.Service))
		}

		// A confiança precisa estar dentro da faixa aceita pelo classificador.
		for _, patterns := range [][]string{sig.NSFingerprints, sig.MXFingerprints, sig.SRVFingerprints, sig.SPFFingerprints} {
			for _, pattern := range patterns {
				if _, err := domainutil.NormalizeDNSProviderPattern(pattern); err != nil {
					report.SchemaErrors++
					report.Errors = append(report.Errors, fmt.Sprintf("Serviço '%s' possui padrão de provedor DNS inválido: '%s'", sig.Service, pattern))
				}
			}
		}

		confidence := effectiveConfidence(sig)
		if invalidValue, invalid := firstInvalidConfidence(sig); invalid {
			report.ConfidenceErr++
			report.Errors = append(report.Errors, fmt.Sprintf("Serviço '%s' tem confidence inválido: %d (deve ser 0-100)", sig.Service, invalidValue))
		} else if confidence == 0 {
			// O valor zero gera um aviso, mas não invalida o catálogo.
			report.Warnings = append(report.Warnings, fmt.Sprintf("Serviço '%s' com confidence 0 (ausente ou zerado)", sig.Service))
		}

		// Detecta serviços duplicados.
		if serviceMap[sig.Service] {
			report.Duplicates++
			report.Errors = append(report.Errors, fmt.Sprintf("Serviço duplicado detectado: '%s'", sig.Service))
		}
		serviceMap[sig.Service] = true

		// Detecta CNAMEs compartilhados por serviços diferentes.
		for _, cname := range sig.CNames {
			if strings.TrimSpace(cname) == "" {
				continue
			}
			if existingSvc, exists := cnameMap[cname]; exists && existingSvc != sig.Service {
				report.Duplicates++
				report.Errors = append(report.Errors, fmt.Sprintf("CNAME duplicado/compartilhado: '%s' está em '%s' e '%s'", cname, existingSvc, sig.Service))
			}
			cnameMap[cname] = sig.Service
		}

		// Valida expressões regulares e informa colisões exatas.
		fp := sig.Fingerprint
		if !sig.NXDomain || fp != "" {
			if sig.IsRegex {
				_, err := regexp.Compile(fp)
				if err != nil {
					report.RegexErrors++
					report.Errors = append(report.Errors, fmt.Sprintf("Serviço '%s' possui expressão regular ou sintaxe inválida: '%s' -> %v", sig.Service, fp, err))
				}
			}

			// Registra colisões exatas entre serviços distintos.
			if fp != "" {
				if existingSvc, exists := fingerprintMap[fp]; exists && existingSvc != sig.Service {
					report.Collisions++
					report.CollisionInfo = append(report.CollisionInfo, fmt.Sprintf("Assinatura exata '%s' aparece em '%s' e '%s'", fp, existingSvc, sig.Service))
				}
				fingerprintMap[fp] = sig.Service
			}
		}
	}

	return report
}

func hasDetectionMechanism(sig signatures.Fingerprint) bool {
	return sig.Fingerprint != "" || sig.Engine != nil || len(sig.CNames) > 0 ||
		len(sig.NSFingerprints) > 0 || len(sig.MXFingerprints) > 0 ||
		len(sig.SRVFingerprints) > 0 || len(sig.TXTFingerprints) > 0 ||
		len(sig.SPFFingerprints) > 0 || len(sig.ASNFingerprints) > 0
}

func effectiveConfidence(sig signatures.Fingerprint) int {
	values := []int{
		sig.Confidence, sig.MXConfidence, sig.SRVConfidence, sig.TXTConfidence,
		sig.SPFConfidence, sig.TLSConfidence, sig.ASNConfidence,
	}
	result := 0
	for _, value := range values {
		if value > result {
			result = value
		}
	}
	return result
}

func firstInvalidConfidence(sig signatures.Fingerprint) (int, bool) {
	values := []int{
		sig.Confidence, sig.MXConfidence, sig.SRVConfidence, sig.TXTConfidence,
		sig.SPFConfidence, sig.TLSConfidence, sig.ASNConfidence,
	}
	for _, value := range values {
		if value < 0 || value > 100 {
			return value, true
		}
	}
	return 0, false
}

func (r *ValidationReport) HasFatalErrors() bool {
	return r.SchemaErrors > 0 || r.Duplicates > 0 || r.RegexErrors > 0 || r.ConfidenceErr > 0
}

func (r *ValidationReport) Print(strict bool) {
	fmt.Println("--- Validação do catálogo de assinaturas ---")
	fmt.Printf("Serviços:              %d\n", r.TotalServices)
	fmt.Printf("Erros de esquema:      %d\n", r.SchemaErrors)
	fmt.Printf("Entradas duplicadas:   %d\n", r.Duplicates)
	fmt.Printf("Erros de regex:        %d\n", r.RegexErrors)
	fmt.Printf("Colisões:              %d\n", r.Collisions)
	fmt.Printf("Erros de confiança:    %d\n\n", r.ConfidenceErr)

	if len(r.Errors) > 0 {
		fmt.Println("Erros:")
		for _, e := range r.Errors {
			fmt.Printf("  - %s\n", e)
		}
		fmt.Println("")
	}

	if len(r.Warnings) > 0 {
		fmt.Println("Avisos:")
		for _, w := range r.Warnings {
			fmt.Printf("  - %s\n", w)
		}
		fmt.Println("")
	}
	if len(r.CollisionInfo) > 0 {
		fmt.Println("Colisões por escopo do provedor:")
		fmt.Println("  Informativas: assinaturas HTTP só podem corresponder ao candidato CNAME do mesmo provedor.")
		for _, collision := range r.CollisionInfo {
			fmt.Printf("  - %s\n", collision)
		}
		fmt.Println("")
	}

	failed := r.HasFatalErrors()
	if strict && len(r.Warnings) > 0 {
		failed = true
	}

	fmt.Print("Status: ")
	if failed {
		fmt.Println("falhou")
	} else {
		fmt.Println("aprovado")
	}
}
