package presentation

import (
	"strings"

	"github.com/amchdd/subdomainabber/internal/classification"
	"github.com/amchdd/subdomainabber/internal/core"
	"github.com/amchdd/subdomainabber/internal/verify"
)

// Classification mantém os identificadores persistidos estáveis e traduz
// apenas a forma apresentada ao usuário.
func Classification(value string) string {
	switch value {
	case classification.LevelTakenOver:
		return "CONTROLE DO RECURSO COMPROVADO"
	case classification.LevelConfirmed:
		return "REIVINDICABILIDADE COMPROVADA"
	case classification.LevelTakeoverable:
		return "TAKEOVER POSSÍVEL"
	case classification.LevelLikelyTakeoverable:
		return "TAKEOVER PROVÁVEL"
	case classification.LevelZoneControlConfirmed:
		return "CONTROLE DA ZONA CONFIRMADO"
	case classification.LevelDelegationClaimabilityVerified:
		return "REIVINDICABILIDADE DA DELEGAÇÃO CONFIRMADA"
	case classification.LevelDelegationTakeoverCandidate:
		return "CANDIDATO A TAKEOVER DE DELEGAÇÃO"
	case classification.LevelDelegationBroken:
		return "DELEGAÇÃO QUEBRADA"
	case classification.LevelExposed:
		return "EXPOSIÇÃO"
	case classification.LevelOrphaned:
		return "RECURSO ÓRFÃO"
	case classification.LevelMisconfigured:
		return "CONFIGURAÇÃO INCORRETA"
	case classification.LevelUnknown:
		return "DESCONHECIDO"
	case classification.LevelInsufficientEvidence:
		return "EVIDÊNCIA INSUFICIENTE"
	case classification.LevelHealthy:
		return "SAUDÁVEL"
	case "":
		return "SEM CLASSIFICAÇÃO"
	default:
		return strings.ReplaceAll(value, "_", " ")
	}
}

func StateChange(value verify.StateChange) string {
	switch value {
	case verify.Discovered:
		return "DESCOBERTO"
	case verify.Fixed:
		return "CORRIGIDO"
	case verify.Improved:
		return "MELHOROU"
	case verify.Regressed:
		return "REGREDIU"
	case verify.Changed:
		return "ALTERADO"
	case verify.Unchanged:
		return "SEM ALTERAÇÃO"
	case verify.Incomplete:
		return "REVALIDAÇÃO INCONCLUSIVA"
	default:
		return strings.ReplaceAll(string(value), "_", " ")
	}
}

func Severity(value string) string {
	switch strings.ToUpper(strings.TrimSpace(value)) {
	case "INFO":
		return "INFORMATIVA"
	case "LOW":
		return "BAIXA"
	case "MEDIUM", "WARNING":
		return "MÉDIA"
	case "HIGH":
		return "ALTA"
	case "CRITICAL":
		return "CRÍTICA"
	default:
		return value
	}
}

func Confidence(value string) string {
	switch strings.ToUpper(strings.TrimSpace(value)) {
	case "HIGH":
		return "ALTA"
	case "MEDIUM":
		return "MÉDIA"
	case "LOW":
		return "BAIXA"
	default:
		return value
	}
}

func Rule(value string) string {
	switch strings.ToUpper(strings.TrimSpace(value)) {
	case "HTTP_BLOCKED_NO_EXPOSURE":
		return "HTTP bloqueado sem exposição"
	case "EDGE_BLOCKED_NO_EXPOSURE":
		return "borda bloqueada sem exposição"
	case "HTTP_RESOURCE_NOT_AVAILABLE":
		return "recurso HTTP indisponível"
	case "HTTP_ERROR_NO_EXPOSURE":
		return "erro HTTP sem exposição"
	case "PLAINTEXT_WEB_CONTENT":
		return "conteúdo web disponível sem TLS"
	case "PLAINTEXT_AUTH_INTERFACE":
		return "interface de autenticação disponível sem TLS"
	case "SENSITIVE_COOKIE_OVER_HTTP":
		return "cookie sensível emitido por HTTP"
	case "REDIRECT_DESTINATION_DNS_MISSING":
		return "destino DNS do redirect ausente"
	case "REDIRECT_DESTINATION_INCONCLUSIVE":
		return "destino do redirect inconclusivo"
	case "CSP_HARDENING_ONLY":
		return "observação de hardening CSP"
	case "HSTS_POSTURE_ONLY":
		return "observação de postura HSTS"
	case "HTTP_HTTPS_UPGRADE":
		return "upgrade HTTP para HTTPS"
	case "TIMEOUT":
		return "tempo esgotado"
	case "TLS_ERROR":
		return "erro TLS"
	case "DNS_SERVFAIL":
		return "DNS SERVFAIL"
	case "CONNECTION_REFUSED":
		return "conexão recusada"
	case "INSUFFICIENT_EVIDENCE":
		return "evidência insuficiente"
	case "UNSUPPORTED_PROTOCOL":
		return "protocolo não suportado"
	default:
		return value
	}
}

func Reason(value string) string {
	upper := strings.ToUpper(strings.TrimSpace(value))
	switch {
	case strings.HasPrefix(upper, "HTTP_STATUS_"):
		return "status HTTP " + strings.TrimPrefix(upper, "HTTP_STATUS_")
	case strings.HasPrefix(upper, "HTTPS_STATUS_"):
		return "status HTTPS " + strings.TrimPrefix(upper, "HTTPS_STATUS_")
	case strings.HasPrefix(upper, "EDGE_PROVIDER_"):
		provider := strings.TrimPrefix(upper, "EDGE_PROVIDER_")
		return "provedor de borda " + strings.ReplaceAll(provider, "_", " ")
	}
	switch upper {
	case "HTTP_NO_HTTPS_UPGRADE":
		return "HTTP sem upgrade para HTTPS"
	case "HTTP_REDIRECTS_TO_HTTPS":
		return "HTTP redireciona para HTTPS"
	case "HTTPS_REDIRECTS_TO_HTTP":
		return "HTTPS redireciona para HTTP"
	case "EDGE_RESPONSE":
		return "resposta de borda ou CDN"
	case "HTML_CONTENT":
		return "conteúdo HTML"
	case "PASSWORD_FORM":
		return "formulário com campo de senha"
	case "SENSITIVE_COOKIE_WITHOUT_SECURE":
		return "cookie sensível sem Secure"
	case "HTTP_HTTPS_CONTENT_SIMILAR", "SIMILAR_CONTENT":
		return "conteúdo HTTP e HTTPS semelhante"
	case "SAME_STATUS":
		return "mesmo status HTTP e HTTPS"
	case "SAME_SERVER":
		return "mesmo servidor HTTP e HTTPS"
	case "HTTPS_RESPONSE":
		return "resposta HTTPS observada"
	case "HSTS_ABSENT":
		return "HSTS ausente"
	case "CSP_ABSENT":
		return "CSP ausente"
	case "HTTPS_STATUS_2XX":
		return "resposta HTTPS bem-sucedida"
	case "REDIRECT_LOCATION_PRESENT":
		return "cabeçalho Location presente"
	case "DESTINATION_NXDOMAIN":
		return "destino NXDOMAIN"
	case "DESTINATION_NO_DATA":
		return "destino sem registros A/AAAA"
	case "UNSUPPORTED_PROTOCOL":
		return "protocolo não suportado"
	default:
		return value
	}
}

// Value traduz estados estruturados somente na apresentação. Códigos de
// protocolo como NXDOMAIN, SERVFAIL e REFUSED permanecem inalterados.
func Value(value string) string {
	switch strings.ToUpper(strings.TrimSpace(value)) {
	case "NOT_CHECKED":
		return "NÃO VERIFICADA"
	case "NOT_VERIFIED":
		return "NÃO COMPROVADA"
	case "MANUAL_REVIEW":
		return "REVISÃO MANUAL"
	case "PROVIDER_VERIFIED":
		return "VERIFICADA PELO PROVEDOR"
	case "CONTROL_CONFIRMED", "CONTROLLED":
		return "CONTROLE CONFIRMADO"
	case "NOT_CLAIMABLE":
		return "NÃO REIVINDICÁVEL"
	case "RESOLVED":
		return "RESOLVIDO"
	case "NO_DATA":
		return "SEM DADOS"
	case "TIMEOUT":
		return "TEMPO ESGOTADO"
	case "ERROR":
		return "ERRO"
	case "PROVIDER_OWNED":
		return "PERTENCE AO PROVEDOR"
	case "PRIMARY":
		return "PRIMÁRIO"
	case "FALLBACK":
		return "CONTINGÊNCIA"
	case "POSSIBLY_RESIDUAL":
		return "POSSIVELMENTE RESIDUAL"
	case "RELATED_PROVIDER_PRESENT":
		return "PROVEDOR RELACIONADO PRESENTE"
	case "EXTERNAL_UNVERIFIED":
		return "EXTERNO NÃO VERIFICADO"
	case "NOT_TESTED":
		return "NÃO TESTADA"
	case "NOT_APPLICABLE":
		return "NÃO APLICÁVEL"
	case "OBSERVATION":
		return "OBSERVAÇÃO"
	case "CANDIDATE":
		return "CANDIDATO"
	case "CONFIRMED":
		return "CONFIRMADO"
	case "SUPPRESSED":
		return "SUPRIMIDO"
	case "INCONCLUSIVE":
		return "INCONCLUSIVO"
	case "HEALTHY":
		return "SAUDÁVEL"
	case "EDGE_RESPONSE":
		return "RESPOSTA DE BORDA"
	case "APPLICATION_RESPONSE":
		return "RESPOSTA DE APLICAÇÃO"
	case "RESOURCE_NOT_AVAILABLE":
		return "RECURSO INDISPONÍVEL"
	case "NO_DIFFERENCE":
		return "SEM DIFERENÇA"
	case "TRANSPORT_FAILURE":
		return "FALHA DE TRANSPORTE"
	case "REJECTED":
		return "REJEITADA"
	case "REPRODUCIBLE_DIFFERENTIAL":
		return "DIFERENCIAL REPRODUZÍVEL"
	case "REVEALED_PROVIDER_FINGERPRINT":
		return "ASSINATURA DO PROVEDOR REVELADA"
	case "FRAMING_DIFFERENTIAL":
		return "DIFERENCIAL DE FRAMING"
	case "FRAMING_REJECTED":
		return "FRAMING REJEITADO"
	case "FRAMING_TRANSPORT_FAILURE":
		return "FALHA DE TRANSPORTE NO FRAMING"
	case "FRAMING_NO_DIFFERENCE":
		return "FRAMING SEM DIFERENÇA"
	case "":
		return ""
	default:
		return value
	}
}

func EvidenceDescription(evidence core.Evidence) string {
	switch evidence.Type {
	case "HTTP_HSTS_MISSING":
		return "cabeçalho Strict-Transport-Security ausente na resposta HTTPS"
	case "HTTP_CSP_MISSING":
		return "cabeçalho Content-Security-Policy ausente na resposta HTTPS"
	case "NS_PROVIDER_MATCH":
		return "a delegação afetada usa um provedor DNS conhecido"
	case "CNAME_RESOLUTION_INCONCLUSIVE":
		return "a resolução do último CNAME foi inconclusiva; isso não prova abandono"
	case "STALE_CLOUD_IP_CANDIDATE":
		return "o IP de nuvem está inacessível por HTTP e possui sinal TLS de abandono; a possibilidade de realocação não foi comprovada"
	case "EMAIL_DMARC_MISSING":
		return "nenhuma política DMARC foi encontrada"
	case "EMAIL_SPF_MISSING":
		return "o domínio possui registros MX, mas não publica uma política SPF"
	case "HTTP_OPEN_REDIRECT":
		return "o host aceitou um redirecionamento para destino externo"
	case "DANGLING_REDIRECT":
		return "a cadeia termina em um hostname inexistente ou recurso removido"
	case "HTTP_HTTPS_REDIRECT_MISSING":
		return "o endpoint HTTP não faz upgrade direto para HTTPS no mesmo hostname"
	case "HTTP_NO_HTTPS_UPGRADE":
		return "o endpoint HTTP não conclui o upgrade para HTTPS"
	case "HTTP_BLOCKED_WITHOUT_REDIRECT":
		return "a resposta HTTP bloqueia o conteúdo sem demonstrar exposição da aplicação"
	case "HTTP_EDGE_BLOCK":
		return "a resposta sem upgrade foi produzida pela borda ou pelo CDN"
	case "PLAINTEXT_WEB_CONTENT":
		return "conteúdo HTML navegável está disponível por HTTP"
	case "PLAINTEXT_AUTH_INTERFACE":
		return "um formulário com campo de senha está disponível por HTTP"
	case "HTTP_SENSITIVE_COOKIE_WITHOUT_SECURE":
		return "cookie sensível da aplicação foi emitido por HTTP sem Secure"
	case "HTTPS_HSTS_ABSENT":
		return "HSTS não foi observado; trata-se de postura de transporte"
	case "HTTPS_CSP_ABSENT":
		return "CSP não foi observada em uma página HTML 2xx; trata-se de hardening"
	case "HTTP_HTTPS_PORT_INCONSISTENT":
		return "o upgrade redireciona para uma porta HTTPS não convencional"
	case "HTTPS_DOWNGRADE_REDIRECT":
		return "o endpoint HTTPS redireciona para HTTP"
	case "CSP_DANGLING_DEPENDENCY":
		return "a política CSP confia em um host órfão vinculado a provedor conhecido"
	case "SUBRESOURCE_DANGLING", "DEAD_ASSET_REFERENCE":
		return "a página referencia um recurso em host órfão vinculado a provedor conhecido"
	case "DEAD_ASSET_HTTP":
		return "a página referencia um asset que responde como removido"
	case "ORIGIN_DIRECT_MATCH":
		return "um destino permitido reproduziu a aplicação com o Host e o SNI originais"
	case "ORIGIN_EXPOSURE_CANDIDATE":
		return "um cabeçalho revelou um candidato a origin; a alcançabilidade direta não foi confirmada"
	case "TLS_CERTIFICATE_DRIFT":
		return "issuer, SAN ou provider mudou desde a coleta anterior"
	case "SNI_CERT_MISMATCH":
		return "o mesmo IP apresentou outro certificado com SNI ausente ou alternativo"
	case "DNSSEC_BOGUS":
		return "a validação DNSSEC falha, mas a consulta com verificação desabilitada recebe resposta"
	case "DNSSEC_SERVFAIL_INCONCLUSIVE":
		return "a consulta retorna SERVFAIL mesmo sem validação DNSSEC; a causa permanece inconclusiva"
	case "MX_PRIMARY_BROKEN_WITH_FALLBACK":
		return "o MX prioritário falhou, mas há um destino alternativo resolvível"
	case "MX_BACKUP_BROKEN":
		return "um MX de contingência falhou enquanto outro destino continua resolvível"
	case "CAA_POLICY_INCONSISTENT":
		return "as políticas CAA do hostname e da zona registrável divergem"
	case "CAA_ISSUER_MISMATCH":
		return "o emissor do certificado observado não aparece na política CAA efetiva"
	case "TXT_OWNERSHIP_TOKEN_RESIDUAL":
		return "o token de propriedade pode ser residual; isso não comprova vínculo nem exploração"
	case "PROVIDER_MIGRATION_DETECTED":
		return "o provedor observado mudou desde a varredura anterior"
	case "PROVIDER_MIGRATION_STALE_REFERENCE":
		return "a referência ao provedor anterior permanece após a migração"
	case "RELATED_DOMAIN_COOKIE_SCOPE":
		return "o domínio registrável define cookie com escopo que inclui o subdomínio candidato"
	case "RELATED_DOMAIN_CORS_CREDENTIALS":
		return "o domínio registrável confia na origem candidata e permite credenciais"
	default:
		return evidence.Description
	}
}
