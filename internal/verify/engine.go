package verify

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/amchdd/subdomainabber/internal/classification"
	"github.com/amchdd/subdomainabber/internal/confidence"
	"github.com/amchdd/subdomainabber/internal/core"
	"github.com/amchdd/subdomainabber/internal/dns"
	"github.com/amchdd/subdomainabber/internal/evidence"
	"github.com/amchdd/subdomainabber/internal/storage"
	"github.com/amchdd/subdomainabber/internal/verifiers"
)

type StateChange string

const (
	Discovered StateChange = "DISCOVERED"
	Fixed      StateChange = "FIXED"
	Improved   StateChange = "IMPROVED"
	Regressed  StateChange = "REGRESSED"
	Changed    StateChange = "CHANGED"
	Unchanged  StateChange = "UNCHANGED"
	Incomplete StateChange = "INCOMPLETE"
)

// Result representa o resultado da revalidação de um host.
type Result struct {
	Host              string
	OldClassification string
	NewClassification string
	State             StateChange
	NewAnalysis       *core.HostAnalysis
	Reason            string
	MissingVectors    []string
	UnexpectedVectors []string
}

type Engine struct {
	resolver        *dns.Resolver
	registry        *evidence.Registry
	verifierEngine  *verifiers.Engine
	db              *storage.Store
	signatureDigest string
}

// RequireCompatibleProfile impede transições quando a execução histórica não
// pode ser reproduzida com o mesmo catálogo e os mesmos módulos.
func (e *Engine) RequireCompatibleProfile(signatureDigest string) {
	e.signatureDigest = signatureDigest
}

func NewEngine(res *dns.Resolver, reg *evidence.Registry, vEngine *verifiers.Engine, db *storage.Store) *Engine {
	return &Engine{
		resolver:       res,
		registry:       reg,
		verifierEngine: vEngine,
		db:             db,
	}
}

// Verify analisa novamente o host e emite um evento de diferença de estado.
func (e *Engine) Verify(ctx context.Context, historical *core.HostAnalysis) (*Result, error) {
	if historical == nil {
		return nil, fmt.Errorf("análise histórica ausente")
	}
	if reason := e.profileCompatibilityError(historical.ScanProfile); reason != "" {
		return incompleteResult(historical, reason, nil, nil), nil
	}
	dnsRecords, err := e.resolver.DiscoverProfile(ctx, historical.Host)
	if err != nil {
		return nil, fmt.Errorf("descobrindo o perfil DNS de %s: %w", historical.Host, err)
	}
	if historical.ScanProfile != nil && historical.ScanProfile.CheckSRV && !strings.HasPrefix(historical.Host, "_") {
		base := dns.ExtractRootDomain(historical.Host)
		if historical.ScanProfile.SRVExhaustive || base == "" {
			base = historical.Host
		}
		records, discoverErr := e.resolver.DiscoverCommonSRV(ctx, base, historical.ScanProfile.SRVOwners)
		if discoverErr != nil {
			return nil, fmt.Errorf("falha na enumeração SRV para %s: %w", historical.Host, discoverErr)
		}
		dnsRecords.SRVRecords = mergeSRVRecords(dnsRecords.SRVRecords, records)
		dnsRecords.SRV = dnsRecords.SRV[:0]
		for _, record := range dnsRecords.SRVRecords {
			dnsRecords.SRV = append(dnsRecords.SRV, fmt.Sprintf("%s:%d", record.Target, record.Port))
		}
	}

	analysis := &core.HostAnalysis{
		Host:           historical.Host,
		DNS:            dnsRecords,
		Classification: classification.LevelUnknown,
		ScanProfile:    cloneProfile(historical.ScanProfile),
	}

	if err := e.registry.Run(ctx, analysis); err != nil {
		return nil, fmt.Errorf("coletando evidências de %s: %w", historical.Host, err)
	}

	classification.Process(analysis)

	e.verifierEngine.Run(ctx, analysis)
	if analysis.VerificationScore > 0 {
		analysis.Classification = classification.Classify(analysis)
	}

	// Uma observação antiga e ainda vulnerável reforça o contexto temporal.
	if !historical.FirstSeen.IsZero() {
		daysObserved := time.Since(historical.FirstSeen).Hours() / 24.0
		if daysObserved >= 30 && (analysis.Classification == classification.LevelOrphaned || analysis.Classification == classification.LevelLikelyTakeoverable || analysis.Classification == classification.LevelTakeoverable) {
			analysis.AddEvidence(core.Evidence{
				Type:        "LONG_LIVED_ORPHAN",
				Source:      "HISTORY",
				Description: fmt.Sprintf("O host permanece vulnerável ou abandonado há %.0f dias", daysObserved),
				Weight:      0,
				Confidence:  0,
			})
		}
	}
	confidence.Calculate(analysis)
	missing, unexpected := vectorDifferences(historical.TestedVectors, analysis.TestedVectors)
	if len(missing) > 0 || len(unexpected) > 0 {
		return incompleteResult(historical, "a cobertura efetiva difere da varredura histórica", missing, unexpected), nil
	}

	state := e.determineStateChange(historical.Classification, analysis.Classification)

	// Registra somente a descoberta inicial ou uma transição de estado.
	if state != Unchanged || historical.Classification == "" {
		reason := getTransitionReason(analysis, historical.Classification)
		if err := e.db.SaveSnapshot(analysis, reason); err != nil {
			return nil, fmt.Errorf("salvando instantâneo da transição: %w", err)
		}
	}

	return &Result{
		Host:              historical.Host,
		OldClassification: historical.Classification,
		NewClassification: analysis.Classification,
		State:             state,
		NewAnalysis:       analysis,
	}, nil
}

func (e *Engine) profileCompatibilityError(profile *core.ScanProfile) string {
	if e.signatureDigest == "" {
		return ""
	}
	if profile == nil || profile.Version == 0 {
		return "o registro foi criado antes da persistência do perfil; execute uma nova varredura antes de revalidar"
	}
	if profile.Version != 1 {
		return fmt.Sprintf("a versão %d do perfil histórico não é suportada", profile.Version)
	}
	if profile.SignatureDigest == "" || profile.SignatureDigest != e.signatureDigest {
		return "o catálogo de assinaturas mudou desde a varredura histórica; execute uma nova varredura de referência"
	}
	if profile.CheckFraming {
		return "o laboratório de framing não é repetido automaticamente pela revalidação"
	}
	if profile.Aggressive {
		return "a reivindicação automática não é repetida pelo comando verify"
	}
	return ""
}

func incompleteResult(historical *core.HostAnalysis, reason string, missing, unexpected []string) *Result {
	analysis := &core.HostAnalysis{
		Host:           historical.Host,
		Classification: historical.Classification,
		ScanProfile:    cloneProfile(historical.ScanProfile),
		TestedVectors:  append([]string(nil), historical.TestedVectors...),
	}
	return &Result{
		Host:              historical.Host,
		OldClassification: historical.Classification,
		NewClassification: historical.Classification,
		State:             Incomplete,
		NewAnalysis:       analysis,
		Reason:            reason,
		MissingVectors:    missing,
		UnexpectedVectors: unexpected,
	}
}

func cloneProfile(profile *core.ScanProfile) *core.ScanProfile {
	if profile == nil {
		return nil
	}
	clone := *profile
	clone.SRVOwners = append([]string(nil), profile.SRVOwners...)
	return &clone
}

func vectorDifferences(expected, actual []string) ([]string, []string) {
	expectedSet := normalizedVectorSet(expected)
	actualSet := normalizedVectorSet(actual)
	var missing, unexpected []string
	for vector := range expectedSet {
		if _, ok := actualSet[vector]; !ok {
			missing = append(missing, vector)
		}
	}
	for vector := range actualSet {
		if _, ok := expectedSet[vector]; !ok {
			unexpected = append(unexpected, vector)
		}
	}
	sort.Strings(missing)
	sort.Strings(unexpected)
	return missing, unexpected
}

func normalizedVectorSet(vectors []string) map[string]struct{} {
	set := make(map[string]struct{})
	for _, vector := range vectors {
		vector = strings.ToUpper(strings.TrimSpace(vector))
		if vector != "" {
			set[vector] = struct{}{}
		}
	}
	return set
}

func mergeSRVRecords(existing, additional []core.SRVRecord) []core.SRVRecord {
	seen := make(map[string]struct{}, len(existing)+len(additional))
	merged := make([]core.SRVRecord, 0, len(existing)+len(additional))
	for _, records := range [][]core.SRVRecord{existing, additional} {
		for _, record := range records {
			key := fmt.Sprintf("%s|%d|%d|%d|%s", record.Owner, record.Priority, record.Weight, record.Port, record.Target)
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			merged = append(merged, record)
		}
	}
	return merged
}

func getTransitionReason(analysis *core.HostAnalysis, oldClass string) string {
	if oldClass == "" {
		return "Descoberta inicial"
	}
	if analysis.Classification == classification.LevelHealthy {
		return "O host foi corrigido ou os recursos órfãos foram removidos"
	}
	if analysis.VerificationScore == 100 && analysis.ActiveVerification != nil && analysis.ActiveVerification.Verified && analysis.ActiveVerification.ControlProven {
		return "A verificação ativa comprovou o controle do recurso"
	}
	if analysis.UnknownProvider != nil {
		return "Domínio raiz desconhecido detectado: " + analysis.UnknownProvider.RootDomain
	}
	return "Vulnerabilidade ou configuração incorreta identificada pelas assinaturas"
}

// GetTransitionSeverity retorna a severidade de uma transição entre classificações.
func GetTransitionSeverity(oldClass, newClass string) string {
	if oldClass == newClass {
		return "NONE"
	}

	oldRank := classification.RiskRank(oldClass)
	newRank := classification.RiskRank(newClass)
	if newRank <= oldRank {
		return "LOW"
	}

	switch {
	case newRank >= classification.RiskRank(classification.LevelTakeoverable):
		return "CRITICAL"
	case newRank >= classification.RiskRank(classification.LevelOrphaned):
		return "HIGH"
	default:
		return "MEDIUM"
	}
}

func (e *Engine) determineStateChange(oldClass, newClass string) StateChange {
	if oldClass == newClass {
		return Unchanged
	}

	// Uma classificação saudável encerra um estado anterior de risco.
	if newClass == classification.LevelHealthy {
		return Fixed
	}

	oldSev := classification.RiskRank(oldClass)
	newSev := classification.RiskRank(newClass)

	if newSev > oldSev {
		return Regressed
	}

	if newSev < oldSev {
		return Improved
	}

	return Changed
}
