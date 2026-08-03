package stats

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/amchdd/subdomainabber/internal/classification"
	"github.com/amchdd/subdomainabber/internal/verify"
)

// Service consulta as estatísticas armazenadas no banco.
type Service struct {
	db *sql.DB
}

func NewService(db *sql.DB) *Service {
	return &Service{db: db}
}

// GetStats consolida classificações, transições e tipos de evidência.
func (s *Service) GetStats(ctx context.Context) (*DBStats, error) {
	stats := &DBStats{
		ClassificationCounts: make(map[string]int),
		StateChangeCounts:    make(map[string]int),
	}

	// Total de hosts.
	err := s.db.QueryRowContext(ctx, "SELECT COUNT(1) FROM hosts").Scan(&stats.TotalHosts)
	if err != nil {
		return nil, fmt.Errorf("contando hosts: %w", err)
	}

	// Distribuição das classificações.
	rows, err := s.db.QueryContext(ctx, "SELECT classification, COUNT(1) FROM hosts GROUP BY classification")
	if err != nil {
		return nil, fmt.Errorf("agrupando classificações: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var class string
		var count int
		if err := rows.Scan(&class, &count); err == nil {
			stats.ClassificationCounts[class] = count
		}
	}

	// Mantém todas as classificações na saída, inclusive as sem ocorrências.
	defaultClasses := []string{
		classification.LevelHealthy,
		classification.LevelInsufficientEvidence,
		classification.LevelUnknown,
		classification.LevelMisconfigured,
		classification.LevelExposed,
		classification.LevelOrphaned,
		classification.LevelDelegationBroken,
		classification.LevelDelegationTakeoverCandidate,
		classification.LevelLikelyTakeoverable,
		classification.LevelTakeoverable,
		classification.LevelDelegationClaimabilityVerified,
		classification.LevelConfirmed,
		classification.LevelZoneControlConfirmed,
		classification.LevelTakenOver,
	}
	for _, c := range defaultClasses {
		if _, exists := stats.ClassificationCounts[c]; !exists {
			stats.ClassificationCounts[c] = 0
		}
	}

	// Transições entre a classificação anterior e a atual.
	changeRows, err := s.db.QueryContext(ctx, "SELECT classification, previous_classification FROM hosts WHERE previous_classification != '' AND previous_classification != classification")
	if err == nil {
		defer changeRows.Close()
		for changeRows.Next() {
			var curr, prev string
			if err := changeRows.Scan(&curr, &prev); err == nil {
				state := determineStateChange(prev, curr)
				stats.StateChangeCounts[string(state)]++
			}
		}
	}

	// Tipos de evidência mais frequentes.
	// A extensão JSON1 do SQLite permite percorrer vetores JSON durante a consulta SQL.
	// json_each extrai os elementos do vetor evidences; json_extract obtém o campo "type".
	queryEvidences := `
		SELECT json_extract(value, '$.type') as type, count(1) as c
		FROM hosts, json_each(hosts.evidences)
		GROUP BY type
		ORDER BY c DESC
		LIMIT 20
	`
	evRows, err := s.db.QueryContext(ctx, queryEvidences)
	if err == nil {
		defer evRows.Close()
		for evRows.Next() {
			var evType string
			var count int
			if err := evRows.Scan(&evType, &count); err == nil {
				stats.TopEvidenceTypes = append(stats.TopEvidenceTypes, EvidenceStat{
					Type:  evType,
					Count: count,
				})
			}
		}
	}

	return stats, nil
}

// determineStateChange reimplementa somente a classificação de transições necessária
// às estatísticas, sem acoplar o serviço ao motor completo de verificação.
func determineStateChange(oldClass, newClass string) verify.StateChange {
	if oldClass == newClass {
		return verify.Unchanged
	}
	if newClass == classification.LevelHealthy {
		return verify.Fixed
	}
	if classification.RiskRank(newClass) > classification.RiskRank(oldClass) {
		return verify.Regressed
	}
	if classification.RiskRank(newClass) < classification.RiskRank(oldClass) {
		return verify.Improved
	}
	return verify.Changed
}
