package learning

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/amchdd/subdomainabber/internal/core"
)

// Candidate representa um padrão recorrente que pode originar uma nova assinatura.
type Candidate struct {
	TargetCNAME   string
	PageTitle     string
	StatusCode    string
	ObservedHosts int
}

type Engine struct {
	db *sql.DB
}

func NewEngine(db *sql.DB) *Engine {
	return &Engine{db: db}
}

// Discover procura anomalias recorrentes no banco de dados.
func (e *Engine) Discover(ctx context.Context, minOccurrences int) ([]Candidate, error) {
	// A consulta percorre os hosts marcados como ORPHANED ou UNKNOWN.
	query := `
		SELECT 
			host,
			dns_records,
			evidences
		FROM hosts 
		WHERE classification IN ('ORPHANED', 'UNKNOWN', 'MISCONFIGURED')
	`
	rows, err := e.db.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("buscando hosts elegíveis: %w", err)
	}
	defer rows.Close()

	// O agrupamento em memória evita uma consulta JSON complexa no SQLite.
	grouping := make(map[string]*Candidate)

	for rows.Next() {
		var host, dnsRaw, evRaw string
		if err := rows.Scan(&host, &dnsRaw, &evRaw); err != nil {
			continue
		}

		var dnsRecords core.DNSRecordSet
		var evidences []core.Evidence

		if err := json.Unmarshal([]byte(dnsRaw), &dnsRecords); err != nil {
			continue
		}
		if err := json.Unmarshal([]byte(evRaw), &evidences); err != nil {
			continue
		}

		// Usa o primeiro destino externo disponível como ponto de agrupamento.
		var targetCNAME string
		if len(dnsRecords.CNAME) > 0 {
			targetCNAME = dnsRecords.CNAME[0]
		} else if len(dnsRecords.NS) > 0 {
			targetCNAME = dnsRecords.NS[0]
		}

		if targetCNAME == "" {
			continue
		}

		// Reduz o destino à base usada no agrupamento do provedor.
		parts := strings.Split(targetCNAME, ".")
		var providerBase string
		if len(parts) > 2 {
			providerBase = strings.Join(parts[len(parts)-2:], ".")
		} else {
			providerBase = targetCNAME
		}

		// Obtém o título e o status da resposta HTTP observada.
		var title, status string
		for _, ev := range evidences {
			if ev.Type == "HTTP_RESPONSE" {
				if t, ok := ev.Metadata["title"]; ok && t != "" {
					title = t
				}
				if s, ok := ev.Metadata["status"]; ok {
					status = s
				}
				break
			}
		}

		if title == "" {
			continue
		}

		key := fmt.Sprintf("%s|%s|%s", providerBase, title, status)
		if cand, exists := grouping[key]; exists {
			cand.ObservedHosts++
		} else {
			grouping[key] = &Candidate{
				TargetCNAME:   providerBase,
				PageTitle:     title,
				StatusCode:    status,
				ObservedHosts: 1,
			}
		}
	}

	var results []Candidate
	for _, cand := range grouping {
		if cand.ObservedHosts >= minOccurrences {
			results = append(results, *cand)
		}
	}

	// Exibe primeiro os padrões com mais ocorrências.
	sort.Slice(results, func(i, j int) bool {
		return results[i].ObservedHosts > results[j].ObservedHosts
	})

	return results, nil
}
