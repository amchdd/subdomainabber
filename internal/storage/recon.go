package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/amchdd/subdomainabber/internal/core"
)

type ReconRun struct {
	ID              string
	Root            string
	Mode            string
	Status          string
	DiscoveredCount int
	StartedAt       time.Time
	FinishedAt      *time.Time
}

func createReconSchema(db *sql.DB) error {
	_, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS recon_runs (
			id TEXT PRIMARY KEY,
			root TEXT NOT NULL,
			mode TEXT NOT NULL,
			status TEXT NOT NULL,
			discovered_count INTEGER NOT NULL DEFAULT 0,
			checkpoint_json TEXT NOT NULL DEFAULT '{}',
			started_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			finished_at DATETIME
		);
		CREATE INDEX IF NOT EXISTS idx_recon_runs_root ON recon_runs(root, started_at DESC);
		CREATE TABLE IF NOT EXISTS recon_names (
			name TEXT PRIMARY KEY,
			root TEXT NOT NULL,
			resolved INTEGER NOT NULL,
			wildcard INTEGER NOT NULL,
			status TEXT NOT NULL,
			a_json TEXT NOT NULL,
			aaaa_json TEXT NOT NULL,
			cname_json TEXT NOT NULL,
			active INTEGER NOT NULL DEFAULT 1,
			first_seen DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			last_seen DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
		);
		CREATE INDEX IF NOT EXISTS idx_recon_names_root ON recon_names(root, active, name);
		CREATE TABLE IF NOT EXISTS recon_origins (
			name TEXT NOT NULL,
			source TEXT NOT NULL,
			method TEXT NOT NULL,
			parent TEXT NOT NULL,
			depth INTEGER NOT NULL,
			first_seen DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			last_seen DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			PRIMARY KEY(name, source, method, parent)
		);
		CREATE TABLE IF NOT EXISTS recon_run_names (
			run_id TEXT NOT NULL,
			name TEXT NOT NULL,
			PRIMARY KEY(run_id, name)
		);
	`)
	return err
}

func (store *Store) StartRecon(root, mode string) (string, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	id, err := runID()
	if err != nil {
		return "", err
	}
	_, err = store.db.Exec(`INSERT INTO recon_runs (id, root, mode, status) VALUES (?, ?, ?, 'RUNNING')`, id, root, mode)
	if err != nil {
		return "", fmt.Errorf("iniciando recon de %s: %w", root, err)
	}
	return id, nil
}

func (store *Store) SaveReconCandidates(runID string, candidates []core.ReconCandidate) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	tx, err := store.db.Begin()
	if err != nil {
		return fmt.Errorf("iniciando persistência do recon: %w", err)
	}
	defer tx.Rollback()
	for _, candidate := range candidates {
		a, err := json.Marshal(candidate.DNS.A)
		if err != nil {
			return err
		}
		aaaa, err := json.Marshal(candidate.DNS.AAAA)
		if err != nil {
			return err
		}
		cnames, err := json.Marshal(candidate.DNS.CNAME)
		if err != nil {
			return err
		}
		_, err = tx.Exec(`
			INSERT INTO recon_names (name, root, resolved, wildcard, status, a_json, aaaa_json, cname_json)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?)
			ON CONFLICT(name) DO UPDATE SET
				root = excluded.root,
				resolved = excluded.resolved,
				wildcard = excluded.wildcard,
				status = excluded.status,
				a_json = excluded.a_json,
				aaaa_json = excluded.aaaa_json,
				cname_json = excluded.cname_json,
				active = 1,
				last_seen = CURRENT_TIMESTAMP
		`, candidate.Name, candidate.Root, candidate.Resolved, candidate.Wildcard, candidate.DNS.Status, string(a), string(aaaa), string(cnames))
		if err != nil {
			return fmt.Errorf("salvando hostname %s: %w", candidate.Name, err)
		}
		if _, err = tx.Exec(`INSERT OR IGNORE INTO recon_run_names (run_id, name) VALUES (?, ?)`, runID, candidate.Name); err != nil {
			return fmt.Errorf("vinculando hostname %s à execução: %w", candidate.Name, err)
		}
		for _, origin := range candidate.Origins {
			_, err = tx.Exec(`
				INSERT INTO recon_origins (name, source, method, parent, depth)
				VALUES (?, ?, ?, ?, ?)
				ON CONFLICT(name, source, method, parent) DO UPDATE SET
					depth = excluded.depth,
					last_seen = CURRENT_TIMESTAMP
			`, candidate.Name, origin.Source, origin.Method, origin.Parent, origin.Depth)
			if err != nil {
				return fmt.Errorf("salvando origem de %s: %w", candidate.Name, err)
			}
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("confirmando persistência do recon: %w", err)
	}
	return nil
}

func (store *Store) SaveReconCheckpoint(runID string, checkpoint core.ReconCheckpoint) error {
	data, err := json.Marshal(checkpoint)
	if err != nil {
		return fmt.Errorf("serializando checkpoint: %w", err)
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	result, err := store.db.Exec(`UPDATE recon_runs SET checkpoint_json = ? WHERE id = ?`, string(data), runID)
	if err != nil {
		return fmt.Errorf("salvando checkpoint: %w", err)
	}
	if count, _ := result.RowsAffected(); count == 0 {
		return fmt.Errorf("execução de recon %s não encontrada", runID)
	}
	return nil
}

func (store *Store) ReconCheckpoint(ctx context.Context, runID string) (core.ReconCheckpoint, error) {
	store.mu.RLock()
	defer store.mu.RUnlock()
	var data string
	if err := store.db.QueryRowContext(ctx, `SELECT checkpoint_json FROM recon_runs WHERE id = ?`, runID).Scan(&data); err != nil {
		return core.ReconCheckpoint{}, fmt.Errorf("consultando checkpoint: %w", err)
	}
	var checkpoint core.ReconCheckpoint
	if err := json.Unmarshal([]byte(data), &checkpoint); err != nil {
		return checkpoint, fmt.Errorf("decodificando checkpoint: %w", err)
	}
	return checkpoint, nil
}

func (store *Store) FinishRecon(runID, status string, count int) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	_, err := store.db.Exec(`UPDATE recon_runs SET status = ?, discovered_count = ?, finished_at = CURRENT_TIMESTAMP WHERE id = ?`, status, count, runID)
	if err != nil {
		return fmt.Errorf("finalizando recon: %w", err)
	}
	return nil
}

func (store *Store) LatestRecon(ctx context.Context, root string) (*ReconRun, error) {
	store.mu.RLock()
	defer store.mu.RUnlock()
	row := store.db.QueryRowContext(ctx, `
		SELECT id, root, mode, status, discovered_count, started_at, finished_at
		FROM recon_runs WHERE root = ? ORDER BY started_at DESC, rowid DESC LIMIT 1
	`, root)
	var run ReconRun
	var finished sql.NullTime
	if err := row.Scan(&run.ID, &run.Root, &run.Mode, &run.Status, &run.DiscoveredCount, &run.StartedAt, &finished); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("consultando última execução de recon: %w", err)
	}
	if finished.Valid {
		run.FinishedAt = &finished.Time
	}
	return &run, nil
}

func (store *Store) ReconCandidates(ctx context.Context, root string, activeOnly bool) ([]core.ReconCandidate, error) {
	store.mu.RLock()
	defer store.mu.RUnlock()
	query := `SELECT name, root, resolved, wildcard, status, a_json, aaaa_json, cname_json FROM recon_names WHERE root = ?`
	if activeOnly {
		query += ` AND active = 1`
	}
	query += ` ORDER BY name`
	return store.readReconCandidates(ctx, query, root)
}

func (store *Store) ReconRunCandidates(ctx context.Context, runID string) ([]core.ReconCandidate, error) {
	store.mu.RLock()
	defer store.mu.RUnlock()
	return store.readReconCandidates(ctx, `
		SELECT names.name, names.root, names.resolved, names.wildcard, names.status,
			names.a_json, names.aaaa_json, names.cname_json
		FROM recon_names names
		JOIN recon_run_names runs ON runs.name = names.name
		WHERE runs.run_id = ?
		ORDER BY names.name
	`, runID)
}

func (store *Store) readReconCandidates(ctx context.Context, query string, args ...any) ([]core.ReconCandidate, error) {
	rows, err := store.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("consultando catálogo de recon: %w", err)
	}
	defer rows.Close()
	var candidates []core.ReconCandidate
	for rows.Next() {
		var candidate core.ReconCandidate
		var a, aaaa, cnames string
		if err := rows.Scan(&candidate.Name, &candidate.Root, &candidate.Resolved, &candidate.Wildcard, &candidate.DNS.Status, &a, &aaaa, &cnames); err != nil {
			return nil, fmt.Errorf("lendo catálogo de recon: %w", err)
		}
		if err := json.Unmarshal([]byte(a), &candidate.DNS.A); err != nil {
			return nil, err
		}
		if err := json.Unmarshal([]byte(aaaa), &candidate.DNS.AAAA); err != nil {
			return nil, err
		}
		if err := json.Unmarshal([]byte(cnames), &candidate.DNS.CNAME); err != nil {
			return nil, err
		}
		origins, err := store.reconOrigins(ctx, candidate.Name)
		if err != nil {
			return nil, err
		}
		candidate.Origins = origins
		candidates = append(candidates, candidate)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("percorrendo catálogo de recon: %w", err)
	}
	return candidates, nil
}

func (store *Store) reconOrigins(ctx context.Context, name string) ([]core.ReconOrigin, error) {
	rows, err := store.db.QueryContext(ctx, `SELECT source, method, parent, depth FROM recon_origins WHERE name = ? ORDER BY source, method, parent`, name)
	if err != nil {
		return nil, fmt.Errorf("consultando origens de %s: %w", name, err)
	}
	defer rows.Close()
	var origins []core.ReconOrigin
	for rows.Next() {
		var origin core.ReconOrigin
		if err := rows.Scan(&origin.Source, &origin.Method, &origin.Parent, &origin.Depth); err != nil {
			return nil, err
		}
		origins = append(origins, origin)
	}
	return origins, rows.Err()
}
