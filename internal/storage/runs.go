package storage

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/amchdd/subdomainabber/internal/core"
)

type Run struct {
	ID             string          `json:"id"`
	Status         string          `json:"status"`
	StartedAt      time.Time       `json:"started_at"`
	FinishedAt     *time.Time      `json:"finished_at,omitempty"`
	TargetCount    int             `json:"target_count"`
	CompletedCount int             `json:"completed_count"`
	Profile        json.RawMessage `json:"profile,omitempty"`
}

func createRunSchema(db *sql.DB) error {
	_, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS scan_runs (
			id TEXT PRIMARY KEY,
			status TEXT NOT NULL,
			started_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			finished_at DATETIME,
			profile_json TEXT NOT NULL DEFAULT 'null',
			target_count INTEGER NOT NULL DEFAULT 0,
			completed_count INTEGER NOT NULL DEFAULT 0
		);
		CREATE TABLE IF NOT EXISTS run_targets (
			run_id TEXT NOT NULL,
			host TEXT NOT NULL,
			status TEXT NOT NULL DEFAULT 'PENDING',
			last_error TEXT NOT NULL DEFAULT '',
			updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			PRIMARY KEY (run_id, host),
			FOREIGN KEY (run_id) REFERENCES scan_runs(id)
		);
		CREATE TABLE IF NOT EXISTS observations (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			run_id TEXT NOT NULL,
			host TEXT NOT NULL,
			analysis_json TEXT NOT NULL,
			observed_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			UNIQUE(run_id, host),
			FOREIGN KEY (run_id) REFERENCES scan_runs(id)
		);
		CREATE INDEX IF NOT EXISTS idx_observations_host ON observations(host, observed_at);
		CREATE INDEX IF NOT EXISTS idx_run_targets_status ON run_targets(run_id, status);
	`)
	return err
}

func (s *Store) StartRun(profile *core.ScanProfile, targets []string) (string, error) {
	id, err := runID()
	if err != nil {
		return "", err
	}
	profileJSON, err := json.Marshal(profile)
	if err != nil {
		return "", fmt.Errorf("serializando perfil da execução: %w", err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return "", err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`INSERT INTO scan_runs (id, status, profile_json, target_count) VALUES (?, 'RUNNING', ?, ?)`, id, string(profileJSON), len(targets)); err != nil {
		return "", fmt.Errorf("iniciando execução: %w", err)
	}
	for _, host := range targets {
		if _, err := tx.Exec(`INSERT OR IGNORE INTO run_targets (run_id, host) VALUES (?, ?)`, id, host); err != nil {
			return "", fmt.Errorf("registrando alvo %s: %w", host, err)
		}
	}
	if err := tx.Commit(); err != nil {
		return "", err
	}
	return id, nil
}

func (s *Store) AddTargets(runID string, targets []string) error {
	if runID == "" || len(targets) == 0 {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, host := range targets {
		if _, err := tx.Exec(`INSERT OR IGNORE INTO run_targets (run_id, host) VALUES (?, ?)`, runID, host); err != nil {
			return fmt.Errorf("registrando alvo %s: %w", host, err)
		}
	}
	if _, err := tx.Exec(`UPDATE scan_runs SET target_count = (SELECT COUNT(*) FROM run_targets WHERE run_id = ?) WHERE id = ?`, runID, runID); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) SaveObservation(runID string, analysis *core.HostAnalysis) error {
	if runID == "" || analysis == nil {
		return nil
	}
	payload, err := json.Marshal(analysis)
	if err != nil {
		return fmt.Errorf("serializando observação: %w", err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err = s.db.Exec(`
		INSERT INTO observations (run_id, host, analysis_json) VALUES (?, ?, ?)
		ON CONFLICT(run_id, host) DO UPDATE SET analysis_json = excluded.analysis_json, observed_at = CURRENT_TIMESTAMP
	`, runID, analysis.Host, string(payload))
	if err != nil {
		return fmt.Errorf("persistindo observação de %s: %w", analysis.Host, err)
	}
	return nil
}

func (s *Store) MarkTarget(runID, host, status string, targetErr error) error {
	if runID == "" {
		return nil
	}
	message := ""
	if targetErr != nil {
		message = targetErr.Error()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	result, err := s.db.Exec(`UPDATE run_targets SET status = ?, last_error = ?, updated_at = CURRENT_TIMESTAMP WHERE run_id = ? AND host = ?`, status, message, runID, host)
	if err != nil {
		return err
	}
	changed, _ := result.RowsAffected()
	if changed > 0 && status != "PENDING" {
		_, err = s.db.Exec(`UPDATE scan_runs SET completed_count = (SELECT COUNT(*) FROM run_targets WHERE run_id = ? AND status != 'PENDING') WHERE id = ?`, runID, runID)
	}
	return err
}

func (s *Store) FinishRun(runID, status string) error {
	if runID == "" {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.Exec(`UPDATE scan_runs SET status = ?, finished_at = CURRENT_TIMESTAMP WHERE id = ?`, status, runID)
	return err
}

func (s *Store) PendingTargets(ctx context.Context, runID string) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT host FROM run_targets WHERE run_id = ? AND status = 'PENDING' ORDER BY host`, runID)
	if err != nil {
		return nil, fmt.Errorf("consultando retomada: %w", err)
	}
	defer rows.Close()
	var targets []string
	for rows.Next() {
		var host string
		if err := rows.Scan(&host); err != nil {
			return nil, err
		}
		targets = append(targets, host)
	}
	return targets, rows.Err()
}

func (s *Store) RunProfile(ctx context.Context, runID string) (*core.ScanProfile, error) {
	var payload string
	if err := s.db.QueryRowContext(ctx, `SELECT profile_json FROM scan_runs WHERE id = ?`, runID).Scan(&payload); err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("execução %s não encontrada", runID)
		}
		return nil, err
	}
	if payload == "" || payload == "null" {
		return nil, nil
	}
	var profile core.ScanProfile
	if err := json.Unmarshal([]byte(payload), &profile); err != nil {
		return nil, fmt.Errorf("interpretando perfil da execução %s: %w", runID, err)
	}
	return &profile, nil
}

func (s *Store) Observations(ctx context.Context, runID string) ([]core.HostAnalysis, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT analysis_json FROM observations WHERE run_id = ? ORDER BY host`, runID)
	if err != nil {
		return nil, fmt.Errorf("consultando observações: %w", err)
	}
	defer rows.Close()
	var analyses []core.HostAnalysis
	for rows.Next() {
		var payload string
		if err := rows.Scan(&payload); err != nil {
			return nil, err
		}
		var analysis core.HostAnalysis
		if err := json.Unmarshal([]byte(payload), &analysis); err != nil {
			return nil, fmt.Errorf("decodificando observação: %w", err)
		}
		analyses = append(analyses, analysis)
	}
	return analyses, rows.Err()
}

func (s *Store) Runs(ctx context.Context, limit int) ([]Run, error) {
	if limit < 1 {
		limit = 20
	}
	rows, err := s.db.QueryContext(ctx, `SELECT id, status, started_at, finished_at, target_count, completed_count, profile_json FROM scan_runs ORDER BY started_at DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var runs []Run
	for rows.Next() {
		var run Run
		var finished sql.NullTime
		var profile string
		if err := rows.Scan(&run.ID, &run.Status, &run.StartedAt, &finished, &run.TargetCount, &run.CompletedCount, &profile); err != nil {
			return nil, err
		}
		if finished.Valid {
			run.FinishedAt = &finished.Time
		}
		run.Profile = json.RawMessage(profile)
		runs = append(runs, run)
	}
	return runs, rows.Err()
}

func runID() (string, error) {
	value := make([]byte, 16)
	if _, err := rand.Read(value); err != nil {
		return "", fmt.Errorf("gerando identificador da execução: %w", err)
	}
	return hex.EncodeToString(value), nil
}
