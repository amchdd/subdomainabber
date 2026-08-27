package storage

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/amchdd/subdomainabber/internal/domainutil"
	"github.com/amchdd/subdomainabber/internal/platform"
)

type PlatformSync struct {
	ID          string
	Status      string
	Stage       string
	Platforms   []string
	Full        bool
	TargetCount int
	ScanRunID   string
	LastError   string
	StartedAt   time.Time
	FinishedAt  *time.Time
}

type PlatformWork struct {
	ID               int64
	RunID            string
	Platform         string
	ProgramID        string
	AssetID          string
	Root             string
	AutomatedTooling int
	UserAgent        string
	RequestHeader    string
}

type PlatformRequirement struct {
	Target    string
	Platform  string
	ProgramID string
	Rules     platform.Rules
}

func createPlatformSchema(db *sql.DB) error {
	_, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS platform_sync_runs (
			id TEXT PRIMARY KEY,
			status TEXT NOT NULL,
			stage TEXT NOT NULL DEFAULT 'CATALOG',
			platforms_json TEXT NOT NULL,
			full INTEGER NOT NULL,
			target_count INTEGER NOT NULL DEFAULT 0,
			scan_run_id TEXT NOT NULL DEFAULT '',
			last_error TEXT NOT NULL DEFAULT '',
			started_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			finished_at DATETIME
		);
		CREATE TABLE IF NOT EXISTS platform_programs (
			platform TEXT NOT NULL,
			id TEXT NOT NULL,
			handle TEXT NOT NULL,
			name TEXT NOT NULL,
			state TEXT NOT NULL,
			url TEXT NOT NULL,
			bounty INTEGER NOT NULL,
			rules_json TEXT NOT NULL,
			active INTEGER NOT NULL DEFAULT 1,
			first_seen DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			last_seen DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			PRIMARY KEY(platform, id)
		);
		CREATE TABLE IF NOT EXISTS platform_assets (
			platform TEXT NOT NULL,
			program_id TEXT NOT NULL,
			id TEXT NOT NULL,
			value TEXT NOT NULL,
			type TEXT NOT NULL,
			kind TEXT NOT NULL,
			host TEXT NOT NULL,
			recon_root TEXT NOT NULL,
			eligible INTEGER NOT NULL,
			bounty INTEGER NOT NULL,
			instruction TEXT NOT NULL,
			severity TEXT NOT NULL,
			group_name TEXT NOT NULL,
			scope_hash TEXT NOT NULL,
			active INTEGER NOT NULL DEFAULT 1,
			first_seen DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			last_seen DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			PRIMARY KEY(platform, program_id, id)
		);
		CREATE INDEX IF NOT EXISTS idx_platform_assets_active ON platform_assets(platform, active, eligible);
		CREATE TABLE IF NOT EXISTS platform_targets (
			target TEXT PRIMARY KEY,
			first_seen DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			last_seen DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
		);
		CREATE TABLE IF NOT EXISTS platform_target_links (
			target TEXT NOT NULL,
			platform TEXT NOT NULL,
			program_id TEXT NOT NULL,
			asset_id TEXT NOT NULL,
			last_seen DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			PRIMARY KEY(target, platform, program_id, asset_id)
		);
		CREATE TABLE IF NOT EXISTS platform_sync_queue (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			run_id TEXT NOT NULL,
			platform TEXT NOT NULL,
			program_id TEXT NOT NULL,
			asset_id TEXT NOT NULL,
			recon_root TEXT NOT NULL,
			status TEXT NOT NULL DEFAULT 'PENDING',
			last_error TEXT NOT NULL DEFAULT '',
			updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			UNIQUE(run_id, platform, program_id, asset_id)
		);
		CREATE INDEX IF NOT EXISTS idx_platform_queue_pending ON platform_sync_queue(run_id, status, id);
	`)
	return err
}

func (store *Store) StartPlatformSync(platforms []string, full bool) (string, error) {
	platforms = append([]string(nil), platforms...)
	sort.Strings(platforms)
	data, err := json.Marshal(platforms)
	if err != nil {
		return "", err
	}
	id, err := runID()
	if err != nil {
		return "", err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	_, err = store.db.Exec(`INSERT INTO platform_sync_runs (id, status, platforms_json, full) VALUES (?, 'RUNNING', ?, ?)`, id, string(data), full)
	if err != nil {
		return "", fmt.Errorf("iniciando sincronização: %w", err)
	}
	return id, nil
}

func (store *Store) SavePlatformPrograms(runID, name string, programs []platform.Program) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	tx, err := store.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var full bool
	if err := tx.QueryRow(`SELECT full FROM platform_sync_runs WHERE id = ?`, runID).Scan(&full); err != nil {
		return fmt.Errorf("consultando modo da sincronização: %w", err)
	}
	if _, err := tx.Exec(`UPDATE platform_programs SET active = 0 WHERE platform = ?`, name); err != nil {
		return err
	}
	if _, err := tx.Exec(`UPDATE platform_assets SET active = 0 WHERE platform = ?`, name); err != nil {
		return err
	}
	for _, program := range programs {
		if program.Platform == "" {
			program.Platform = name
		}
		rules, err := json.Marshal(program.Rules)
		if err != nil {
			return err
		}
		_, err = tx.Exec(`
			INSERT INTO platform_programs (platform, id, handle, name, state, url, bounty, rules_json)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?)
			ON CONFLICT(platform, id) DO UPDATE SET
				handle = excluded.handle, name = excluded.name, state = excluded.state,
				url = excluded.url, bounty = excluded.bounty, rules_json = excluded.rules_json,
				active = 1, last_seen = CURRENT_TIMESTAMP
		`, name, program.ID, program.Handle, program.Name, program.State, program.URL, program.Bounty, string(rules))
		if err != nil {
			return fmt.Errorf("salvando programa %s: %w", program.Handle, err)
		}
		for _, asset := range program.Assets {
			if err := store.savePlatformAsset(tx, runID, name, program.ID, asset, full); err != nil {
				return err
			}
		}
	}
	return tx.Commit()
}

func (store *Store) savePlatformAsset(tx *sql.Tx, runID, name, programID string, asset platform.Asset, full bool) error {
	if asset.ID == "" {
		asset.ID = assetID(asset)
	}
	hash := assetID(asset)
	var previous string
	err := tx.QueryRow(`SELECT scope_hash FROM platform_assets WHERE platform = ? AND program_id = ? AND id = ?`, name, programID, asset.ID).Scan(&previous)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	changed := full || previous != hash
	_, err = tx.Exec(`
		INSERT INTO platform_assets (
			platform, program_id, id, value, type, kind, host, recon_root,
			eligible, bounty, instruction, severity, group_name, scope_hash
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(platform, program_id, id) DO UPDATE SET
			value = excluded.value, type = excluded.type, kind = excluded.kind,
			host = excluded.host, recon_root = excluded.recon_root,
			eligible = excluded.eligible, bounty = excluded.bounty,
			instruction = excluded.instruction, severity = excluded.severity,
			group_name = excluded.group_name, scope_hash = excluded.scope_hash,
			active = 1, last_seen = CURRENT_TIMESTAMP
	`, name, programID, asset.ID, asset.Value, asset.Type, asset.Kind, asset.Host, asset.ReconRoot,
		asset.Eligible, asset.Bounty, asset.Instruction, asset.Severity, asset.Group, hash)
	if err != nil {
		return fmt.Errorf("salvando ativo %s: %w", asset.Value, err)
	}
	if changed {
		if _, err := tx.Exec(`DELETE FROM platform_target_links WHERE platform = ? AND program_id = ? AND asset_id = ?`, name, programID, asset.ID); err != nil {
			return err
		}
	}
	if asset.Eligible && asset.Host != "" {
		if err := saveTarget(tx, asset.Host, name, programID, asset.ID); err != nil {
			return err
		}
	}
	if asset.Eligible && asset.Kind == platform.KindWildcard && asset.ReconRoot != "" && changed {
		_, err = tx.Exec(`
			INSERT OR IGNORE INTO platform_sync_queue (run_id, platform, program_id, asset_id, recon_root)
			VALUES (?, ?, ?, ?, ?)
		`, runID, name, programID, asset.ID, asset.ReconRoot)
	}
	return err
}

func (store *Store) PendingPlatformAssets(ctx context.Context, runID string) ([]PlatformWork, error) {
	store.mu.RLock()
	defer store.mu.RUnlock()
	rows, err := store.db.QueryContext(ctx, `
		SELECT queue.id, queue.run_id, queue.platform, queue.program_id, queue.asset_id,
			queue.recon_root, programs.rules_json
		FROM platform_sync_queue queue
		JOIN platform_programs programs
		  ON programs.platform = queue.platform AND programs.id = queue.program_id
		WHERE queue.run_id = ? AND queue.status <> 'COMPLETED'
		ORDER BY queue.id
	`, runID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var works []PlatformWork
	for rows.Next() {
		var work PlatformWork
		var data string
		if err := rows.Scan(&work.ID, &work.RunID, &work.Platform, &work.ProgramID, &work.AssetID, &work.Root, &data); err != nil {
			return nil, err
		}
		var rules platform.Rules
		if err := json.Unmarshal([]byte(data), &rules); err != nil {
			return nil, err
		}
		work.AutomatedTooling = rules.AutomatedTooling
		work.UserAgent = rules.UserAgent
		work.RequestHeader = rules.RequestHeader
		works = append(works, work)
	}
	return works, rows.Err()
}

func (store *Store) SavePlatformTargets(work PlatformWork, targets []string) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	root, err := domainutil.NormalizeHostname(work.Root)
	if err != nil {
		return fmt.Errorf("raiz de recon inválida: %w", err)
	}
	tx, err := store.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, target := range targets {
		target, err = domainutil.NormalizeHostname(target)
		if err != nil || !strings.HasSuffix(target, "."+root) {
			continue
		}
		if err := saveTarget(tx, target, work.Platform, work.ProgramID, work.AssetID); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func saveTarget(tx *sql.Tx, target, name, programID, assetID string) error {
	if _, err := tx.Exec(`
		INSERT INTO platform_targets (target) VALUES (?)
		ON CONFLICT(target) DO UPDATE SET last_seen = CURRENT_TIMESTAMP
	`, target); err != nil {
		return err
	}
	_, err := tx.Exec(`
		INSERT INTO platform_target_links (target, platform, program_id, asset_id)
		VALUES (?, ?, ?, ?)
		ON CONFLICT(target, platform, program_id, asset_id) DO UPDATE SET last_seen = CURRENT_TIMESTAMP
	`, target, name, programID, assetID)
	return err
}

func (store *Store) CompletePlatformAsset(id int64, status, lastError string) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	_, err := store.db.Exec(`UPDATE platform_sync_queue SET status = ?, last_error = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?`, status, lastError, id)
	return err
}

func (store *Store) PlatformTargets(ctx context.Context) ([]string, error) {
	store.mu.RLock()
	defer store.mu.RUnlock()
	rows, err := store.db.QueryContext(ctx, `
		SELECT DISTINCT links.target
		FROM platform_target_links links
		JOIN platform_assets assets
		  ON assets.platform = links.platform AND assets.program_id = links.program_id AND assets.id = links.asset_id
		JOIN platform_programs programs
		  ON programs.platform = assets.platform AND programs.id = assets.program_id
		WHERE assets.active = 1 AND assets.eligible = 1 AND programs.active = 1
		ORDER BY links.target
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var targets []string
	for rows.Next() {
		var target string
		if err := rows.Scan(&target); err != nil {
			return nil, err
		}
		targets = append(targets, target)
	}
	return targets, rows.Err()
}

func (store *Store) ActivePlatformRules(ctx context.Context) ([]PlatformRequirement, error) {
	store.mu.RLock()
	defer store.mu.RUnlock()
	return store.platformRequirements(ctx, `
		SELECT '', platform, id, rules_json
		FROM platform_programs
		WHERE active = 1
		ORDER BY platform, id
	`)
}

func (store *Store) PlatformTargetRules(ctx context.Context) ([]PlatformRequirement, error) {
	store.mu.RLock()
	defer store.mu.RUnlock()
	return store.platformRequirements(ctx, `
		SELECT DISTINCT links.target, programs.platform, programs.id, programs.rules_json
		FROM platform_target_links links
		JOIN platform_assets assets
		  ON assets.platform = links.platform AND assets.program_id = links.program_id AND assets.id = links.asset_id
		JOIN platform_programs programs
		  ON programs.platform = assets.platform AND programs.id = assets.program_id
		WHERE assets.active = 1 AND assets.eligible = 1 AND programs.active = 1
		ORDER BY links.target, programs.platform, programs.id
	`)
}

func (store *Store) platformRequirements(ctx context.Context, query string) ([]PlatformRequirement, error) {
	rows, err := store.db.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var requirements []PlatformRequirement
	for rows.Next() {
		var requirement PlatformRequirement
		var data string
		if err := rows.Scan(&requirement.Target, &requirement.Platform, &requirement.ProgramID, &data); err != nil {
			return nil, err
		}
		if err := json.Unmarshal([]byte(data), &requirement.Rules); err != nil {
			return nil, err
		}
		requirements = append(requirements, requirement)
	}
	return requirements, rows.Err()
}

func (store *Store) SetPlatformSyncStage(runID, stage, scanRunID string) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	_, err := store.db.Exec(`UPDATE platform_sync_runs SET stage = ?, scan_run_id = ? WHERE id = ?`, stage, scanRunID, runID)
	return err
}

func (store *Store) FinishPlatformSync(runID, status string, count int, lastError string) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	_, err := store.db.Exec(`
		UPDATE platform_sync_runs
		SET status = ?, target_count = ?, last_error = ?, finished_at = CURRENT_TIMESTAMP
		WHERE id = ?
	`, status, count, lastError, runID)
	return err
}

func (store *Store) LatestPlatformSync(ctx context.Context) (*PlatformSync, error) {
	store.mu.RLock()
	defer store.mu.RUnlock()
	row := store.db.QueryRowContext(ctx, `
		SELECT id, status, stage, platforms_json, full, target_count, scan_run_id,
			last_error, started_at, finished_at
		FROM platform_sync_runs ORDER BY started_at DESC, rowid DESC LIMIT 1
	`)
	var syncRun PlatformSync
	var data string
	var finished sql.NullTime
	if err := row.Scan(&syncRun.ID, &syncRun.Status, &syncRun.Stage, &data, &syncRun.Full, &syncRun.TargetCount,
		&syncRun.ScanRunID, &syncRun.LastError, &syncRun.StartedAt, &finished); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	if err := json.Unmarshal([]byte(data), &syncRun.Platforms); err != nil {
		return nil, err
	}
	if finished.Valid {
		syncRun.FinishedAt = &finished.Time
	}
	return &syncRun, nil
}

func assetID(asset platform.Asset) string {
	data, _ := json.Marshal(asset)
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:16])
}
