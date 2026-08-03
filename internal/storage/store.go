package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	_ "modernc.org/sqlite"

	"github.com/amchdd/subdomainabber/internal/core"
)

// Store encapsula o acesso ao banco de dados SQLite para persistir HostAnalysis.
type Store struct {
	db *sql.DB
	mu sync.RWMutex
}

// GetDB retorna a conexão bruta com o banco de dados para consultas avançadas.
func (s *Store) GetDB() *sql.DB {
	return s.db
}

// New cria uma nova instância de Store e executa a criação do esquema.
func New(dbPath string) (*Store, error) {
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("abrindo banco de dados %q: %w", dbPath, err)
	}

	pragmas := []string{
		"PRAGMA journal_mode = WAL;",
		"PRAGMA synchronous = NORMAL;",
		"PRAGMA busy_timeout = 5000;",
	}
	for _, p := range pragmas {
		if _, err := db.Exec(p); err != nil {
			db.Close()
			return nil, fmt.Errorf("executando %s: %w", p, err)
		}
	}

	schema := `CREATE TABLE IF NOT EXISTS hosts (
		host           TEXT PRIMARY KEY,
		classification TEXT,
		risk_score     INTEGER,
		mitigation_score INTEGER,
		confidence_score INTEGER,
		dns_records    TEXT,
		evidences      TEXT,
		tested_vectors TEXT NOT NULL DEFAULT '[]',
		scan_profile   TEXT NOT NULL DEFAULT 'null',
		first_seen     DATETIME DEFAULT CURRENT_TIMESTAMP,
		last_seen      DATETIME DEFAULT CURRENT_TIMESTAMP,
		previous_classification TEXT DEFAULT '',
		last_state_change       DATETIME DEFAULT CURRENT_TIMESTAMP
	);`
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("criando esquema: %w", err)
	}

	schemaUP := `CREATE TABLE IF NOT EXISTS unknown_providers (
		root_domain TEXT PRIMARY KEY,
		frequency INTEGER DEFAULT 1,
		severity TEXT,
		first_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
		last_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
		example_hosts TEXT DEFAULT '[]',
		last_discovery_score REAL DEFAULT 0.0
	);`
	if _, err := db.Exec(schemaUP); err != nil {
		db.Close()
		return nil, fmt.Errorf("criando esquema de provedores desconhecidos: %w", err)
	}

	schemaSnapshots := `CREATE TABLE IF NOT EXISTS host_snapshots (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		host TEXT,
		classification TEXT,
		confidence_score INTEGER,
		coverage_score INTEGER,
		knowledge_score INTEGER,
		transition_reason TEXT,
		observed_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);
	CREATE INDEX IF NOT EXISTS idx_snapshots_host ON host_snapshots(host);`
	if _, err := db.Exec(schemaSnapshots); err != nil {
		db.Close()
		return nil, fmt.Errorf("criando esquema de instantâneos de hosts: %w", err)
	}

	schemaClaims := `CREATE TABLE IF NOT EXISTS claim_audits (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		host TEXT NOT NULL,
		provider_id TEXT NOT NULL,
		status TEXT NOT NULL,
		external_id TEXT NOT NULL DEFAULT '',
		receipt_json TEXT NOT NULL DEFAULT '',
		last_error TEXT NOT NULL DEFAULT '',
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);
	CREATE INDEX IF NOT EXISTS idx_claim_audits_pending ON claim_audits(status);`
	if _, err := db.Exec(schemaClaims); err != nil {
		db.Close()
		return nil, fmt.Errorf("criando esquema de auditorias de reivindicação: %w", err)
	}

	if err := RunMigrations(db); err != nil {
		db.Close()
		return nil, fmt.Errorf("aplicando migrações: %w", err)
	}

	return &Store{db: db}, nil
}

func RunMigrations(db *sql.DB) error {
	migrations := []string{
		`ALTER TABLE hosts ADD COLUMN previous_classification TEXT DEFAULT '';`,
		`ALTER TABLE hosts ADD COLUMN last_state_change DATETIME DEFAULT CURRENT_TIMESTAMP;`,
		`ALTER TABLE hosts ADD COLUMN risk_score INTEGER DEFAULT 0;`,
		`ALTER TABLE hosts ADD COLUMN mitigation_score INTEGER DEFAULT 0;`,
		`ALTER TABLE hosts ADD COLUMN confidence_score INTEGER DEFAULT 0;`,
		`ALTER TABLE hosts ADD COLUMN tested_vectors TEXT NOT NULL DEFAULT '[]';`,
		`ALTER TABLE hosts ADD COLUMN scan_profile TEXT NOT NULL DEFAULT 'null';`,
		`ALTER TABLE unknown_providers ADD COLUMN example_hosts TEXT DEFAULT '[]';`,
		`ALTER TABLE unknown_providers ADD COLUMN last_discovery_score REAL DEFAULT 0.0;`,
	}

	for _, query := range migrations {
		_, err := db.Exec(query)
		if err != nil {
			// Ignorar erro de coluna já existente
			if strings.Contains(err.Error(), "duplicate column name") {
				continue
			}
			return err
		}
	}
	return nil
}

// IsAlreadyFound verifica se um host já foi registrado
func (s *Store) IsAlreadyFound(host string) (bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var count int
	err := s.db.QueryRow(
		"SELECT COUNT(1) FROM hosts WHERE host = ?", host,
	).Scan(&count)
	if err != nil {
		return false, fmt.Errorf("consultando hosts: %w", err)
	}
	return count > 0, nil
}

// SaveAnalysis persiste o objeto completo HostAnalysis no banco de dados.
func (s *Store) SaveAnalysis(a *core.HostAnalysis) error {
	if a == nil {
		return fmt.Errorf("análise ausente")
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	dnsJSON, err := json.Marshal(a.DNS)
	if err != nil {
		return fmt.Errorf("serializando DNS: %w", err)
	}

	evidencesJSON, err := json.Marshal(a.Evidences)
	if err != nil {
		return fmt.Errorf("serializando evidências: %w", err)
	}
	testedVectorsJSON, err := json.Marshal(a.TestedVectors)
	if err != nil {
		return fmt.Errorf("serializando vetores testados: %w", err)
	}
	scanProfileJSON, err := json.Marshal(a.ScanProfile)
	if err != nil {
		return fmt.Errorf("serializando perfil da varredura: %w", err)
	}

	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("iniciando transação da análise: %w", err)
	}
	defer tx.Rollback()

	_, err = tx.Exec(
		`INSERT INTO hosts (
			host, classification, risk_score, mitigation_score, confidence_score, dns_records, evidences, tested_vectors, scan_profile, first_seen, last_seen, previous_classification, last_state_change
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, '', CURRENT_TIMESTAMP)
		 ON CONFLICT(host) DO UPDATE SET
			previous_classification = CASE 
				WHEN hosts.classification != excluded.classification THEN hosts.classification 
				ELSE hosts.previous_classification 
			END,
			last_state_change = CASE 
				WHEN hosts.classification != excluded.classification THEN CURRENT_TIMESTAMP 
				ELSE hosts.last_state_change 
			END,
			classification = excluded.classification,
			risk_score = excluded.risk_score,
			mitigation_score = excluded.mitigation_score,
			confidence_score = excluded.confidence_score,
			dns_records = excluded.dns_records,
			evidences = excluded.evidences,
			tested_vectors = excluded.tested_vectors,
			scan_profile = excluded.scan_profile,
			last_seen = CURRENT_TIMESTAMP`,
		a.Host, a.Classification, a.RiskScore, a.MitigationScore, a.ConfidenceScore, string(dnsJSON), string(evidencesJSON), string(testedVectorsJSON), string(scanProfileJSON),
	)
	if err != nil {
		return fmt.Errorf("inserindo ou atualizando host: %w", err)
	}

	// Mantém exemplos de provedores desconhecidos para análise posterior.
	if a.UnknownProvider != nil {
		var existingHostsStr string
		err := tx.QueryRow(`SELECT example_hosts FROM unknown_providers WHERE root_domain = ?`, a.UnknownProvider.RootDomain).Scan(&existingHostsStr)

		var exampleHosts []string
		if err == nil && existingHostsStr != "" {
			if unmarshalErr := json.Unmarshal([]byte(existingHostsStr), &exampleHosts); unmarshalErr != nil {
				return fmt.Errorf("decodificando hosts de exemplo do provedor %s: %w", a.UnknownProvider.RootDomain, unmarshalErr)
			}
		} else if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("consultando provedor desconhecido %s: %w", a.UnknownProvider.RootDomain, err)
		}

		found := false
		for _, h := range exampleHosts {
			if h == a.Host {
				found = true
				break
			}
		}
		if !found {
			exampleHosts = append(exampleHosts, a.Host)
			if len(exampleHosts) > 10 {
				exampleHosts = exampleHosts[1:] // Mantém os dez exemplos mais recentes.
			}
		}

		hostsJSON, marshalErr := json.Marshal(exampleHosts)
		if marshalErr != nil {
			return fmt.Errorf("serializando hosts de exemplo: %w", marshalErr)
		}

		_, err = tx.Exec(`
			INSERT INTO unknown_providers (root_domain, frequency, severity, first_seen, last_seen, example_hosts)
			VALUES (?, 1, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, ?)
			ON CONFLICT(root_domain) DO UPDATE SET
				frequency = frequency + 1,
				severity = CASE
					WHEN excluded.severity = 'HIGH' THEN 'HIGH'
					WHEN excluded.severity = 'MEDIUM' AND unknown_providers.severity = 'LOW' THEN 'MEDIUM'
					ELSE unknown_providers.severity
				END,
				last_seen = CURRENT_TIMESTAMP,
				example_hosts = excluded.example_hosts
		`, a.UnknownProvider.RootDomain, a.UnknownProvider.Severity, string(hostsJSON))
		if err != nil {
			return fmt.Errorf("inserindo provedor desconhecido: %w", err)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("confirmando transação da análise: %w", err)
	}
	return nil
}

// SaveSnapshot persiste um retrato pontual para o histórico de transições.
func (s *Store) SaveSnapshot(a *core.HostAnalysis, reason string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	_, err := s.db.Exec(`
		INSERT INTO host_snapshots (
			host, classification, confidence_score, coverage_score, knowledge_score, transition_reason, observed_at
		) VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
	`, a.Host, a.Classification, a.ConfidenceScore, int(a.CoverageScore), int(a.KnowledgeScore), reason)

	if err != nil {
		return fmt.Errorf("inserindo instantâneo para %s: %w", a.Host, err)
	}
	return nil
}

// HostSnapshot representa um registro da tabela host_snapshots.
type HostSnapshot struct {
	Host             string
	Classification   string
	ConfidenceScore  int
	CoverageScore    int
	KnowledgeScore   int
	TransitionReason string
	ObservedAt       time.Time
}

// GetHostSnapshots recupera a linha do tempo de um host em ordem cronológica.
func (s *Store) GetHostSnapshots(ctx context.Context, host string) ([]HostSnapshot, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	query := `SELECT host, classification, confidence_score, coverage_score, knowledge_score, transition_reason, observed_at FROM host_snapshots WHERE host = ? ORDER BY observed_at ASC`
	rows, err := s.db.QueryContext(ctx, query, host)
	if err != nil {
		return nil, fmt.Errorf("consultando snapshots de %s: %w", host, err)
	}
	defer rows.Close()

	var results []HostSnapshot
	for rows.Next() {
		var a HostSnapshot
		if err := rows.Scan(&a.Host, &a.Classification, &a.ConfidenceScore, &a.CoverageScore, &a.KnowledgeScore, &a.TransitionReason, &a.ObservedAt); err != nil {
			return nil, fmt.Errorf("lendo instantâneo de %s: %w", host, err)
		}
		results = append(results, a)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("percorrendo instantâneos de %s: %w", host, err)
	}
	return results, nil
}

// QueryOptions agrupa os filtros opcionais para recuperar hosts do banco.
type QueryOptions struct {
	OnlyRisky      bool
	Classification string
	ChangedSince   time.Duration
}

// GetAllHosts recupera os hosts do banco filtrados pelas opções.
func (s *Store) GetAllHosts(ctx context.Context, opts QueryOptions) ([]core.HostAnalysis, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	query := `SELECT host, classification, previous_classification, risk_score, mitigation_score, confidence_score, dns_records, evidences, tested_vectors, scan_profile, first_seen, last_seen, last_state_change FROM hosts WHERE 1=1`
	var args []interface{}

	if opts.OnlyRisky {
		query += ` AND classification NOT IN ('HEALTHY', 'UNKNOWN', 'INSUFFICIENT_EVIDENCE')`
	}
	if opts.Classification != "" {
		query += ` AND classification = ?`
		args = append(args, opts.Classification)
	}
	if opts.ChangedSince > 0 {
		targetTime := time.Now().Add(-opts.ChangedSince).UTC().Format("2006-01-02 15:04:05")
		query += ` AND last_state_change >= ?`
		args = append(args, targetTime)
	}

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("consultando todos os hosts: %w", err)
	}
	defer rows.Close()

	var results []core.HostAnalysis
	for rows.Next() {
		var a core.HostAnalysis
		var dnsText, evText, testedVectorsText, scanProfileText string
		var firstSeen, lastSeen, lastChange time.Time

		err := rows.Scan(&a.Host, &a.Classification, &a.PreviousClassification, &a.RiskScore, &a.MitigationScore, &a.ConfidenceScore, &dnsText, &evText, &testedVectorsText, &scanProfileText, &firstSeen, &lastSeen, &lastChange)
		if err != nil {
			return nil, fmt.Errorf("lendo host persistido: %w", err)
		}

		if err := json.Unmarshal([]byte(dnsText), &a.DNS); err != nil {
			return nil, fmt.Errorf("decodificando registros DNS de %s: %w", a.Host, err)
		}
		if err := json.Unmarshal([]byte(evText), &a.Evidences); err != nil {
			return nil, fmt.Errorf("decodificando evidências de %s: %w", a.Host, err)
		}
		if err := json.Unmarshal([]byte(testedVectorsText), &a.TestedVectors); err != nil {
			return nil, fmt.Errorf("decodificando vetores testados de %s: %w", a.Host, err)
		}
		if scanProfileText != "" && scanProfileText != "null" {
			if err := json.Unmarshal([]byte(scanProfileText), &a.ScanProfile); err != nil {
				return nil, fmt.Errorf("decodificando perfil da varredura de %s: %w", a.Host, err)
			}
		}

		a.FirstSeen = firstSeen
		a.LastSeen = lastSeen
		a.LastStateChange = lastChange

		results = append(results, a)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("percorrendo hosts persistidos: %w", err)
	}
	return results, nil
}

// GetAllUnknownProviders recupera os provedores desconhecidos por frequência.
func (s *Store) GetAllUnknownProviders(ctx context.Context) ([]core.UnknownProviderEvidence, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	query := `SELECT root_domain, frequency, severity, first_seen, last_seen, example_hosts, last_discovery_score FROM unknown_providers ORDER BY frequency DESC`
	rows, err := s.db.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("consultando provedores desconhecidos: %w", err)
	}
	defer rows.Close()

	var results []core.UnknownProviderEvidence
	for rows.Next() {
		var a core.UnknownProviderEvidence
		var hostsStr string
		if err := rows.Scan(&a.RootDomain, &a.Frequency, &a.Severity, &a.FirstSeen, &a.LastSeen, &hostsStr, &a.LastDiscoveryScore); err != nil {
			return nil, fmt.Errorf("lendo provedor desconhecido: %w", err)
		}

		if hostsStr != "" {
			if err := json.Unmarshal([]byte(hostsStr), &a.ExampleHosts); err != nil {
				return nil, fmt.Errorf("decodificando hosts de exemplo de %s: %w", a.RootDomain, err)
			}
		}

		results = append(results, a)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("percorrendo provedores desconhecidos: %w", err)
	}
	return results, nil
}

// UpdateDiscoveryScore atualiza a pontuação de descoberta para monitorar saltos
// no mecanismo de fingerprints.
func (s *Store) UpdateDiscoveryScore(ctx context.Context, rootDomain string, score float64) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	_, err := s.db.ExecContext(ctx, `UPDATE unknown_providers SET last_discovery_score = ? WHERE root_domain = ?`, score, rootDomain)
	return err
}

// ClaimAuditRecord registra somente transições reais do estado de reivindicação.
// ReceiptJSON é preenchido depois que um provedor aloca um recurso com sucesso.
type ClaimAuditRecord struct {
	ID          int64
	Host        string
	ProviderID  string
	Status      string
	ExternalID  string
	ReceiptJSON string
	LastError   string
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

func (s *Store) CreateClaimAudit(ctx context.Context, record ClaimAuditRecord) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	result, err := s.db.ExecContext(ctx, `
		INSERT INTO claim_audits (host, provider_id, status, external_id, receipt_json, last_error)
		VALUES (?, ?, ?, ?, ?, ?)
	`, record.Host, record.ProviderID, record.Status, record.ExternalID, record.ReceiptJSON, record.LastError)
	if err != nil {
		return 0, err
	}
	return result.LastInsertId()
}

func (s *Store) UpdateClaimAudit(ctx context.Context, id int64, status, externalID, receiptJSON, lastError string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.ExecContext(ctx, `
		UPDATE claim_audits
		SET status = ?, external_id = ?, receipt_json = ?, last_error = ?, updated_at = CURRENT_TIMESTAMP
		WHERE id = ?
	`, status, externalID, receiptJSON, lastError, id)
	return err
}

func (s *Store) PendingClaimAudits(ctx context.Context) ([]ClaimAuditRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, host, provider_id, status, external_id, receipt_json, last_error, created_at, updated_at
		FROM claim_audits
		WHERE status IN ('ATTEMPTING', 'CLAIM_SUCCEEDED', 'RELEASE_PENDING', 'RELEASE_FAILED')
		  AND receipt_json <> ''
		ORDER BY id
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var records []ClaimAuditRecord
	for rows.Next() {
		var record ClaimAuditRecord
		if err := rows.Scan(&record.ID, &record.Host, &record.ProviderID, &record.Status, &record.ExternalID, &record.ReceiptJSON, &record.LastError, &record.CreatedAt, &record.UpdatedAt); err != nil {
			return nil, err
		}
		records = append(records, record)
	}
	return records, rows.Err()
}

// DB retorna a conexão subjacente para consultas somente leitura, como
// estatísticas.
func (s *Store) DB() *sql.DB {
	return s.db
}

// Close encerra a conexão com o banco de dados.
func (s *Store) Close() error {
	return s.db.Close()
}
