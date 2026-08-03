package stats

// DBStats representa o sumário completo de métricas do banco de dados.
type DBStats struct {
	TotalHosts           int
	ClassificationCounts map[string]int
	StateChangeCounts    map[string]int
	TopEvidenceTypes     []EvidenceStat
}

// EvidenceStat representa a contagem de um tipo específico de evidência.
type EvidenceStat struct {
	Type  string
	Count int
}
