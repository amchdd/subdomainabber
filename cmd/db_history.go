package cmd

import (
	"encoding/json"
	"fmt"
	"sort"

	"github.com/amchdd/subdomainabber/internal/classification"
	"github.com/amchdd/subdomainabber/internal/confidence"
	"github.com/amchdd/subdomainabber/internal/core"
	"github.com/amchdd/subdomainabber/internal/storage"
	"github.com/spf13/cobra"
)

var (
	historyLimit int
	historyJSON  bool
)

var historyCmd = &cobra.Command{
	Use:   "history",
	Short: "Lista as execuções registradas no banco",
	RunE: func(cmd *cobra.Command, args []string) (runErr error) {
		store, err := openStore()
		if err != nil {
			return err
		}
		defer closeStoreWithError(store, &runErr)
		runs, err := store.Runs(cmd.Context(), historyLimit)
		if err != nil {
			return fmt.Errorf("consultando histórico: %w", err)
		}
		if historyJSON {
			encoder := json.NewEncoder(cmd.OutOrStdout())
			encoder.SetIndent("", "  ")
			return encoder.Encode(runs)
		}
		for _, run := range runs {
			fmt.Fprintf(cmd.OutOrStdout(), "%s  %-11s  %d/%d  %s\n", run.ID, run.Status, run.CompletedCount, run.TargetCount, run.StartedAt.Format("2006-01-02 15:04:05"))
		}
		return nil
	},
}

var replayCmd = &cobra.Command{
	Use:   "replay <execução>",
	Short: "Reclassifica observações armazenadas sem acessar a rede",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) (runErr error) {
		store, err := openStore()
		if err != nil {
			return err
		}
		defer closeStoreWithError(store, &runErr)
		analyses, err := store.Observations(cmd.Context(), args[0])
		if err != nil {
			return err
		}
		encoder := json.NewEncoder(cmd.OutOrStdout())
		for index := range analyses {
			analyses[index].UnknownProvider = nil
			classification.Process(&analyses[index])
			confidence.Calculate(&analyses[index])
			if err := encoder.Encode(&analyses[index]); err != nil {
				return fmt.Errorf("gerando replay: %w", err)
			}
		}
		return nil
	},
}

var diffCmd = &cobra.Command{
	Use:   "diff <execução-a> <execução-b>",
	Short: "Compara classificações e evidências entre duas execuções",
	Args:  cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) (runErr error) {
		store, err := openStore()
		if err != nil {
			return err
		}
		defer closeStoreWithError(store, &runErr)
		left, err := store.Observations(cmd.Context(), args[0])
		if err != nil {
			return err
		}
		right, err := store.Observations(cmd.Context(), args[1])
		if err != nil {
			return err
		}
		changes := compareRuns(left, right)
		encoder := json.NewEncoder(cmd.OutOrStdout())
		encoder.SetIndent("", "  ")
		return encoder.Encode(changes)
	},
}

type runChange struct {
	Host            string   `json:"host"`
	Before          string   `json:"before,omitempty"`
	After           string   `json:"after,omitempty"`
	AddedEvidence   []string `json:"added_evidence,omitempty"`
	RemovedEvidence []string `json:"removed_evidence,omitempty"`
}

func compareRuns(left, right []core.HostAnalysis) []runChange {
	leftByHost := analysisMap(left)
	rightByHost := analysisMap(right)
	hosts := make(map[string]struct{}, len(left)+len(right))
	for host := range leftByHost {
		hosts[host] = struct{}{}
	}
	for host := range rightByHost {
		hosts[host] = struct{}{}
	}
	var changes []runChange
	for host := range hosts {
		before, beforeOK := leftByHost[host]
		after, afterOK := rightByHost[host]
		change := runChange{Host: host}
		if beforeOK {
			change.Before = before.Classification
		}
		if afterOK {
			change.After = after.Classification
		}
		change.AddedEvidence, change.RemovedEvidence = evidenceDiff(before.Evidences, after.Evidences)
		if change.Before != change.After || len(change.AddedEvidence) > 0 || len(change.RemovedEvidence) > 0 {
			changes = append(changes, change)
		}
	}
	sort.Slice(changes, func(i, j int) bool { return changes[i].Host < changes[j].Host })
	return changes
}

func analysisMap(analyses []core.HostAnalysis) map[string]core.HostAnalysis {
	result := make(map[string]core.HostAnalysis, len(analyses))
	for _, analysis := range analyses {
		result[analysis.Host] = analysis
	}
	return result
}

func evidenceDiff(before, after []core.Evidence) ([]string, []string) {
	left, right := evidenceSet(before), evidenceSet(after)
	var added, removed []string
	for value := range right {
		if _, ok := left[value]; !ok {
			added = append(added, value)
		}
	}
	for value := range left {
		if _, ok := right[value]; !ok {
			removed = append(removed, value)
		}
	}
	sort.Strings(added)
	sort.Strings(removed)
	return added, removed
}

func evidenceSet(evidences []core.Evidence) map[string]struct{} {
	result := make(map[string]struct{}, len(evidences))
	for _, evidence := range evidences {
		encoded, err := json.Marshal(evidence)
		if err != nil {
			result[evidence.Type+"|"+evidence.Source] = struct{}{}
			continue
		}
		result[string(encoded)] = struct{}{}
	}
	return result
}

func openStore() (*storage.Store, error) {
	cfg, err := loadCommandConfigWithError()
	if err != nil {
		return nil, err
	}
	if cfg.DBPath == "" {
		cfg.DBPath = "subdomainabber.db"
	}
	store, err := storage.New(cfg.DBPath)
	if err != nil {
		return nil, fmt.Errorf("abrindo banco de dados: %w", err)
	}
	return store, nil
}

func init() {
	dbCmd.AddCommand(historyCmd, replayCmd, diffCmd)
	historyCmd.Flags().IntVar(&historyLimit, "limit", 20, "Quantidade máxima de execuções")
	historyCmd.Flags().BoolVar(&historyJSON, "json", false, "Saída em formato JSON")
}
