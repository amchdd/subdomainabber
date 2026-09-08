package benchmark

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"

	"github.com/amchdd/subdomainabber/internal/classification"
	"github.com/amchdd/subdomainabber/internal/confidence"
	"github.com/amchdd/subdomainabber/internal/core"
)

type Corpus struct {
	SchemaVersion int          `json:"schema_version"`
	Cases         []CorpusCase `json:"cases"`
}

type CorpusCase struct {
	Name             string            `json:"name"`
	Vector           string            `json:"vector"`
	Expected         string            `json:"expected"`
	MaxRequests      int               `json:"max_requests,omitempty"`
	ObservedRequests int               `json:"observed_requests,omitempty"`
	Analysis         core.HostAnalysis `json:"analysis"`
}

type CorpusResult struct {
	Total          int            `json:"total"`
	Passed         int            `json:"passed"`
	Failed         int            `json:"failed"`
	BudgetFailures int            `json:"budget_failures"`
	ByVector       map[string]int `json:"by_vector"`
	Failures       []string       `json:"failures,omitempty"`
}

func RunCorpus(path string) (CorpusResult, error) {
	result := CorpusResult{ByVector: make(map[string]int)}
	files, err := corpusFiles(path)
	if err != nil {
		return result, err
	}
	if len(files) == 0 {
		return result, fmt.Errorf("nenhum arquivo JSON encontrado no corpus")
	}
	for _, file := range files {
		corpus, err := loadCorpus(file)
		if err != nil {
			return result, err
		}
		for _, test := range corpus.Cases {
			result.Total++
			result.ByVector[test.Vector]++
			classification.Process(&test.Analysis)
			confidence.Calculate(&test.Analysis)
			failed := test.Analysis.Classification != test.Expected
			if test.MaxRequests > 0 && test.ObservedRequests > test.MaxRequests {
				failed = true
				result.BudgetFailures++
			}
			if failed {
				result.Failed++
				result.Failures = append(result.Failures, fmt.Sprintf("%s: obtido %s, esperado %s", test.Name, test.Analysis.Classification, test.Expected))
			} else {
				result.Passed++
			}
		}
	}
	sort.Strings(result.Failures)
	return result, nil
}

func corpusFiles(path string) ([]string, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("abrindo corpus: %w", err)
	}
	if !info.IsDir() {
		return []string{path}, nil
	}
	var files []string
	err = filepath.WalkDir(path, func(current string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if !entry.IsDir() && filepath.Ext(entry.Name()) == ".json" {
			files = append(files, current)
		}
		return nil
	})
	sort.Strings(files)
	return files, err
}

func loadCorpus(path string) (Corpus, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Corpus{}, err
	}
	var corpus Corpus
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&corpus); err != nil {
		return Corpus{}, fmt.Errorf("interpretando %s: %w", path, err)
	}
	if corpus.SchemaVersion != 1 {
		return Corpus{}, fmt.Errorf("%s usa versão de esquema não suportada: %d", path, corpus.SchemaVersion)
	}
	for index, test := range corpus.Cases {
		if test.Name == "" || test.Vector == "" || test.Expected == "" || test.Analysis.Host == "" {
			return Corpus{}, fmt.Errorf("%s contém caso incompleto na posição %d", path, index+1)
		}
		if test.MaxRequests < 0 || test.ObservedRequests < 0 {
			return Corpus{}, fmt.Errorf("%s contém orçamento inválido na posição %d", path, index+1)
		}
	}
	return corpus, nil
}
