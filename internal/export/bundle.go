package export

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/amchdd/subdomainabber/internal/core"
)

type EvidenceBundle struct {
	SchemaVersion int                 `json:"schema_version"`
	RunID         string              `json:"run_id"`
	GeneratedAt   time.Time           `json:"generated_at"`
	Analyses      []core.HostAnalysis `json:"analyses"`
	Digest        string              `json:"digest"`
	PublicKey     string              `json:"public_key"`
	Signature     string              `json:"signature"`
}

func GenerateKey(privatePath, publicPath string) error {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("gerando chave Ed25519: %w", err)
	}
	if err := writeNew(privatePath, []byte(base64.StdEncoding.EncodeToString(privateKey)+"\n"), 0o600); err != nil {
		return err
	}
	if err := writeNew(publicPath, []byte(base64.StdEncoding.EncodeToString(publicKey)+"\n"), 0o644); err != nil {
		return err
	}
	return nil
}

func WriteBundle(path, runID, privatePath string, analyses []core.HostAnalysis) error {
	privateKey, err := readPrivateKey(privatePath)
	if err != nil {
		return err
	}
	analysisJSON, err := json.Marshal(analyses)
	if err != nil {
		return err
	}
	digest := sha256.Sum256(analysisJSON)
	bundle := EvidenceBundle{
		SchemaVersion: 1,
		RunID:         runID,
		GeneratedAt:   time.Now().UTC(),
		Analyses:      analyses,
		Digest:        hex.EncodeToString(digest[:]),
		PublicKey:     base64.StdEncoding.EncodeToString(privateKey.Public().(ed25519.PublicKey)),
	}
	bundle.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, bundleMessage(bundle)))
	data, err := json.MarshalIndent(bundle, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(path, append(data, '\n'), 0o600); err != nil {
		return fmt.Errorf("gravando bundle: %w", err)
	}
	return nil
}

func VerifyBundle(path string, trustedKey ...string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("lendo bundle: %w", err)
	}
	var bundle EvidenceBundle
	if err := json.Unmarshal(data, &bundle); err != nil {
		return fmt.Errorf("interpretando bundle: %w", err)
	}
	if bundle.SchemaVersion != 1 {
		return fmt.Errorf("versão de bundle não suportada: %d", bundle.SchemaVersion)
	}
	analysisJSON, err := json.Marshal(bundle.Analyses)
	if err != nil {
		return err
	}
	digest := sha256.Sum256(analysisJSON)
	if hex.EncodeToString(digest[:]) != bundle.Digest {
		return fmt.Errorf("o conteúdo do bundle não corresponde ao digest")
	}
	publicKey, err := base64.StdEncoding.DecodeString(bundle.PublicKey)
	if err != nil || len(publicKey) != ed25519.PublicKeySize {
		return fmt.Errorf("chave pública inválida no bundle")
	}
	if len(trustedKey) > 0 && trustedKey[0] != "" {
		data, readErr := os.ReadFile(trustedKey[0])
		if readErr != nil {
			return fmt.Errorf("lendo chave pública confiável: %w", readErr)
		}
		trusted, decodeErr := base64.StdEncoding.DecodeString(string(bytes.TrimSpace(data)))
		if decodeErr != nil || !bytes.Equal(trusted, publicKey) {
			return fmt.Errorf("a chave pública do bundle não corresponde à chave confiável")
		}
	}
	signature, err := base64.StdEncoding.DecodeString(bundle.Signature)
	if err != nil || !ed25519.Verify(ed25519.PublicKey(publicKey), bundleMessage(bundle), signature) {
		return fmt.Errorf("assinatura Ed25519 inválida")
	}
	return nil
}

func bundleMessage(bundle EvidenceBundle) []byte {
	return []byte(fmt.Sprintf("%d\n%s\n%s\n%s", bundle.SchemaVersion, bundle.RunID, bundle.GeneratedAt.Format(time.RFC3339Nano), bundle.Digest))
}

func readPrivateKey(path string) (ed25519.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("lendo chave privada: %w", err)
	}
	decoded, err := base64.StdEncoding.DecodeString(string(bytes.TrimSpace(data)))
	if err != nil || len(decoded) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("chave privada Ed25519 inválida")
	}
	return ed25519.PrivateKey(decoded), nil
}

func writeNew(path string, data []byte, mode os.FileMode) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return fmt.Errorf("criando %s: %w", path, err)
	}
	defer file.Close()
	if _, err := file.Write(data); err != nil {
		return fmt.Errorf("gravando %s: %w", path, err)
	}
	return nil
}
