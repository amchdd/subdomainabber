package color

import (
	"fmt"
	"io"
	"os"
	"strings"
)

const (
	Reset = "\033[0m"
	Bold  = "\033[1m"
	Dim   = "\033[2m"

	Red        = "\033[91m"
	Green      = "\033[92m"
	Yellow     = "\033[93m"
	Magenta    = "\033[95m"
	Cyan       = "\033[96m"
	Gray       = "\033[90m"
	BrightRed  = "\033[91m"
	BrightBlue = "\033[94m"
)

type Tone string

const (
	ToneCritical Tone = "critical"
	ToneHigh     Tone = "high"
	ToneMedium   Tone = "medium"
	ToneLow      Tone = "low"
	ToneInfo     Tone = "info"
	ToneMuted    Tone = "muted"
)

// Enabled informa se a formatação ANSI é apropriada para o destino de escrita.
func Enabled(writer io.Writer) bool {
	if os.Getenv("NO_COLOR") != "" || strings.EqualFold(os.Getenv("TERM"), "dumb") {
		return false
	}
	if forced := strings.TrimSpace(os.Getenv("CLICOLOR_FORCE")); forced != "" && forced != "0" {
		return true
	}
	file, ok := writer.(*os.File)
	if !ok {
		return false
	}
	info, err := file.Stat()
	return err == nil && info.Mode()&os.ModeCharDevice != 0
}

func Paint(value, sequence string, enabled bool) string {
	if !enabled || value == "" {
		return value
	}
	return sequence + value + Reset
}

func Emphasis(value string, enabled bool) string {
	return Paint(value, Bold, enabled)
}

func Field(value string, enabled bool) string {
	return Paint(value, Bold+Cyan, enabled)
}

func ToneText(value string, tone Tone, enabled bool) string {
	sequence := Gray
	switch tone {
	case ToneCritical:
		sequence = Bold + BrightRed
	case ToneHigh:
		sequence = Bold + Red
	case ToneMedium:
		sequence = Bold + Yellow
	case ToneLow:
		sequence = Bold + BrightBlue
	case ToneInfo:
		sequence = Green
	case ToneMuted:
		sequence = Dim + Gray
	}
	return Paint(value, sequence, enabled)
}

// ColorizeClassificationLabelWith escolhe a cor pelo identificador técnico,
// mas permite apresentar um rótulo humano traduzido.
func ColorizeClassificationLabelWith(classification, label string, enabled bool) string {
	value := fmt.Sprintf("[%s]", label)
	switch classification {
	case "TAKEN_OVER", "CONFIRMED_TAKEOVERABLE", "TAKEOVERABLE", "ZONE_CONTROL_CONFIRMED":
		return ToneText(value, ToneCritical, enabled)
	case "LIKELY_TAKEOVERABLE", "DELEGATION_TAKEOVER_CANDIDATE", "DELEGATION_CLAIMABILITY_VERIFIED":
		return ToneText(value, ToneMedium, enabled)
	case "UNKNOWN_PROVIDER", "EXPOSED":
		return Paint(value, Magenta, enabled)
	case "MISCONFIGURED", "DELEGATION_BROKEN", "ORPHANED":
		return ToneText(value, ToneLow, enabled)
	case "HEALTHY":
		return ToneText(value, ToneInfo, enabled)
	case "UNKNOWN", "INSUFFICIENT_EVIDENCE":
		return ToneText(value, ToneMuted, enabled)
	default:
		return ToneText(value, ToneMuted, enabled)
	}
}
