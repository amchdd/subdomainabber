package signatures

import (
	"fmt"
	"regexp"
	"strings"
)

// Condition representa uma expressão lógica para correspondência de fingerprints.
type Condition struct {
	Type     string         `json:"type"` // "AND", "OR", "NOT", "MATCH", "REGEX"
	Value    string         `json:"value,omitempty"`
	Children []Condition    `json:"children,omitempty"`
	Compiled *regexp.Regexp `json:"-"`
}

// Evaluate verifica se o texto do corpo atende à condição.
func (c *Condition) Evaluate(body string) bool {
	switch strings.ToUpper(c.Type) {
	case "AND":
		if len(c.Children) == 0 {
			return false
		}
		for _, child := range c.Children {
			if !child.Evaluate(body) {
				return false
			}
		}
		return true
	case "OR":
		if len(c.Children) == 0 {
			return false
		}
		for _, child := range c.Children {
			if child.Evaluate(body) {
				return true
			}
		}
		return false
	case "NOT":
		if len(c.Children) == 0 {
			return false
		}
		return !c.Children[0].Evaluate(body)
	case "MATCH":
		return strings.Contains(strings.ToLower(body), strings.ToLower(c.Value))
	case "REGEX":
		compiled := c.Compiled
		if compiled == nil {
			// Condições criadas programaticamente também são aceitas, mas a
			// compilação local não altera a estrutura compartilhada entre workers.
			compiled, _ = regexp.Compile("(?i)" + c.Value)
		}
		if compiled != nil {
			return compiled.MatchString(body)
		}
		return false
	}
	return false
}

func compileCondition(condition *Condition) error {
	if condition == nil {
		return nil
	}
	typeName := strings.ToUpper(strings.TrimSpace(condition.Type))
	condition.Type = typeName
	switch typeName {
	case "AND", "OR":
		if len(condition.Children) == 0 {
			return fmt.Errorf("a condição %s exige ao menos um filho", typeName)
		}
	case "NOT":
		if len(condition.Children) != 1 {
			return fmt.Errorf("a condição NOT exige exatamente um filho")
		}
	case "MATCH":
		if strings.TrimSpace(condition.Value) == "" {
			return fmt.Errorf("a condição MATCH não pode ter valor vazio")
		}
	case "REGEX":
		if strings.TrimSpace(condition.Value) == "" {
			return fmt.Errorf("a condição REGEX não pode ter valor vazio")
		}
		compiled, err := regexp.Compile("(?i)" + condition.Value)
		if err != nil {
			return fmt.Errorf("regex da condição inválida: %w", err)
		}
		condition.Compiled = compiled
	default:
		return fmt.Errorf("tipo de condição não suportado %q", condition.Type)
	}
	for index := range condition.Children {
		if err := compileCondition(&condition.Children[index]); err != nil {
			return fmt.Errorf("filho %d de %s: %w", index+1, typeName, err)
		}
	}
	return nil
}
