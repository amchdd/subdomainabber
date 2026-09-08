package discovery

import "strings"

var wordFamilies = [][]string{environmentWords, regionWords}

func GenerateMutations(root, name string, words []string) []string {
	root = normalizeName(root)
	name = normalizeName(name)
	if root == "" || name == "" || name == root || !belongsToDomain(name, root) {
		return nil
	}

	label, parent := firstLabel(name)
	relative := strings.TrimSuffix(name, "."+root)
	labels := strings.Split(relative, ".")
	seen := make(map[string]struct{})
	var result []string
	add := func(candidate string) {
		candidate = normalizeName(candidate)
		if candidate == "" || candidate == name || !belongsToDomain(candidate, root) {
			return
		}
		if _, found := seen[candidate]; found {
			return
		}
		seen[candidate] = struct{}{}
		result = append(result, candidate)
	}

	for _, word := range words {
		add(label + "-" + word + "." + parent)
		add(word + "-" + label + "." + parent)
		for index := 0; index <= len(labels); index++ {
			changed := make([]string, 0, len(labels)+1)
			changed = append(changed, labels[:index]...)
			changed = append(changed, word)
			changed = append(changed, labels[index:]...)
			add(strings.Join(changed, ".") + "." + root)
		}
	}

	parts := strings.Split(label, "-")
	for index, part := range parts {
		for _, family := range wordFamilies {
			if !containsWord(family, part) {
				continue
			}
			for _, replacement := range family {
				changed := append([]string(nil), parts...)
				changed[index] = replacement
				add(strings.Join(changed, "-") + "." + parent)
			}
		}
	}
	for index, current := range labels {
		for _, family := range wordFamilies {
			if !containsWord(family, current) {
				continue
			}
			for _, replacement := range family {
				changed := append([]string(nil), labels...)
				changed[index] = replacement
				add(strings.Join(changed, ".") + "." + root)
			}
		}
	}
	return result
}

func containsWord(words []string, target string) bool {
	for _, word := range words {
		if word == target {
			return true
		}
	}
	return false
}
