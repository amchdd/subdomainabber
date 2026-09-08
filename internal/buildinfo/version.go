// Package buildinfo expõe metadados de versão compartilhados pelos comandos da CLI.
package buildinfo

// Version é a versão semântica informada pela CLI. Compilações de lançamento
// podem substituí-la com -ldflags "-X github.com/amchdd/subdomainabber/internal/buildinfo.Version=<version>".
var Version = "v0.2.0"
