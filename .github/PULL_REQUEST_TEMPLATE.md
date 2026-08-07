## Resumo

Descreva o problema e a solução.

## Segurança e tráfego

- [ ] A mudança não amplia escopo ou tráfego silenciosamente.
- [ ] Testes usam apenas dublês, loopback ou dados controlados.
- [ ] Não há segredos, dados de programas ou alvos reais nas alterações.
- [ ] Opções ativas exigem ativação explícita e possuem documentação compatível com o risco.

## Validação

- [ ] `go fmt ./...`
- [ ] `go mod verify`
- [ ] `go vet ./...`
- [ ] `go run github.com/rhysd/actionlint/cmd/actionlint@v1.7.12 .github/workflows/*.yml`
- [ ] `go run honnef.co/go/tools/cmd/staticcheck@v0.7.0 ./...`
- [ ] `go run golang.org/x/vuln/cmd/govulncheck@v1.6.0 ./...`
- [ ] `go test ./... -count=1`
- [ ] `go run . fingerprints validate --strict`
- [ ] `go build ./...`

## Compatibilidade

Liste mudanças de CLI, esquema, configuração ou formato de saída, se houver.

- [ ] README, changelog e exemplos de configuração foram atualizados quando necessário.
- [ ] Avisos de terceiros continuam corretos para qualquer dado ou assinatura incorporada.
