## Resumo

Descreva o problema, a solução e o motivo da mudança.

## Tipo de mudança

- [ ] `feat`: nova funcionalidade
- [ ] `fix`: correção de defeito
- [ ] `docs`: documentação
- [ ] `refactor`: refatoração
- [ ] `test`: testes
- [ ] `ci`/`build`: automação, build ou dependências
- [ ] `chore`: manutenção

## Branch e destino

- [ ] O título segue Conventional Commits.
- [ ] A branch de trabalho partiu de `dev` e o PR aponta para `dev`.
- [ ] Caso o PR aponte para `main`, ele parte de `dev` ou de `hotfix/*`.
- [ ] O PR está focado em uma única mudança coerente.

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

## Compatibilidade e documentação

Descreva qualquer impacto na CLI, configuração, banco de dados, formato de saída ou comportamento de rede.

- [ ] README, changelog e exemplos de configuração foram atualizados quando necessário.
- [ ] Avisos de terceiros continuam corretos para qualquer dado ou assinatura incorporada.
- [ ] Não há mudança incompatível sem documentação e justificativa explícitas.
