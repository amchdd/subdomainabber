# Como contribuir

Obrigado por contribuir com o SubdomainAbber. O projeto prioriza evidência reproduzível, baixo ruído e uso autorizado.

## Ambiente de desenvolvimento

Use Go 1.26.5 ou superior:

```bash
go mod download
go fmt ./...
go mod verify
go vet ./...
go run github.com/rhysd/actionlint/cmd/actionlint@v1.7.12 .github/workflows/ci.yml .github/workflows/release.yml
go run honnef.co/go/tools/cmd/staticcheck@v0.7.0 ./...
go run golang.org/x/vuln/cmd/govulncheck@v1.6.0 ./...
go test ./... -count=1
go run . fingerprints validate --strict
go run . benchmark synthetic
go run . benchmark regression datasets/regression
go run . benchmark mutator
go build ./...
```

Antes de abrir uma solicitação de alteração (pull request), confirme também que `gofmt -l .` não lista arquivos. O detector de condições de corrida (`go test -race ./... -count=1`) faz parte da CI em Linux.

No Windows, o detector de condições de corrida exige CGO e um compilador C compatível. Se esse requisito não estiver disponível no ambiente local, registre a limitação na solicitação e aguarde a etapa correspondente da CI; não marque o teste como executado.

## Regras de segurança para testes

- testes automatizados não devem depender de alvos públicos;
- use `httptest`, endereços de loopback e dublês de DNS/HTTP;
- nunca inclua tokens, webhooks, bancos reais ou dados de programas de bug bounty;
- mudanças no framing devem permanecer restritas ao laboratório controlado;
- mudanças no mecanismo de reivindicação precisam provar reversão, liberação e recuperação de falhas com provedores simulados;
- a CI nunca deve executar `--aggressive` nem usar credenciais de escrita.

## Assinaturas

Uma assinatura nova deve declarar `check_type`, provedor, padrões com limites DNS para o vetor correspondente, confiança, requisitos de prova e referência pública. Assinaturas HTTP também devem especificar corpo, status e cabeçalhos quando relevantes. Textos genéricos como `404 Not Found` não podem promover classificação automática.

Adicione testes para correspondência positiva, domínio semelhante que não deve casar e resposta genérica que deve permanecer neutra.

Quando uma assinatura derivar de um catálogo externo, preserve a origem, indique as alterações realizadas e atualize [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) se a atribuição ou a licença mudar.

## Documentação e mensagens

Textos destinados ao usuário devem ser escritos em PT-BR claro e direto. Não traduza flags, protocolos, identificadores de evidência nem trechos literais necessários para reconhecer respostas de provedores. Evite linguagem promocional e não apresente um candidato passivo como controle comprovado.

## Processo de lançamento

Antes de criar uma versão, mantenha a mesma versão semântica no `CHANGELOG.md`, em `internal/buildinfo/version.go` e nas referências do `README.md`. Execute todas as verificações da seção de ambiente de desenvolvimento e confirme que a árvore de trabalho contém apenas as mudanças previstas para o lançamento.

Crie a tag no formato `vMAJOR.MINOR.PATCH` ou com um sufixo de pré-lançamento, como `v0.2.0-alpha`. O fluxo de lançamento valida a tag, compila os pacotes para as plataformas suportadas, gera as somas de verificação e publica versões com sufixo `alpha` ou `beta` como pré-lançamentos. Não anuncie uma versão antes da conclusão bem-sucedida desse fluxo.

## Solicitações de alteração

Mantenha cada PR focado. Descreva o comportamento anterior, a mudança proposta, o risco de tráfego, os testes executados e qualquer impacto no formato de dados ou na CLI. Mudanças em opções, configuração ou esquema também devem atualizar o README, o changelog, [.env.example](.env.example) e [config.example.yaml](config.example.yaml), conforme aplicável.

Vulnerabilidades no próprio projeto devem ser relatadas conforme [SECURITY.md](SECURITY.md), não em relatórios públicos.
