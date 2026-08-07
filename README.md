# Subdomainabber

[![Version](https://img.shields.io/badge/version-v0.1.0--alpha-orange)](CHANGELOG.md)
[![Go CI](https://github.com/amchdd/subdomainabber/actions/workflows/ci.yml/badge.svg)](https://github.com/amchdd/subdomainabber/actions/workflows/ci.yml)
[![License: MIT + Commons Clause](https://img.shields.io/badge/license-MIT%20%2B%20Commons%20Clause-blue.svg)](LICENSE)

Subdomainabber é uma ferramenta de varredura em Go para investigar possíveis casos de takeover de subdomínio em programas de bug bounty e avaliações de segurança autorizadas. Ela correlaciona DNS, HTTP e TLS, registra evidências reproduzíveis e mantém um histórico local em SQLite.

> **Versão alpha:** `v0.1.0-alpha` ainda pode alterar opções de linha de comando, o formato do banco e os critérios de classificação. Todo resultado exige validação manual antes de ser relatado.

## Uso autorizado

Execute somente contra domínios incluídos no escopo do programa ou para os quais você possui autorização explícita. Respeite limites de taxa, janelas de teste e regras sobre automação.

O modo padrão **não reivindica nem cria recursos**. Nesta versão alpha, os únicos adaptadores de validação ativa disponíveis são os do Amazon S3 e do Amazon Route 53. O uso por meio de `--aggressive` exige confirmação adicional, lista de permissões exata e credenciais de escrita. Uma classificação de risco não comprova explorabilidade nem autoriza essa operação.

## O que a ferramenta faz

- coleta e correlaciona CNAME, delegação NS, MX, SRV, TXT/SPF, A/AAAA, HTTP e TLS;
- vincula assinaturas HTTP específicas ao provedor e ao CNAME observados;
- separa takeover, exposição, configuração quebrada e candidatos que ainda exigem prova de reivindicabilidade;
- armazena resultados e instantâneos em SQLite para revalidação posterior;
- oferece saída em texto, JSON Lines e modos de explicação;
- roteia verificadores ativos somente para provedores e CNAMEs compatíveis;
- permite módulos ativos opcionais para exposição em nuvem, AXFR, redirecionamentos e outras verificações;
- inclui sondas de evasão HTTP de requisição única e um laboratório separado de framing;
- oferece reivindicações reais e auditáveis para o Amazon S3 e o Amazon Route 53 no modo agressivo, com prova de controle e tentativa imediata de liberação.

### Maturidade dos vetores

| Vetor | Tratamento atual |
|---|---|
| CNAME | vínculo com o provedor, assinatura HTTP, TLS, verificadores e Mutator |
| NS | corte de zona autoritativo, visão da zona pai, registros de cola (glue) e DS; Amazon Route 53 pode provar controle por reivindicação temporária autorizada |
| MX | relata destino quebrado e contexto do provedor; registrabilidade e controle de entrega permanecem não verificados |
| SRV | preserva nome, prioridade, peso, porta e destino, além de oferecer enumeração controlada por `--check-srv` |
| TXT/SPF | observa tokens TXT sem declarar obsolescência; SPF mantém a cadeia e usa o RCODE DNS real |
| A/AAAA | correlaciona ASN e provedor de nuvem e produz somente um candidato para revisão quando há sinais adicionais; portas fechadas não provam IP desalocado |
| AXFR | tratado como exposição de informação, nunca como controle da zona |

Delegações seguem estados próprios: `DELEGATION_BROKEN`, `DELEGATION_TAKEOVER_CANDIDATE`, `DELEGATION_CLAIMABILITY_VERIFIED` e `ZONE_CONTROL_CONFIRMED`. A implementação passiva produz apenas os dois primeiros; o adaptador do Amazon Route 53 pode produzir o último por criação temporária e correspondência exata do conjunto de NS.

### Como ler a saída

A saída humana lista todos os achados do host e coloca primeiro aquele com maior impacto ou que efetivamente causou a classificação:

```text
[TAKEOVER PROVÁVEL] assets.example.com
  Vetor               : CNAME
  Cadeia              : assets.example.com → missing.s3.amazonaws.com
  Provedor            : AWS/S3
  Evidência           : HTTP 404 — "NoSuchBucket"
  Fonte               : linha de base
  Confiança da análise: ALTA
  Próximo passo       : valide o vínculo do recurso no provedor dentro do escopo do programa

[MX QUEBRADO] assets.example.com
  Vetor               : MX
  Destino             : mail.expired.example
  Resultado DNS       : NXDOMAIN
  Provedor            : desconhecido
  Propriedade         : EXTERNO NÃO VERIFICADO
  Registrabilidade    : expired.example (NÃO VERIFICADA)
  Reivindicabilidade  : NÃO COMPROVADA
  Impacto             : interceptação de e-mail somente após prova de registro ou vínculo no provedor
  Confiança da análise: ALTA
  Próximo passo       : valide propriedade, disponibilidade de registro e controle de entrega
```

`[CONTROLE CONFIRMADO]`, `[CONTROLE DO RECURSO COMPROVADO]` e `[CONTROLE DA ZONA CONFIRMADO]` são reservados a uma prova ativa estruturada. Rótulos de quebra, revisão, recurso órfão e takeover provável continuam sendo achados de investigação.

## Requisitos e instalação

- Go 1.26.5 ou superior.

Para instalar pelo módulo Go:

```bash
go install github.com/amchdd/subdomainabber@latest
```

O Go grava o executável em `GOBIN` ou, quando essa variável não está definida, em `$(go env GOPATH)/bin`. Inclua esse diretório no `PATH`. No PowerShell, um executável compilado na pasta atual deve ser chamado com o prefixo `.\`.

Para compilar a partir do código-fonte:

```bash
git clone https://github.com/amchdd/subdomainabber.git
cd subdomainabber
go build -o subdomainabber .
```

No PowerShell, compile e execute o binário local desta forma:

```powershell
git clone https://github.com/amchdd/subdomainabber.git
Set-Location subdomainabber
go build -o subdomainabber.exe .
.\subdomainabber.exe --version
```

Confirme o executável:

```bash
subdomainabber --version
# v0.1.0-alpha
```

## Uso rápido

O comando `scan` aceita argumentos, arquivo e entrada padrão (`stdin`). Entradas duplicadas são removidas.
Quando a entrada é fornecida diretamente ao comando raiz, `scan` é assumido automaticamente; portanto, `subdomainabber -l hosts.txt` e `subdomainabber scan -l hosts.txt` são equivalentes.

```bash
# Argumentos
subdomainabber scan api.example.com assets.example.com

# Arquivo, um host por linha
subdomainabber scan --list hosts.txt

# Forma curta equivalente
subdomainabber -l hosts.txt

# Pipeline
printf "api.example.com\nassets.example.com\n" | subdomainabber scan

# JSON Lines para automação
subdomainabber scan -l hosts.txt --json --silent

# Explicação da classificação
subdomainabber scan -l hosts.txt --explain
```

Por padrão, a ferramenta aceita até 50 hosts em processamento simultâneo, tempo limite de rede de 5 segundos por operação e limite global de 10 operações por segundo. Quando o limite de taxa está ativo, a quantidade efetiva de hosts em processamento é limitada ao menor valor entre `--concurrency` e `--rl`; portanto, `--concurrency 50 --rl 10` executa dez hosts simultaneamente e evita que algum host fique indefinidamente sem oportunidade de execução. O tempo aguardando uma permissão do limitador não consome o tempo limite de rede.

Os valores finais de concorrência, tempo limite e taxa precisam ser positivos. Nas opções de `scan`, zero apenas mantém o valor seguro da configuração ou o padrão; ele não desabilita o limitador. O modo `--daemon` aceita intervalos a partir de um minuto, e `enum --concurrency` aceita valores entre 1 e 1000.

Em terminal interativo — ou sempre com `--verbose` — o progresso inicial é exibido imediatamente em `stderr` e atualizado a cada dez segundos, com hosts processados, achados, hosts ativos, operações concedidas ou aguardando, tempo decorrido, velocidade e previsão de término (ETA). A previsão fica em calibração até dez hosts terminarem para evitar estimativas iniciais enganosas. Resultados e JSON Lines continuam em `stdout`.

Ajuste os limites às regras do programa:

```bash
subdomainabber scan -l hosts.txt --concurrency 10 --timeout 8 --rl 5
```

`--check-all` é deliberadamente intensivo. Cada host pode gerar consultas para vários tipos DNS, HTTP/TLS, delegação, DNSSEC e AXFR. Como todos os módulos compartilham o mesmo limitador global, listas grandes ainda podem levar vários minutos. A ferramenta reutiliza consultas DNS idênticas, executa NS, DNSSEC e AXFR por corte de zona e enumera os seis nomes SRV comuns uma vez por domínio registrável. A enumeração SRV em cada nome de host só ocorre com `--srv-exhaustive`.

## Módulos ativos e níveis de risco

As flags abaixo geram tráfego adicional. Elas nunca ampliam a autorização concedida pelo programa.

| Opção | Comportamento |
|---|---|
| `--check-all` | Habilita NS, enumeração SRV, exposição em nuvem, AXFR, DNSSEC, e-mail, cabeçalhos, Shadow IT e redirecionamentos. Não habilita evasão nem framing. |
| `--check-ns` | Ativa o catálogo de NS orientado a provedores; o modo passivo gera um candidato e `--aggressive` pode provar Amazon Route 53 por correspondência exata. |
| `--check-srv [--srv-owners ...]` | Enumera nomes comuns (`_sip._tcp`, `_autodiscover._tcp` etc.) uma vez por domínio registrável ou usa uma lista controlada. Nomes SRV recebidos diretamente também são analisados. |
| `--srv-exhaustive` | Com `--check-srv`, repete a enumeração em cada nome de host. É mais lento e só deve ser usado quando o escopo realmente possui zonas SRV em subdomínios arbitrários. |
| `--evasion` | Executa cinco sondas HTTP brutas de requisição única somente quando a linha de base aparenta bloqueio. Não executa CL.TE/TE.CL. |
| `--whois-pivot --whois-pivot-confirm --whois-pivot-allowlist ...` | Descobre domínios relacionados por WHOIS e só inclui na varredura os domínios registráveis presentes na lista permitida. A confirmação não substitui a leitura do escopo do programa. |
| `--check-framing` | Laboratório CL.TE/TE.CL de risco elevado. Exige também confirmação e lista de permissões controlada. |
| `--aggressive` | Habilita validação ativa no Amazon S3 e no Amazon Route 53. Exige confirmação, lista de permissões exata e credenciais capazes de criar e excluir o recurso temporário. |
| `--discord-webhook` | Envia achados relevantes da varredura inicial ao Discord. Prefira `SABBER_DISCORD_WEBHOOK` para não gravar o segredo no histórico do shell. |
| `--discord-min-severity` | Define o limiar `info`, `low`, `medium`, `high` ou `critical`. O padrão `medium` elimina HEALTHY e misconfigurações de baixa prioridade. |
| `--min-severity` | Filtra a CLI pela mesma escala do Discord. Vazio mantém todos os achados acionáveis; `medium` é útil para focar takeover provável, delegação candidata e exposições. |
| `--show-inconclusive` | Exibe blocos humanos para `UNKNOWN` e `INSUFFICIENT_EVIDENCE`. Por padrão, esses estados ficam no JSON/SQLite e não poluem o stdout. |
| `--no-color` | Desabilita ANSI. Cores também são removidas automaticamente em pipes/arquivos e quando `NO_COLOR` está definido. |

Framing experimental deve ser usado apenas em laboratório próprio e controlado:

```bash
subdomainabber scan lab.example \
  --check-framing \
  --framing-confirm-controlled \
  --framing-allowlist lab.example
```

Não execute framing em infraestrutura de terceiros sem autorização específica. Uma diferença de interpretação não é evidência de provedor ou de takeover. Consulte [a auditoria técnica do HTTP Mutator](docs/http-mutator-audit.md).

## Reivindicação automática agressiva

O modo agressivo existe para programas que autorizam explicitamente a criação temporária do recurso. Na `v0.1.0-alpha`, há validação ativa para o Amazon S3 e para zonas do Amazon Route 53. MX, SRV, SPF, TXT, A/AAAA, Azure, Google Cloud e outros provedores permanecem não suportados enquanto não houver um adaptador capaz de criar, provar controle e liberar o recurso.

```bash
export SABBER_AWS_ACCESS_KEY="..."
export SABBER_AWS_SECRET_KEY="..."
# export SABBER_AWS_SESSION_TOKEN="..." # se usar credenciais temporárias
export SABBER_AWS_REGION="us-east-1"

subdomainabber scan bucket.example.com \
  --aggressive \
  --aggressive-confirm-auto-claim \
  --aggressive-allowlist bucket.example.com
```

Quando o host chega a uma classificação elegível e possui um candidato compatível, o fluxo S3:

1. registra `ATTEMPTING` no SQLite, com a identidade esperada e o token de prova, antes de alterar o estado externo;
2. extrai o nome exato do bucket do endpoint S3 publicado no CNAME e recusa endpoints ambíguos ou regiões incompatíveis;
3. grava um objeto privado com o token aleatório;
4. verifica o token por `HeadObject`;
5. registra `CLAIM_SUCCESS` somente após a prova;
6. tenta remover o objeto e o bucket imediatamente;
7. registra `RELEASE_SUCCEEDED` ou mantém `RELEASE_FAILED` para reconciliação na próxima execução agressiva.

Para o Amazon Route 53, o mecanismo só aceita uma delegação publicada pela zona pai quando todos os NS falharam de forma conclusiva, não há DS na zona pai e todos os servidores de nomes pertencem ao mesmo provedor. Um simples `NS_PROVIDER_MATCH` nunca autoriza a criação. Depois dessas condições, o mecanismo cria uma zona hospedada temporária para o corte de zona, compara o conjunto completo de NS atribuído com a delegação publicada pela zona pai e só emite `ZONE_CONTROL_CONFIRMED` quando os conjuntos são idênticos; depois, tenta remover a zona. Se os conjuntos forem diferentes e a limpeza for confirmada, produz `DELEGATION_CLAIMABILITY_NOT_DEMONSTRATED` e rebaixa o caso para `DELEGATION_BROKEN`. Uma falha de limpeza permanece auditada para reconciliação e interrompe a execução agressiva. O mesmo corte de zona só é testado uma vez por execução, mesmo quando muitos hosts descendentes aparecem na entrada.

As confirmações, a lista permitida e as credenciais são verificadas antes da varredura. Já as condições derivadas das evidências, como delegação pai, DS, falha conclusiva e vínculo com o provedor, são avaliadas durante a análise; candidatos que não as atendem são ignorados ou registrados como não suportados, sem criação externa. Não use credenciais administrativas: aplique uma política dedicada e limite a conta ou região conforme as regras do programa.
O modo agressivo não pode ser combinado com `--daemon`: cada execução com escrita precisa ser única e explícita. Um host já registrado no SQLite pode ser informado novamente em uma varredura agressiva; varreduras comuns também atualizam o histórico em vez de abandonar observações repetidas.

## Revalidação e banco local

Cada varredura usa `subdomainabber.db` por padrão. Escolha outro caminho com `--db`.

```bash
subdomainabber --db programa.db scan -l hosts.txt
subdomainabber --db programa.db verify --only-risky
subdomainabber --db programa.db db stats
subdomainabber --db programa.db db export --format json
```

`verify` revalida os hosts já armazenados no banco; ele não recebe uma lista de entrada.
A varredura inicial envia achados relevantes como `DISCOVERED`, e o `verify` envia mudanças posteriores. Configure o Discord com `--discord-webhook` ou `SABBER_DISCORD_WEBHOOK`; o Telegram usa `SABBER_TELEGRAM=bot_token:chat_id`.

A CLI e o Discord usam a mesma seleção de evidência causal em vez da primeira evidência coletada. Configurações incorretas mostram o vetor e a causa concreta, como `HTTP_OPEN_REDIRECT` ou `SPF_BROKEN_INCLUDE`; ausência isolada de HSTS/CSP permanece apenas como contexto. Delegações e AXFR são agrupadas pela zona. Assim, dezenas de hosts abaixo de `projects.example.com` geram apenas um achado por corte de zona. Na saída humana da CLI, `HEALTHY`, `UNKNOWN` e `INSUFFICIENT_EVIDENCE` ficam ocultos por padrão; use `--show-inconclusive` para revisão. Eles nunca são enviados como descobertas ao Discord, inclusive quando o limiar é `info`.

| Severidade | Classificações típicas |
|---|---|
| `critical` | `TAKEN_OVER`, `ZONE_CONTROL_CONFIRMED` |
| `high` | `CONFIRMED_TAKEOVERABLE`, `DELEGATION_CLAIMABILITY_VERIFIED`, `TAKEOVERABLE` |
| `medium` | `LIKELY_TAKEOVERABLE`, `DELEGATION_TAKEOVER_CANDIDATE`, `EXPOSED` |
| `low` | `ORPHANED`, `DELEGATION_BROKEN`, `MISCONFIGURED` |
| `info` | transições de correção; descobertas saudáveis continuam suprimidas |

Exemplo mantendo apenas prioridade média ou superior:

```bash
subdomainabber -l hosts.txt \
  --check-all \
  --min-severity medium \
  --discord-min-severity medium \
  --discord-webhook "$SABBER_DISCORD_WEBHOOK"
```

## Assinaturas e benchmarks

```bash
subdomainabber fingerprints validate
subdomainabber fingerprints list
subdomainabber fingerprints coverage
subdomainabber benchmark synthetic
subdomainabber benchmark regression datasets/regression
subdomainabber benchmark mutator
```

`benchmark gold` acessa somente as entradas marcadas como verificadas no conjunto informado e deve obedecer às mesmas regras de autorização da ferramenta. Os arquivos em `datasets/gold` são modelos inativos com domínios reservados; substitua-os apenas por infraestrutura controlada e registre data, autorização, referência e evidência esperada.
`benchmark mutator` é totalmente local e mede sondas executadas, rejeições, diferenças, assinaturas, falsos positivos e falsos negativos em comportamentos controlados de borda e origem. Os nomes das pilhas descrevem comportamentos simulados, não alegações de vulnerabilidade de fornecedores.

## Configuração

A precedência é: padrões internos, arquivo YAML, variáveis `SABBER_*` e flags CLI. Veja [config.example.yaml](config.example.yaml) e [.env.example](.env.example). Nunca versione tokens, webhooks ou bancos de resultados.

`.env.example` é apenas uma referência: a ferramenta não carrega arquivos `.env` automaticamente. Defina as variáveis no processo ou no mecanismo de segredos do ambiente de execução.

Sem `--config`, o arquivo padrão é `subdomainabber/config.yaml` dentro do diretório de configuração do usuário, como `%APPDATA%\subdomainabber\config.yaml` no Windows ou `${XDG_CONFIG_HOME:-$HOME/.config}/subdomainabber/config.yaml` no Linux.

```yaml
no_color: false
discord_min_severity: medium
```

A saída humana da CLI, a ajuda, o progresso, os erros e as notificações são apresentados em PT-BR, sem opção de idioma. A estrutura JSON e os identificadores técnicos de classificações e evidências permanecem estáveis para automação; apenas os textos descritivos humanos são emitidos em PT-BR.

## Limitações conhecidas do alpha

- assinaturas podem ficar desatualizadas ou produzir falsos positivos ou negativos;
- validação ativa real está limitada a Amazon S3 e Amazon Route 53;
- o motor grava uma tentativa preventiva antes de criar recursos e tenta reconciliá-la na execução agressiva seguinte; no Amazon S3, uma interrupção entre a criação do bucket e a gravação do objeto de prova ainda exige inspeção manual da conta;
- WAFs, CDNs, respostas DNS curinga e diferenças regionais podem alterar as observações;
- o benchmark local atual demonstra os invariantes do Mutator, mas não substitui medições contra versões reais de Nginx, HAProxy, Envoy, Traefik e Apache;
- MX/SRV/SPF/TXT/A/AAAA continuam candidatos até que exista um adaptador de criação, prova de controle e liberação para o provedor;
- algumas verificações dependem de conectividade e APIs de terceiros;
- `--timeout` limita a operação de rede após a permissão do limitador de taxa; ele não é um prazo total para concluir todos os módulos de um host;
- apenas `TAKEN_OVER`, `ZONE_CONTROL_CONFIRMED` e resultados com prova ativa estruturada significam controle comprovado; as demais classificações representam achados para investigação.

## Desenvolvimento

```bash
go fmt ./...
go mod verify
go vet ./...
go run github.com/rhysd/actionlint/cmd/actionlint@v1.7.12 .github/workflows/ci.yml .github/workflows/release.yml
go run honnef.co/go/tools/cmd/staticcheck@v0.7.0 ./...
go run golang.org/x/vuln/cmd/govulncheck@v1.6.0 ./...
go test ./... -count=1
go test -race ./... -count=1
go run . fingerprints validate --strict
go run . benchmark synthetic
go run . benchmark regression datasets/regression
go run . benchmark mutator
go build ./...
```

O detector de condições de corrida depende de CGO. No Windows, instale um compilador C compatível antes de executar `go test -race`; sem esse requisito, use o resultado da etapa equivalente da CI em Linux e não considere a validação local concluída.

Leia [CONTRIBUTING.md](CONTRIBUTING.md) antes de enviar mudanças. Vulnerabilidades no próprio projeto devem seguir [SECURITY.md](SECURITY.md).

## Licença

O código original do projeto é disponibilizado sob a [MIT License com a Commons Clause License Condition v1.0](LICENSE). A Commons Clause restringe a venda do Software conforme a definição presente no texto da licença, tornando o projeto **source-available**.

A versão `v0.1.0-alpha` e os commits publicados antes da adoção da Commons Clause permanecem sob os termos da licença MIT que os acompanhava. Consulte [LICENSING.md](LICENSING.md) para o histórico e o resumo dos termos.

O catálogo inclui material derivado sujeito aos avisos e às condições descritos em [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
