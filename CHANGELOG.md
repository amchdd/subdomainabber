# Changelog

Todas as mudanças relevantes deste projeto serão registradas neste arquivo.

O formato segue [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) e as versões seguem [Semantic Versioning](https://semver.org/).
Datas e links de comparação são acrescentados somente depois da publicação da tag correspondente.

## Não publicado

### Adicionado

- limiar de notificação Discord por `--discord-min-severity`/`SABBER_DISCORD_MIN_SEVERITY`;
- cores semânticas no terminal interativo, com suporte a `--no-color` e `NO_COLOR`;
- progresso periódico com hosts processados, hosts ativos, fila do limitador de taxa, vazão e ETA;
- filtros humanos `--min-severity` e `--show-inconclusive`, usando a mesma escala de severidade do Discord;
- `--srv-exhaustive` para a enumeração SRV intencional em cada nome de host;
- `config.example.yaml` sem segredos para documentar a configuração persistente;
- `--whois-pivot-allowlist` para impedir que o pivotamento inclua domínios relacionados sem uma autorização explícita e exata;
- validação dos workflows com `actionlint` na integração contínua.

### Alterado

- licenciamento do código original alterado de MIT para MIT com a Commons Clause License Condition v1.0; `v0.1.0-alpha` e versões anteriores permanecem sob MIT;
- dependências Go diretas atualizadas e ambiente de execução mínimo elevado para Go 1.26.5;
- AWS Smithy, Cobra e dependências transitivas Go atualizadas;
- ações `checkout` e `setup-go` do GitHub Actions atualizadas para a v7;
- workflows passam a obter a versão do Go diretamente de `go.mod` e desativam a troca automática de toolchain;
- lançamentos com sufixo de pré-lançamento do SemVer são publicados no GitHub como pré-lançamentos;
- atualizações das GitHub Actions são agrupadas pelo Dependabot;
- enumeração passiva, pivotamento WHOIS e DNS ativo agora compartilham proxy, tempo limite e limitador de taxa;
- benchmark controlado do Mutator passa a falhar também quando encontra falsos negativos;
- opções de varredura podem ser usadas diretamente no comando raiz, sem informar o subcomando `scan`;
- achados iniciais relevantes podem ser enviados ao Discord por `--discord-webhook`;
- a quantidade efetiva de hosts em processamento é ajustada ao limite global de taxa para evitar privação de execução e reduzir o tempo até o primeiro resultado;
- CLI e Discord compartilham a mesma seleção de evidência causal;
- CLI, ajuda, progresso, erros, relatórios, Discord e Telegram são padronizados em PT-BR; estrutura JSON e identificadores técnicos permanecem estáveis;
- configuração de idioma removida (`--lang`, `SABBER_LANGUAGE`, `language:` no YAML e API Go associada); textos descritivos humanos passam a usar PT-BR fixo;
- anotações operacionais das assinaturas e dos conjuntos de benchmark passam a usar PT-BR, sem alterar trechos literais das respostas dos provedores;
- progresso inclui achados, tempo decorrido, calibração de ETA e distribuição final por categoria;
- o fluxo de lançamento valida o formato SemVer da tag e os mesmos testes essenciais da CI antes de produzir pacotes, que agora incluem os avisos de terceiros;
- nomes SRV comuns são enumerados por domínio registrável por padrão, preservando nomes explícitos.

### Corrigido

- configurações numéricas inválidas são rejeitadas antes da criação de limitadores, canais e rotinas concorrentes; o modo daemon exige intervalo mínimo de um minuto e a enumeração impõe limites seguros de concorrência;
- alertas NS e tentativas agressivas são deduplicados pelo corte de zona, evitando mensagens repetidas por hosts descendentes;
- descobertas `HEALTHY`, `UNKNOWN` e `INSUFFICIENT_EVIDENCE` nunca são enviadas ao Discord;
- o Discord seleciona a evidência causal, ordena por severidade e apresenta o vetor e o recurso em vez da primeira evidência coletada;
- incompatibilidade entre servidores de nomes na reivindicação do Amazon Route 53 rebaixa o achado para delegação quebrada após limpeza confirmada;
- o relatório de CNAME não herda o provedor de evidências A/ASN/CDN pertencentes a outro vetor;
- ANSI não contamina JSON, pipes ou arquivos redirecionados;
- descoberta autoritativa rejeita SOA externo retornado após CNAME, impedindo AXFR/NS fora da zona do nome original;
- correspondência com limites DNS aplicada a TLS curinga, Shadow IT, enumeração e padrões de provedor;
- redirecionamentos abertos exigem correspondência exata do nome de host de prova;
- cancelamento da varredura não deixa tokens presos no semáforo;
- transições entre classificações diferentes de risco equivalente são persistidas como `CHANGED`;
- relatório de confiança aponta o campo vetorial realmente inválido;
- Mutator cobre bordas opacas com respostas 404/503 e desafios JavaScript com resposta 200 sem relaxar controles de repetibilidade e vínculo com o provedor;
- o tempo limite HTTP/bruto começa após a permissão do limitador de taxa, impedindo que operações expirem sem tocar o alvo;
- consultas DNS idênticas concorrentes usam `singleflight`, e a chave do cache diferencia opções DNSSEC;
- detalhes autoritativos, saúde NS, DNSSEC e AXFR são reutilizados por corte de zona dentro do lote;
- AXFR é executado e apresentado uma única vez por zona em cada lote;
- DNSSEC consulta o ápice autoritativo em vez de cada nome de host;
- cancelamento exibe contadores finais sem uma linha de `context canceled` para cada host;
- a saída humana alternativa mostra vetor e evidência causal em vez de somente a classificação genérica;
- `NS_PROVIDER_MATCH` saudável deixa de criar achado, análise de impacto ou candidato de reivindicação automática;
- a reivindicação automática de NS exige a evidência `DELEGATION_TAKEOVER_CANDIDATE` e um provedor uniforme em todos os servidores de nomes;
- respostas NS `NOERROR` só são saudáveis quando possuem AA e o SOA exato da zona;
- tempos esgotados, SERVFAIL e erros parciais de A/AAAA não viram `CNAME_DANGLING`;
- Mutator ignora candidatos que não sejam CNAME ou não possuam assinatura HTTP compatível;
- a descoberta deixa de consultar PTR no nome de host direto e SRV sem prefixo em nomes que não são registros SRV;
- cabeçalhos usam a observação HTTPS real, e TLS/redirecionamentos são evitados quando não existe rota ou linha de base aplicável;
- as análises de Cookie/CORS são executadas depois da correlação e do Mutator, somente para candidatos reais e sem seguir redirecionamentos externos;
- registros explícitos diferentes de um curinga ancestral deixam de ser descartados;
- uma resposta SOA inconclusiva usa uma busca conservadora pelos cortes de zona publicados, sem aceitar SOA de destino externo;
- duplicatas de delegação deixam de reaparecer pela saída alternativa do renderizador;
- o motor de reivindicação grava um registro preventivo antes de alterar o estado externo e reconcilia tentativas interrompidas somente quando o token persistido comprova a identidade do recurso;
- falhas simultâneas ao persistir o recibo e liberar o recurso deixam um registro recuperável, em vez de descartar a tentativa;
- validações agressivas são serializadas e interrompidas quando uma limpeza falha ou a identidade externa fica inconclusiva;
- o adaptador S3 reivindica o bucket codificado no CNAME, valida a região do endpoint e nunca usa o hostname analisado como nome substituto;
- a visão da delegação pai exige consenso entre respostas autoritativas válidas, e qualquer DS observado impede a confirmação de ausência;
- verificadores de provedores respeitam limites de labels DNS e rejeitam domínios apenas semelhantes.

### Removido

- módulos sem caminho de execução para captura de tela sem interface gráfica, pivotamento de certificados e configuração dinâmica;
- gerador Python obsoleto que podia reintroduzir assinaturas CNAME inválidas;
- dependências transitivas do Chromium que ficaram sem uso.

### Segurança

- a CI passa a verificar vulnerabilidades alcançáveis com `govulncheck`;
- filtros de escopo deixam de aceitar domínios que apenas terminam com o texto do alvo.

## Base da versão v0.1.0-alpha

### Adicionado

- correlação de evidências DNS, CNAME, HTTP e TLS;
- classificação vinculada ao provedor com assinaturas HTTP estruturadas;
- entrada da varredura por argumentos, `--list` ou entrada padrão;
- histórico e revalidação no SQLite;
- domínio registrável calculado com Public Suffix List;
- sondas HTTP controladas por `--evasion`;
- laboratório de framing separado, com confirmação e lista de permissões;
- roteamento de verificadores por provedor e CNAME;
- reivindicação automática real no Amazon S3 por `--aggressive`, com prova privada, auditoria e tentativa de liberação imediata;
- validação ativa no Amazon Route 53 que cria uma zona temporária, exige o conjunto exato de NS delegado e executa liberação auditada;
- candidatos estruturados para delegação NS, MX, SRV, TXT, SPF e A/AAAA;
- descoberta do corte de zona autoritativo, delegação na zona pai, registros de cola (glue) e DS;
- enumeração SRV controlada e corpus JSON multivetor para NS, MX, SRV, TXT, SPF e ASN;
- saída humana com vários achados, ordenada por impacto, e medição local do Mutator;
- CI com `vet`, testes, detector de condições de corrida e compilação multiplataforma.

### Alterado

- `NS_ALL_DEAD` conta servidores de nomes únicos;
- AXFR usa o ápice autoritativo e é classificado como exposição;
- MX, SRV, SPF, TXT e A/AAAA só chegam a controle confirmado após prova ativa específica;
- DMARC usa `_dmarc.<domínio-registrável>` e SPF preserva RCODE e cadeia;
- `--rl` limita transações DNS, HTTP, TLS, verificadores e análises de nuvem por um limitador compartilhado;
- o verificador respeita o proxy e bloqueia redirecionamentos para hosts externos;
- ausência de evidência agora é `INSUFFICIENT_EVIDENCE`, não `HEALTHY`;
- `--no-wildcard-filter` passa a desabilitar efetivamente o filtro;
- a correspondência de NS, MX e SRV preserva os limites DNS.

### Segurança

- padrões sem reivindicação automática e com limite de taxa de 10;
- `--check-all` não habilita evasão, framing ou reivindicação automática;
- a reivindicação automática exige confirmação e lista de permissões exata;
- nenhum provedor sem implementação real produz `CLAIM_SUCCESS`;
- AXFR, NS inoperante, TLS autoassinado e pontuação genérica não promovem um host a takeover;
- varreduras repetidas atualizam a observação temporal em vez de serem descartadas pela desduplicação.
