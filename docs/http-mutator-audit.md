# HTTP Mutator: limites, framing e evidência de provedor

O HTTP Mutator padrão é ativado explicitamente por `--evasion` e contém somente sondas de requisição única: NUL no cabeçalho `Host`, espaço em branco adicional no `Host`, ponto final no valor de `Host`, porta explícita e alvo de requisição no formato absoluto. CL.TE e TE.CL não pertencem a `DefaultHTTPMutations` e não são mecanismos de descoberta de takeover de subdomínio em produção.

Cada experimento padrão usa HTTP/1.1 bruto na ordem `C1 → M1 → M2 → C2`. C1/C2 precisam ser equivalentes, M1/M2 precisam ser equivalentes e nenhuma observação pode conter erro de transporte ou de interpretação. A linha de base HTTP inicial decide se o Mutator deve executar, mas também participa do invariante da assinatura: uma regra só é descrita como revelada quando está ausente na linha de base inicial, em C1 e em C2.

A decisão de execução reconhece códigos de status de bloqueio explícitos, sinais conhecidos de WAF ou desafio e desafios JavaScript. Como `--evasion` exige ativação explícita, respostas opacas 404 ou 503 também podem ser investigadas quando já existe um candidato de provedor; isso apenas executa as sondas. Nenhuma dessas respostas promove a classificação sem controles estáveis, mutações reproduzíveis e uma assinatura específica vinculada ao mesmo provedor.

## Destino, autoridade e TLS

`MutationContext` mantém valores independentes:

- `DialHost` e `DialPort`: único destino TCP;
- `HTTPAuthority`: único valor usado para Host/autoridade HTTP;
- `TLSServerName`: único valor usado como SNI;
- `Scheme`: seleciona HTTP ou HTTPS.

O transporte não deriva o SNI da autoridade ou do destino. O coletor inicializa os três valores a partir do host já colocado em escopo; ele não descobre nem se conecta automaticamente a um destino alternativo. HTTPS tem prioridade, e cada esquema recebe um orçamento próprio, impedindo o HTTP de consumir todas as sondas.

## Elegibilidade das assinaturas

Uma correspondência classificável usa `HTTPFingerprintRule`, com `RuleID` determinístico, `ProviderID`, padrões CNAME, condições de status, corpo e cabeçalhos, reivindicabilidade e especificidade mínima. A regra deve:

- pertencer exatamente ao provedor candidato;
- corresponder ao CNAME candidato;
- estar marcada como potencialmente reivindicável;
- satisfazer o status, o corpo e os cabeçalhos configurados;
- superar a especificidade mínima;
- não ser um texto genérico.

`Not Found`, `404 Not Found`, `Page Not Found` e `Site Not Found` nunca produzem `HTTP_MUTATION_REVEALED_PROVIDER_FINGERPRINT`. Correspondências genéricas ou inelegíveis geram apenas `HTTP_MUTATION_FINGERPRINT_REVIEW`, com peso zero. A classificação também exige `RuleID` e rejeita esses textos genéricos.

## Framing experimental de risco elevado

CL.TE/TE.CL só podem ser habilitados com as três opções:

```text
--check-framing
--framing-confirm-controlled
--framing-allowlist lab.example,127.0.0.1:8080
```

A lista de permissões também pode ser fornecida em um arquivo. `--check-all` e `--evasion` não habilitam framing. Autoridades fora da lista são ignoradas. O framing experimental não deve ser executado em infraestrutura de terceiros sem autorização específica e não envia sequências destinadas a interferir com requisições de outros usuários.

Seus únicos resultados são:

```text
FRAMING_DIFFERENTIAL
FRAMING_REJECTED
FRAMING_TRANSPORT_FAILURE
FRAMING_NO_DIFFERENCE
```

O framing nunca chama a confirmação do provedor e nunca gera `HTTP_MUTATION_REVEALED_PROVIDER_FINGERPRINT`.

## Laboratório de framing

O laboratório abre pontos de escuta TCP reais para o proxy frontal e a aplicação de origem e usa `NetworkHTTPRawTransport`. Ele registra quantos bytes o proxy frontal encaminhou, quantos a aplicação de origem consumiu e quantos permaneceram. A resposta HTTP contém somente:

```text
FRAMING_DIFFERENTIAL
NO_FRAMING_DIFFERENTIAL
AMBIGUOUS_FRAMING_REJECTED
```

Bytes residuais nunca são convertidos em uma resposta do AWS/S3 ou de outro provedor.

Para CL.TE, o corpo `0\r\n\r\nX` possui 6 bytes: CL consome 6; TE consome 5 e deixa `X`. Para TE.CL, `1\r\nZ\r\n0\r\n\r\n` possui 11 bytes: TE consome 11; CL consome 4 e deixa `\r\n0\r\n\r\n`. Esses fatos demonstram somente uma divergência de interpretação local.

## Laboratório de aplicação

O laboratório de aplicação é separado. Uma aplicação HTTP controlada possui as rotas `/blocked` e `/provider/aws-s3`. Somente uma requisição HTTP completa e válida para `/provider/aws-s3` devolve `The specified bucket does not exist`; bytes restantes ou divergência de framing não influenciam a resposta. Esse caminho comprova a correlação de uma resposta real da aplicação, mas não demonstra que CL.TE ou TE.CL sejam úteis para descobrir takeover.

Todas as requisições brutas continuam sujeitas ao limite de taxa, ao tempo limite de rede por operação, ao cancelamento por contexto, ao proxy configurado e ao limite por esquema.
