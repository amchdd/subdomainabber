# Motor de reivindicação agressiva

A reivindicação automática da versão de desenvolvimento `v0.1.0-alpha` é uma operação explícita que altera estado externo. Ela não é habilitada por `--check-all`, `--evasion`, `verify` nem por qualquer comando de leitura.

## Condições obrigatórias

Uma execução real exige simultaneamente:

```text
--aggressive
--aggressive-confirm-auto-claim
--aggressive-allowlist <host exato ou arquivo>
```

Cada entrada da lista permitida também precisa estar entre os alvos da varredura. O motor considera candidatos CNAME vinculados ao provedor e candidatos estruturados de NS/MX/SRV/SPF/TXT/A/AAAA, mas só executa escrita quando existe um provedor real compatível.

`--aggressive` é incompatível com `--daemon`, para que uma autorização de escrita não se transforme em reivindicações periódicas. Um achado já salvo pode ser reavaliado por uma nova execução agressiva explícita.

## Provedores suportados

O adaptador do Amazon S3 extrai o nome do bucket de um endpoint virtual-hosted reconhecido no CNAME, exige uma região compatível e só prossegue quando `HeadBucket` comprova sua ausência. Depois, cria o bucket, grava uma prova privada e a valida antes da liberação. O hostname analisado nunca substitui o recurso codificado no CNAME.

O adaptador do Amazon Route 53 cria uma zona hospedada temporária para o corte de zona e exige que o conjunto completo de servidores NS atribuído seja exatamente igual ao conjunto delegado pela zona pai. Qualquer diferença cancela a prova e inicia a limpeza. A correspondência exata produz `ZONE_CONTROL_CONFIRMED` antes da liberação auditada.

Provedores ou vetores não implementados geram `UNSUPPORTED` e nunca `CLAIM_SUCCESS`. Assim, assinaturas JSON ampliam a descoberta e o roteamento, mas não substituem o adaptador de prova.

## Estados persistidos

```text
UNSUPPORTED
ATTEMPTING
CLAIM_SUCCEEDED
CLAIM_FAILED
RELEASE_PENDING
RELEASE_SUCCEEDED
RELEASE_FAILED
```

Antes de chamar o provedor, o motor grava `ATTEMPTING` com o host, o vetor, o recurso esperado e um token aleatório. Esse registro preventivo não afirma que o recurso foi criado. Depois de uma alocação real, ele é substituído pelo recibo completo do provedor.

Uma falha sem recurso criado termina em `CLAIM_FAILED`. Se o provedor devolver um recibo parcial, o motor registra `RELEASE_PENDING` antes de tentar a limpeza. Falhas de liberação permanecem em `RELEASE_FAILED`; a próxima execução agressiva reconcilia registros pendentes antes de iniciar a varredura.

As operações de criação são serializadas. Se uma liberação falhar ou o provedor não devolver uma identidade recuperável, o motor bloqueia novas reivindicações, cancela o restante da execução agressiva e retorna um erro. Uma nova execução só começa depois que a reconciliação confirmar a ausência ou a liberação do recurso pendente.

Uma tentativa interrompida em `ATTEMPTING` só é recuperada quando o adaptador encontra uma identidade vinculada ao token persistido:

- no Amazon S3, a ausência do bucket encerra a tentativa; se o bucket existir, ele precisa conter o objeto privado com os metadados de prova esperados;
- no Amazon Route 53, o nome da zona e a `CallerReference` derivada do token precisam coincidir.

Recursos apenas homônimos não são removidos. Se nenhum recurso autenticado for encontrado, a tentativa termina em `CLAIM_FAILED` sem exclusão externa.

## Testes

Testes automatizados usam provedores e clientes simulados do Amazon S3 e do Amazon Route 53. Eles cobrem correspondência exata de delegação, incompatibilidade com limpeza, sucesso, falha, reversão, prova de controle e reconciliação. Nenhum teste da CI cria recursos reais.

## Limite de recuperação

No Amazon S3, ainda existe uma janela entre `CreateBucket` e `PutObject`: se o processo terminar nesse intervalo, o bucket não contém o token necessário para uma recuperação segura. Inspecione a conta da AWS e remova manualmente o recurso criado pela tentativa antes de iniciar outra execução agressiva.

Se a API do provedor estiver indisponível ou a reconciliação não conseguir provar a identidade do recurso, a ferramenta interrompe o modo agressivo e preserva o registro para análise. Não exclua recursos apenas pelo nome.
