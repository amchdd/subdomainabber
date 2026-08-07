# Estratégia de branches

O Subdomainabber usa um fluxo simples de integração contínua, com branches curtas e duas branches permanentes.

## Branches permanentes

### `main`

Representa o estado estável do projeto.

- recebe pull requests vindas de `dev`, de `hotfix/*` ou atualizações de segurança abertas por `dependabot[bot]` em `dependabot/*`;
- deve permanecer publicável e compatível com o processo de release;
- tags e releases são criadas a partir desta branch;
- commits diretos não fazem parte do fluxo normal.

### `dev`

É a branch de integração das mudanças aprovadas para a próxima versão.

- recebe pull requests de desenvolvimento, documentação, testes, CI e dependências;
- deve permanecer compilável e com a CI verde;
- quando estiver pronta para lançamento, abre-se um pull request de `dev` para `main`.

## Branches de trabalho

Crie branches curtas a partir de `dev`, usando um dos prefixos abaixo:

| Prefixo | Uso |
|---|---|
| `feat/` | nova funcionalidade |
| `fix/` | correção de defeito |
| `docs/` | documentação |
| `refactor/` | refatoração sem mudança funcional intencional |
| `test/` | testes e infraestrutura de testes |
| `ci/` | workflows e automação de integração contínua |
| `build/` | build, dependências e empacotamento |
| `perf/` | melhoria de desempenho |
| `chore/` | manutenção sem impacto funcional direto |

Exemplos:

```text
feat/dnssec-evidence
fix/cname-normalization
docs/active-validation
ci/cache-policy
```

O prefixo `dependabot/*` é reservado ao `dependabot[bot]`. Pull requests de atualização de versão apontam para `dev`; atualizações de segurança podem apontar diretamente para `main`, conforme o comportamento do GitHub.

## Hotfixes

Correções urgentes de uma versão estável partem de `main` e usam `hotfix/*`.

1. crie `hotfix/<descrição>` a partir de `main`;
2. abra o pull request para `main`;
3. use squash merge para integrar a correção;
4. sincronize a correção em `dev` por pull request ou merge controlado.

## Pull requests

- branches de trabalho normalmente apontam para `dev`;
- `dev` e `hotfix/*` apontam para `main`;
- `dependabot/*` pode apontar para `main` somente quando o autor for `dependabot[bot]`;
- mantenha cada pull request pequeno e focado;
- use títulos no padrão Conventional Commits, como `feat(dns): adicionar evidência DNSSEC`; pull requests genuínos do Dependabot são validados pela identidade do bot;
- use squash merge em branches curtas que entram em `dev`;
- use **Create a merge commit** em pull requests de `dev` para `main`, preservando a ancestralidade das duas branches permanentes;
- hotfixes e atualizações isoladas do Dependabot podem usar squash merge;
- não faça merge com verificações obrigatórias falhando;
- mudanças de comportamento devem incluir testes e documentação correspondente.

A `main` aceita merge commits intencionais de promoção da `dev`; por isso, ela não deve exigir histórico estritamente linear. A `dev` pode continuar exigindo histórico linear, pois recebe branches curtas por squash.

## Lançamentos

1. atualize changelog, versão e documentação em `dev`;
2. abra um pull request de `dev` para `main`;
3. valide a CI e revise o conteúdo completo da versão;
4. escolha **Create a merge commit**, não squash, para preservar a relação entre `dev` e `main`;
5. crie a tag semântica a partir de `main`;
6. aguarde o workflow de release concluir antes de anunciar a versão.
