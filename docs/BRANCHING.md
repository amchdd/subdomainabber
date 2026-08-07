# Estratégia de branches

O Subdomainabber usa um fluxo simples de integração contínua, com branches curtas e duas branches permanentes.

## Branches permanentes

### `main`

Representa o estado estável do projeto.

- recebe apenas pull requests vindas de `dev` ou de `hotfix/*`;
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

## Hotfixes

Correções urgentes de uma versão estável partem de `main` e usam `hotfix/*`.

1. crie `hotfix/<descrição>` a partir de `main`;
2. abra o pull request para `main`;
3. depois do merge, sincronize a correção em `dev` por pull request ou merge controlado.

## Pull requests

- branches de trabalho normalmente apontam para `dev`;
- apenas `dev` e `hotfix/*` apontam para `main`;
- mantenha cada pull request pequeno e focado;
- use títulos no padrão Conventional Commits, como `feat(dns): adicionar evidência DNSSEC`;
- prefira squash merge para manter o histórico da branch estável legível;
- não faça merge com verificações obrigatórias falhando;
- mudanças de comportamento devem incluir testes e documentação correspondente.

## Lançamentos

1. atualize changelog, versão e documentação em `dev`;
2. abra um pull request de `dev` para `main`;
3. valide a CI e revise o conteúdo completo da versão;
4. faça o merge;
5. crie a tag semântica a partir de `main`;
6. aguarde o workflow de release concluir antes de anunciar a versão.
