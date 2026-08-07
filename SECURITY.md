# Política de segurança

A segurança do Subdomainabber inclui o próprio código, os workflows de CI e release, os mecanismos de validação ativa e qualquer comportamento que possa ampliar tráfego, escopo ou impacto sem consentimento explícito.

## Versões suportadas

| Versão | Suporte de segurança |
|---|---|
| Release mais recente | Sim |
| Branch `main` | Sim, até a próxima release |
| Branch `dev` e branches de trabalho | Melhor esforço, sem garantia de estabilidade |
| Releases anteriores | Não, salvo indicação explícita no changelog |

Durante a fase alpha, correções de segurança podem incluir mudanças incompatíveis na CLI, na configuração, no banco local ou nos critérios de classificação.

## Como relatar uma vulnerabilidade

Use o recurso **Report a vulnerability** na aba **Security** do repositório quando ele estiver disponível. Esse é o canal preferencial porque mantém o relatório e a discussão privados.

Se o recurso não estiver disponível, não publique detalhes técnicos, payloads, credenciais, alvos ou provas de conceito em uma issue. Abra apenas uma issue curta com o título `[SECURITY] Solicitação de canal privado`, sem informações sensíveis, para que o mantenedor indique um canal apropriado.

Inclua, quando possível:

- versão, tag ou commit afetado;
- descrição do impacto e das condições necessárias para exploração;
- passos mínimos para reprodução em ambiente local ou controlado;
- prova de conceito sem dados reais, segredos ou infraestrutura de terceiros;
- logs e capturas devidamente sanitizados;
- sugestão de correção, se houver.

Não use programas de bug bounty, organizações reais ou sistemas de terceiros para demonstrar uma falha no Subdomainabber.

## Prazos de resposta

O objetivo de atendimento é:

- confirmar o recebimento em até 5 dias úteis;
- fornecer uma avaliação inicial em até 10 dias úteis;
- enviar atualizações pelo menos a cada 14 dias enquanto o caso permanecer aberto.

O prazo de correção depende da severidade, da complexidade e da necessidade de mudanças incompatíveis. Nenhuma data de lançamento é garantida antes da conclusão da análise.

## Exemplos de problemas de segurança

São considerados relevantes, entre outros:

- execução arbitrária de comandos ou código;
- exposição de segredos, tokens, webhooks ou credenciais;
- adulteração da cadeia de build, CI, release ou dependências;
- desvio das confirmações, listas permitidas ou limites do modo agressivo;
- criação, reivindicação ou alteração de recursos sem autorização explícita;
- envio silencioso de tráfego para hosts fora da entrada ou do escopo informado;
- leitura ou alteração indevida de arquivos, banco local ou configuração;
- dados de assinaturas não confiáveis resultando em execução, corrupção ou classificação insegura;
- vulnerabilidades no processo de atualização ou nos artefatos publicados.

Normalmente não são tratados como vulnerabilidade do projeto:

- falsos positivos ou falsos negativos sem impacto de segurança adicional;
- vulnerabilidades encontradas nos domínios examinados pela ferramenta;
- comportamento documentado dos modos `--aggressive`, `--evasion` ou `--check-framing` quando usado com autorização;
- problemas exclusivos de versões sem suporte;
- solicitações de novas assinaturas, provedores ou funcionalidades.

## Divulgação coordenada

Não divulgue publicamente o problema antes de existir uma correção ou antes de uma data acordada com o mantenedor. Depois da correção, o projeto pode publicar um advisory, uma release e os créditos do pesquisador, caso ele concorde.

## Pesquisa de boa-fé

Pesquisas realizadas de boa-fé, dentro desta política e da legislação aplicável, devem:

- usar somente ambientes próprios, locais ou explicitamente autorizados;
- minimizar acesso, alteração, retenção e exposição de dados;
- interromper o teste ao encontrar dados sensíveis ou impacto não previsto;
- não degradar serviços, executar negação de serviço ou testar terceiros;
- conceder tempo razoável para análise e correção.

O mantenedor não pretende tomar medidas contra pesquisas que respeitem essas condições. Esta política não concede autorização para testar infraestrutura de terceiros nem substitui as regras de qualquer programa de segurança.
