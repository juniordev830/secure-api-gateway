# Engenharia reversa e estudo — Secure API Gateway

## Objetivo e fluxo

Proxy HTTP com autenticação e limite de requisições. gateway.go reúne NewHandler e o contador de acesso. cmd/gateway/main.go configura o servidor e delega as decisões de encaminhamento ao handler.

**Tecnologias identificadas** · Go.

**Revisão de referência** · `486d71ba106f`.

## Mapa do código

| Caminho | Papel de leitura | Símbolos selecionados |
| --- | --- | --- |
| [cmd/gateway/main.go](../cmd/gateway/main.go) | Ponto de leitura para entrada ou composição | `newHTTPServer`, `main` |
| [gateway.go](../gateway.go) | Implementação | `allow`, `NewHandler` |

## Configuração e referências

Ambiente e dependências: [go.mod](../go.mod).

Referências existentes: [docs/GUIA_DE_VALIDACAO.md](GUIA_DE_VALIDACAO.md).

## Roteiro de estudo e desenvolvimento

1. Comece pelo fluxo descrito acima e localize seus pontos de entrada no mapa. Acompanhe uma entrada válida até a transformação ou a resposta.
2. Abra um teste relacionado ao fluxo e descreva qual regra ele protege. Compare o tratamento esperado para entradas válidas, inválidas e nos limites.
3. Ao adicionar uma regra, determine qual módulo controla o dado e cubra o caso nesse nível. Em seguida, confira o efeito no comando, na API ou na interface de entrada.

**Pergunta de entrevista**

Onde testaria os limites entre rota pública, rota protegida e upstream local?

## Testes versionados

Arquivos para começar a leitura dos cenários de teste: [cmd/gateway/main_test.go](../cmd/gateway/main_test.go), [gateway_test.go](../gateway_test.go).

Os comandos e versões de runtime usados no CI ficam em [.github/workflows/ci.yml](../.github/workflows/ci.yml).

[Voltar ao README](../README.md).
