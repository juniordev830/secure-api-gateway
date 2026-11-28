# Secure API Gateway

**Navegação** · [Estado](#estado) · [Como executar](#como-executar) · [Testes](#testes) · [Código e estudo](docs/ENGENHARIA_REVERSA.md)

Gateway HTTP em Go com proxy reverso para um **upstream local e fixo**, token obrigatório e limite simples de 60 requisições/minuto por IP. A rota `/health` é pública e `/api/*` exige exatamente um cabeçalho `Authorization: Bearer TOKEN`; requisições com múltiplos valores de autorização são rejeitadas.

## Estado

**MVP funcional / projeto inicial de portfólio.** Implementa o núcleo descrito abaixo, mas não é produto pronto para produção.

## Como executar

```bash
export GATEWAY_TOKEN="$(python -c 'import secrets;print(secrets.token_urlsafe(40))')"
export GATEWAY_UPSTREAM=http://127.0.0.1:9000
go run ./cmd/gateway
```

## Testes

```bash
go test -race ./...
```

O GitHub Actions executa os testes automaticamente em pushes e pull requests.

## Segurança e limitações

Escuta somente em `127.0.0.1`. Remove tokens e cookies ao encaminhar pedidos. Descarta `Forwarded`, `X-Real-IP` e todos os `X-Forwarded-*` enviados pelo cliente, inclusive campos não padronizados de identidade e roteamento; recria apenas `X-Forwarded-For`, `X-Forwarded-Host` e `X-Forwarded-Proto` com dados da conexão. O upstream não deve usar cabeçalhos de identidade não autenticados como substitutos de autorização.

O limitador mantém no máximo **4.096 buckets por processo**. Novos endereços recebem `429` quando esse limite está cheio; entradas expiradas são removidas em uma rotina de limpeza periódica (intervalo de 30 segundos), e a janela individual é reiniciada após um minuto. Esse comportamento evita crescimento ilimitado do mapa, mas é deliberadamente *fail-closed*: em um pico com muitas origens distintas, novos clientes podem ser temporariamente recusados. O rate limiting permanece em memória, por processo, e não coordena múltiplas réplicas.

Não é gateway público pronto. Se implantado atrás de outro proxy, o IP registrado será o do proxy anterior, não necessariamente o do usuário final.

## Evolução planejada

Adicionar roteamento configurável com allowlist, quotas distribuídas, TLS e observabilidade, antes de implantar em rede.

---

Projeto de Engenharia de Software mantido na conta [juniordev830](https://github.com/juniordev830).

## Verificação antes de contribuir

O [guia de validação](docs/GUIA_DE_VALIDACAO.md) descreve o estado do código, as verificações reproduzíveis e os riscos a observar ao revisar novas alterações.

O token de gateway deve ter de 32 a 4.096 caracteres, sem espaços nas extremidades nem controles. O proxy verifica integralmente o corpo antes de enviá-lo ao upstream: mesmo em requisições chunked ou sem `Content-Length`, um corpo acima de 1 MiB recebe HTTP 413 sem envio parcial ao serviço local.

## Código e roteiro de estudo

Onde testaria os limites entre rota pública, rota protegida e upstream local? O [guia de engenharia reversa](docs/ENGENHARIA_REVERSA.md) reúne o mapa dos módulos e uma pergunta técnica baseada no projeto.
