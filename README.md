# Secure API Gateway

Gateway HTTP em Go com proxy reverso para um **upstream local e fixo**, token obrigatório e limite simples de 60 requisições/minuto por IP. A rota `/health` é pública e `/api/*` exige `Authorization: Bearer TOKEN`.

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

Escuta somente em `127.0.0.1`. Remove tokens, cookies e cabeçalhos de encaminhamento recebidos do cliente; define o `Host` esperado do upstream e deixa o proxy gerar o `X-Forwarded-For` a partir do endereço remoto real. Não é gateway público pronto. O rate limiting é em memória e não funciona entre múltiplas réplicas.

## Evolução planejada

Adicionar roteamento configurável com allowlist, quotas distribuídas, TLS e observabilidade, antes de implantar em rede.

---
Projeto de Engenharia de Software mantido na conta [juniordev830](https://github.com/juniordev830).
