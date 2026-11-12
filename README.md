# Secure API Gateway

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

Escuta somente em `127.0.0.1`. Remove tokens e cookies ao encaminhar pedidos. Descarta valores de `Forwarded`, `X-Real-IP` e `X-Forwarded-*` enviados pelo cliente e reconstrói os cabeçalhos `X-Forwarded-*` com base na conexão recebida, evitando falsificação da origem pelo próprio cliente. Não é gateway público pronto. Se implantado atrás de outro proxy, o IP registrado será o do proxy anterior, não necessariamente o do usuário final. O rate limiting é em memória e não funciona entre múltiplas réplicas.

## Evolução planejada

Adicionar roteamento configurável com allowlist, quotas distribuídas, TLS e observabilidade, antes de implantar em rede.

---
Projeto de Engenharia de Software mantido na conta [juniordev830](https://github.com/juniordev830).

## Verificação antes de contribuir

O [guia de validação](docs/GUIA_DE_VALIDACAO.md) descreve o estado do código, as verificações reproduzíveis e os riscos a observar ao revisar novas alterações.
