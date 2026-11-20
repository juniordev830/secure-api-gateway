# Operação e qualidade — Secure API Gateway

## Escopo existente

Reverse proxy Go com upstream fixo local, autenticação Bearer e limite por IP com capacidade de memória limitada.

## Código e testes

`gateway.go`, `cmd/gateway/main.go`, `gateway_test.go`, `go.mod`.

## Reprodução local

`go test -race ./...`; definir `GATEWAY_TOKEN` forte e `GATEWAY_UPSTREAM` local antes de `go run ./cmd/gateway`.

Ao alterar funcionalidade, registrar no PR os comandos executados e os resultados; não tratar verificações não executadas como aprovadas.

## Cenários a incluir na regressão

- Múltiplos cabeçalhos `Authorization` e rota protegida sem token.
- Carga alta e saturação dos 4.096 buckets, sem crescimento adicional do mapa.
- Reutilização de bucket expirado e limpeza periódica de entradas antigas.
- Cabeçalhos encaminhados, upstream indisponível e IP spoofado.

## Riscos e evolução

O limite de buckets evita crescimento ilimitado de memória, mas pode recusar novos IPs com `429` enquanto o mapa estiver cheio. O rate limiting é em memória e por processo; não substitui proteção distribuída. Antes de produção, revisar timeouts, limites de payload, TLS, confiança no proxy e observabilidade.

### Checklist de entrega

- [ ] Novo comportamento ligado a caso de uso real.
- [ ] Testes e exemplo documentados, quando aplicável.
- [ ] Nenhum segredo ou dado de cliente adicionado.
- [ ] Código revisado em branch, sem merge automático.
