# LangChain preflight wrapper configuration

Use the daemon's HTTP preflight endpoint when integrating a LangChain (or equivalent) tool wrapper.

## Endpoint

- Path: `/v1/preflight_tool_call`
- URL: `http://<preflight_http_listen>/v1/preflight_tool_call`
- Example with daemon flag `--preflight-http-listen 127.0.0.1:9465`:
  - `http://127.0.0.1:9465/v1/preflight_tool_call`

`--listen` (default `127.0.0.1:50051`) is the gRPC listener and is **not** the HTTP preflight endpoint.

## Required headers

The wrapper must set:

- `Authorization: Bearer <token>` (when daemon is configured with `--preflight-require-bearer-token`)
- `X-Request-Id: <unique-id>` on every request

Request identity is derived from authentication headers (bearer/HMAC/mTLS fingerprint) and not from request-body metadata.

## Request body notes

`agentId` and `sessionId` are treated as untrusted metadata fields only. They may be logged for diagnostics, but they do not establish principal identity.
