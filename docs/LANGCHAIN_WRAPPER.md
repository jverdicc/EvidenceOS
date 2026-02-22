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

- `X-Request-Id: <unique-id>` on every request.
- `Authorization: Bearer <token>` when daemon is configured with `--preflight-require-bearer-token`.

Compatibility alias supported by the daemon:

- `X-EvidenceOS-Request-Id: <unique-id>` is accepted as an alias for `X-Request-Id`.
- If both headers are present, the daemon prefers `X-Request-Id`.

Request identity is derived from authentication headers (bearer/HMAC/mTLS fingerprint) and not from request-body metadata.

## Request JSON schema

`POST /v1/preflight_tool_call` body (JSON):

```json
{
  "toolName": "string",
  "params": {"...": "..."},
  "sessionId": "string (optional)",
  "agentId": "string (optional)"
}
```

- `toolName` is required.
- `params` is required and must be a JSON object.
- `sessionId` and `agentId` are optional metadata.

## Response JSON schema

Responses are always camelCase:

```json
{
  "decision": "ALLOW | DOWNGRADE | REQUIRE_HUMAN | DENY",
  "reasonCode": "string",
  "reasonDetail": "string (optional)",
  "rewrittenParams": {"...": "..."},
  "budgetDelta": {
    "spent": 1,
    "remaining": 42
  }
}
```

- `reasonDetail`, `rewrittenParams`, and `budgetDelta` are omitted when not applicable.
- Snake_case keys such as `reason_code` or `detail` are not part of the API contract.

## Request body notes

`agentId` and `sessionId` are treated as untrusted metadata fields only. They may be logged for diagnostics, but they do not establish principal identity.
