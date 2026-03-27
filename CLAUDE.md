# CLAUDE.md

## Project overview

Reusable OAuth 2.1 provider for MCP servers deployed on Cloudflare Workers. Wraps any API-key-based service into a per-user OAuth flow compatible with Claude.ai's native "Authorize" button. Extracted from `mcp-atimeus` to avoid duplicating auth boilerplate across integrations.

## Architecture

- **Single export**: `createOAuthMcpWorker(opts)` — returns a Cloudflare Workers `fetch` handler
- **Runtime**: Cloudflare Workers (TypeScript), consumed via Wrangler `[alias]` from sibling projects
- **Dependencies**: `agents` (Cloudflare's MCP handler), `@modelcontextprotocol/sdk` (peer dep)
- **Storage**: expects a KV namespace bound as `MCP_AUTH_KV`

## Key decisions

- **Not published to npm** — consumed via Wrangler `[alias]` pointing to the source file (`../mcp-oauth-provider/src/index.ts`). Avoids publish/version overhead while the API stabilizes.
- **`buildServer` accepts `any` return type** — works around duplicate `McpServer` type conflicts between the consumer's `@modelcontextprotocol/sdk` and the copy bundled inside `agents`. Runtime types are identical; only TS declarations conflict.
- **`@modelcontextprotocol/sdk` is a peer dep** — prevents duplicate installs and the type conflicts above.
- **Per-request server instantiation** — `buildServer` is called on every `/mcp` request. Workers are stateless; reusing a single `McpServer` causes "already connected" errors.
- **401 required for unauthenticated `/mcp` requests** — the server must return `401 Unauthorized` with a `WWW-Authenticate: Bearer realm="...", resource_metadata="..."` header when no valid token is present. Without this, Claude.ai receives 200 and never triggers the OAuth flow — users silently skip the token prompt. This was a real bug found in production.
- **PKCE (S256) required** — verified on token exchange per the MCP spec.
- **Token TTLs**: access tokens 30 days, refresh tokens 1 year, auth codes 5 minutes, client registrations 1 year.
- **i18n**: authorize page supports `"en"` and `"fr"`.
- **Form field name is `api_token`** (generic), not service-specific.

## How consumers use it

```toml
# wrangler.toml
[alias]
"mcp-cloudflare-oauth" = "../mcp-oauth-provider/src/index.ts"
```

```ts
import { createOAuthMcpWorker } from "mcp-cloudflare-oauth";

export default createOAuthMcpWorker({
  issuer: "https://mcp-foo.example.workers.dev",
  serviceName: "Foo",
  serviceTokenUrl: "https://foo.app/settings/tokens",
  buildServer(token) { /* register tools, return McpServer */ },
});
```

## Endpoints provided

| Path | Method | Purpose |
|------|--------|---------|
| `/.well-known/oauth-protected-resource` | GET | RFC 9728 resource metadata |
| `/.well-known/oauth-authorization-server` | GET | RFC 8414 OAuth metadata |
| `/register` | POST | Dynamic client registration (RFC 7591) |
| `/authorize` | GET | HTML form to paste API token |
| `/authorize` | POST | Process form, issue auth code, redirect |
| `/token` | POST | Exchange code/refresh token for access token |
| `/mcp` | POST | MCP Streamable HTTP (delegated to consumer's server) |

## KV key patterns

- `client:{clientId}` — registered OAuth client info (1 year TTL)
- `code:{code}` — authorization code → API token + PKCE data (5 min TTL)
- `access:{token}` — access token → API token (30 day TTL)
- `refresh:{token}` — refresh token → API token (1 year TTL)

## Commands

- `npm run typecheck` — TypeScript type checking

## Current consumers

- [`mcp-atimeus`](https://github.com/lucien-alegria/mcp-atimeus) — Atimeüs payment schedule data
