# mcp-cloudflare-oauth

OAuth 2.1 provider for MCP servers on Cloudflare Workers. Wraps any API-key-based service into a per-user OAuth flow compatible with Claude.ai's "Authorize" button.

## What it does

When building a remote MCP server for Claude.ai, you often need each user to authenticate with their own API key for a third-party service. This package provides the full OAuth 2.1 layer so you only write the MCP tools — no auth boilerplate.

The flow for end users:
1. Add the MCP server URL in Claude
2. Click "Authorize" — redirected to a branded form
3. Paste their API token
4. Done — Claude stores the OAuth token automatically

## Usage

```ts
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { createOAuthMcpWorker } from "mcp-cloudflare-oauth";
import { z } from "zod";

export default createOAuthMcpWorker({
  issuer: "https://mcp-foo.example.workers.dev",
  serviceName: "Foo",
  serviceTokenUrl: "https://foo.app/settings/tokens",
  lang: "en", // or "fr"

  buildServer(token) {
    const server = new McpServer({ name: "mcp-foo", version: "1.0.0" });

    server.tool("my_tool", "Does something", {
      query: z.string().describe("Search query"),
    }, async ({ query }) => {
      const res = await fetch("https://api.foo.app/search", {
        headers: { "X-Auth-Token": token! },
      });
      return { content: [{ type: "text", text: await res.text() }] };
    });

    return server;
  },
});
```

## Options

| Option | Type | Required | Description |
|--------|------|----------|-------------|
| `issuer` | string | Yes | Full base URL of your worker |
| `serviceName` | string | Yes | Display name on the authorize page |
| `serviceTokenUrl` | string | Yes | URL where users create/find their API token |
| `authorizeDescription` | string | No | Custom description on the authorize page |
| `lang` | `"en"` \| `"fr"` | No | Language for the authorize page (default: `"en"`) |
| `buildServer` | function | Yes | Receives the user's API token, returns an `McpServer` |

## What you get

- OAuth 2.1 discovery endpoints (`/.well-known/*`)
- Dynamic client registration (`/register`)
- Branded `/authorize` page with token input form
- PKCE (S256) verification
- Token exchange and refresh (`/token`)
- KV-backed storage (access tokens: 30 days, refresh tokens: 1 year)
- CORS headers
- Per-request `McpServer` instantiation (avoids "already connected" errors)

## Requirements

- Cloudflare Workers with a KV namespace bound as `MCP_AUTH_KV`
- `@modelcontextprotocol/sdk` and `agents` as peer dependencies

### wrangler.toml

```toml
name = "mcp-foo"
main = "src/index.ts"
compatibility_date = "2025-03-14"
compatibility_flags = ["nodejs_compat"]

[alias]
"mcp-cloudflare-oauth" = "../mcp-oauth-provider/src/index.ts"

[[kv_namespaces]]
binding = "MCP_AUTH_KV"
id = "your-kv-namespace-id"
```

## KV key patterns

| Key | Value | TTL |
|-----|-------|-----|
| `client:{id}` | Registered OAuth client info | 1 year |
| `code:{code}` | Auth code + PKCE data + API token | 5 min |
| `access:{token}` | User's API token | 30 days |
| `refresh:{token}` | User's API token | 1 year |
