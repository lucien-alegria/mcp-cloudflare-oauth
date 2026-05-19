import { createMcpHandler } from "agents/mcp";

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

export interface OAuthMcpOptions {
  /**
   * Full base URL of the worker (e.g. "https://mcp-foo.example.workers.dev").
   * Used for OAuth discovery metadata.
   */
  issuer: string;

  /**
   * Display name of the service shown on the /authorize page
   * (e.g. "Atimeüs", "Jira", "Notion").
   */
  serviceName: string;

  /**
   * URL where users can create/find their API token.
   * Shown as a help link on the /authorize page.
   */
  serviceTokenUrl: string;

  /**
   * Optional description shown on the /authorize page below the title.
   * Defaults to "Paste your {serviceName} API token to authorize Claude."
   */
  authorizeDescription?: string;

  /**
   * Optional language for the /authorize page ("fr" | "en"). Defaults to "en".
   */
  lang?: "fr" | "en";

  /**
   * Build an McpServer instance. Called per-request with the user's resolved
   * API token (or undefined if not authenticated). Register your tools here.
   *
   * Accepts `any` to avoid duplicate-type conflicts when the consumer's
   * @modelcontextprotocol/sdk version differs from the one bundled by `agents`.
   */
  buildServer: (token: string | undefined) => any;
}

export interface OAuthMcpEnv {
  MCP_AUTH_KV: KVNamespace;
  TOKEN_ENCRYPTION_KEY?: string;
  [key: string]: unknown;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function randomToken(bytes = 32): string {
  const buf = new Uint8Array(bytes);
  crypto.getRandomValues(buf);
  return Array.from(buf)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

async function sha256(plain: string): Promise<string> {
  const data = new TextEncoder().encode(plain);
  const hash = await crypto.subtle.digest("SHA-256", data);
  return btoa(String.fromCharCode(...new Uint8Array(hash)))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

function jsonResponse(
  body: unknown,
  status = 200,
  headers: Record<string, string> = {}
): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      "Content-Type": "application/json",
      "Cache-Control": "no-store",
      ...headers,
    },
  });
}

function corsHeaders(): Record<string, string> {
  return {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Access-Control-Allow-Headers":
      "Content-Type, Authorization, MCP-Protocol-Version",
    "Access-Control-Expose-Headers": "WWW-Authenticate",
  };
}

// ---------------------------------------------------------------------------
// Encryption helpers (AES-GCM, stored as "v1:{iv_hex}:{base64_ciphertext}")
// ---------------------------------------------------------------------------

async function importAesKey(hexKey: string): Promise<CryptoKey> {
  const bytes = new Uint8Array(
    hexKey.match(/.{2}/g)!.map((b) => parseInt(b, 16))
  );
  return crypto.subtle.importKey("raw", bytes, "AES-GCM", false, [
    "encrypt",
    "decrypt",
  ]);
}

async function encryptToken(plain: string, hexKey: string): Promise<string> {
  const key = await importAesKey(hexKey);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    key,
    new TextEncoder().encode(plain)
  );
  const ivHex = Array.from(iv)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
  const ctB64 = btoa(String.fromCharCode(...new Uint8Array(ciphertext)));
  return `v1:${ivHex}:${ctB64}`;
}

async function decryptToken(
  stored: string,
  hexKey: string
): Promise<string> {
  if (!stored.startsWith("v1:")) return stored; // legacy plain-text fallback
  const parts = stored.split(":");
  const ivHex = parts[1];
  const ctB64 = parts.slice(2).join(":"); // re-join in case base64 contains ":"
  const key = await importAesKey(hexKey);
  const iv = new Uint8Array(ivHex.match(/.{2}/g)!.map((b) => parseInt(b, 16)));
  const ciphertext = Uint8Array.from(atob(ctB64), (c) => c.charCodeAt(0));
  const plaintext = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv },
    key,
    ciphertext
  );
  return new TextDecoder().decode(plaintext);
}

function escapeHtml(s: string): string {
  return s
    .replace(/&/g, "&amp;")
    .replace(/"/g, "&quot;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");
}

// ---------------------------------------------------------------------------
// i18n
// ---------------------------------------------------------------------------

const i18n = {
  fr: {
    title: (name: string) => `Connecter ${name}`,
    subtitle: (name: string) =>
      `Collez votre token API ${name} pour autoriser Claude.`,
    label: "Token API",
    placeholder: "Collez votre token ici\u2026",
    helpLink: "O\u00f9 trouver mon token\u00a0? \u2197",
    button: "Autoriser",
  },
  en: {
    title: (name: string) => `Connect ${name}`,
    subtitle: (name: string) =>
      `Paste your ${name} API token to authorize Claude.`,
    label: "API Token",
    placeholder: "Paste your token here\u2026",
    helpLink: "Where do I find my token? \u2197",
    button: "Authorize",
  },
};

// ---------------------------------------------------------------------------
// OAuth endpoint handlers
// ---------------------------------------------------------------------------

function handleProtectedResourceMetadata(issuer: string): Response {
  return jsonResponse(
    { resource: `${issuer}/mcp`, authorization_servers: [issuer] },
    200,
    corsHeaders()
  );
}

function handleOAuthMetadata(issuer: string): Response {
  return jsonResponse(
    {
      issuer,
      authorization_endpoint: `${issuer}/authorize`,
      token_endpoint: `${issuer}/token`,
      registration_endpoint: `${issuer}/register`,
      response_types_supported: ["code"],
      grant_types_supported: ["authorization_code", "refresh_token"],
      code_challenge_methods_supported: ["S256"],
      token_endpoint_auth_methods_supported: ["client_secret_post", "none"],
      scopes_supported: [],
    },
    200,
    corsHeaders()
  );
}

async function handleRegister(
  request: Request,
  kv: KVNamespace
): Promise<Response> {
  const body = (await request.json()) as Record<string, unknown>;
  const clientId = randomToken(16);
  const clientInfo = {
    client_id: clientId,
    client_id_issued_at: Math.floor(Date.now() / 1000),
    redirect_uris: body.redirect_uris ?? [],
    grant_types: body.grant_types ?? ["authorization_code"],
    response_types: body.response_types ?? ["code"],
    client_name: body.client_name ?? "MCP Client",
    token_endpoint_auth_method: body.token_endpoint_auth_method ?? "none",
  };

  await kv.put(`client:${clientId}`, JSON.stringify(clientInfo), {
    expirationTtl: 60 * 60 * 24 * 365,
  });

  return jsonResponse(clientInfo, 201, corsHeaders());
}

function handleAuthorize(request: Request, opts: OAuthMcpOptions): Response {
  const url = new URL(request.url);
  const clientId = url.searchParams.get("client_id") ?? "";
  const redirectUri = url.searchParams.get("redirect_uri") ?? "";
  const state = url.searchParams.get("state") ?? "";
  const codeChallenge = url.searchParams.get("code_challenge") ?? "";
  const codeChallengeMethod =
    url.searchParams.get("code_challenge_method") ?? "";
  const scope = url.searchParams.get("scope") ?? "";

  const lang = opts.lang ?? "en";
  const t = i18n[lang];
  const description =
    opts.authorizeDescription ?? t.subtitle(opts.serviceName);

  const html = `<!DOCTYPE html>
<html lang="${lang}">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>${escapeHtml(t.title(opts.serviceName))}</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      background: #f5f5f5;
      display: flex;
      justify-content: center;
      align-items: center;
      min-height: 100vh;
      padding: 1rem;
    }
    .card {
      background: white;
      border-radius: 12px;
      box-shadow: 0 2px 12px rgba(0,0,0,0.1);
      padding: 2.5rem;
      max-width: 460px;
      width: 100%;
    }
    h1 { font-size: 1.4rem; margin-bottom: 0.5rem; color: #111; }
    .subtitle { color: #666; font-size: 0.95rem; margin-bottom: 1.5rem; line-height: 1.4; }
    label { display: block; font-weight: 600; margin-bottom: 0.4rem; font-size: 0.9rem; color: #333; }
    input[type="password"] {
      width: 100%; padding: 0.7rem 0.9rem; border: 1px solid #ddd;
      border-radius: 8px; font-size: 0.95rem; margin-bottom: 0.6rem;
      transition: border-color 0.2s;
    }
    input[type="password"]:focus {
      outline: none; border-color: #4a90d9;
      box-shadow: 0 0 0 3px rgba(74,144,217,0.15);
    }
    .help-link { display: inline-block; margin-bottom: 1.5rem; font-size: 0.85rem; color: #4a90d9; text-decoration: none; }
    .help-link:hover { text-decoration: underline; }
    button {
      width: 100%; padding: 0.75rem; background: #4a90d9; color: white;
      border: none; border-radius: 8px; font-size: 1rem; font-weight: 600;
      cursor: pointer; transition: background 0.2s;
    }
    button:hover { background: #3a7bc8; }
    button:disabled { background: #999; cursor: not-allowed; }
  </style>
</head>
<body>
  <div class="card">
    <h1>${escapeHtml(t.title(opts.serviceName))}</h1>
    <p class="subtitle">${escapeHtml(description)}</p>
    <form method="POST" action="/authorize">
      <input type="hidden" name="client_id" value="${escapeHtml(clientId)}">
      <input type="hidden" name="redirect_uri" value="${escapeHtml(redirectUri)}">
      <input type="hidden" name="state" value="${escapeHtml(state)}">
      <input type="hidden" name="code_challenge" value="${escapeHtml(codeChallenge)}">
      <input type="hidden" name="code_challenge_method" value="${escapeHtml(codeChallengeMethod)}">
      <input type="hidden" name="scope" value="${escapeHtml(scope)}">
      <label for="token">${escapeHtml(t.label)}</label>
      <input type="password" id="token" name="api_token" placeholder="${escapeHtml(t.placeholder)}" required autocomplete="off">
      <a class="help-link" href="${escapeHtml(opts.serviceTokenUrl)}" target="_blank" rel="noopener">${escapeHtml(t.helpLink)}</a>
      <button type="submit">${escapeHtml(t.button)}</button>
    </form>
  </div>
</body>
</html>`;

  return new Response(html, {
    headers: { "Content-Type": "text/html; charset=utf-8" },
  });
}

async function handleAuthorizePost(
  request: Request,
  kv: KVNamespace,
  encryptionKey?: string
): Promise<Response> {
  const form = await request.formData();
  const apiToken = form.get("api_token") as string;
  const clientId = form.get("client_id") as string;
  const redirectUri = form.get("redirect_uri") as string;
  const state = form.get("state") as string;
  const codeChallenge = form.get("code_challenge") as string;
  const codeChallengeMethod = form.get("code_challenge_method") as string;

  if (!apiToken || !redirectUri) {
    return new Response("Missing required fields", { status: 400 });
  }

  const code = randomToken(32);
  const payload = JSON.stringify({
    apiToken,
    codeChallenge,
    codeChallengeMethod,
    clientId,
    redirectUri,
  });

  await kv.put(
    `code:${code}`,
    encryptionKey ? await encryptToken(payload, encryptionKey) : payload,
    { expirationTtl: 300 }
  );

  const redirect = new URL(redirectUri);
  redirect.searchParams.set("code", code);
  if (state) redirect.searchParams.set("state", state);

  return Response.redirect(redirect.toString(), 302);
}

async function handleToken(
  request: Request,
  kv: KVNamespace,
  encryptionKey?: string
): Promise<Response> {
  const body = await request.text();
  const params = new URLSearchParams(body);
  const grantType = params.get("grant_type");

  if (grantType === "authorization_code") {
    return handleTokenAuthCode(params, kv, encryptionKey);
  } else if (grantType === "refresh_token") {
    return handleTokenRefresh(params, kv, encryptionKey);
  }

  return jsonResponse(
    { error: "unsupported_grant_type" },
    400,
    corsHeaders()
  );
}

async function handleTokenAuthCode(
  params: URLSearchParams,
  kv: KVNamespace,
  encryptionKey?: string
): Promise<Response> {
  const code = params.get("code");
  const codeVerifier = params.get("code_verifier");
  const redirectUri = params.get("redirect_uri");

  if (!code || !codeVerifier) {
    return jsonResponse({ error: "invalid_request" }, 400, corsHeaders());
  }

  const stored = await kv.get(`code:${code}`);
  if (!stored) {
    return jsonResponse(
      { error: "invalid_grant", error_description: "Code expired or invalid" },
      400,
      corsHeaders()
    );
  }

  const rawPayload = encryptionKey
    ? await decryptToken(stored, encryptionKey)
    : stored;

  const codeData = JSON.parse(rawPayload) as {
    apiToken: string;
    codeChallenge: string;
    codeChallengeMethod: string;
    clientId: string;
    redirectUri: string;
  };

  await kv.delete(`code:${code}`);

  if (redirectUri && redirectUri !== codeData.redirectUri) {
    return jsonResponse(
      { error: "invalid_grant", error_description: "redirect_uri mismatch" },
      400,
      corsHeaders()
    );
  }

  if (codeData.codeChallengeMethod === "S256") {
    const expectedChallenge = await sha256(codeVerifier);
    if (expectedChallenge !== codeData.codeChallenge) {
      return jsonResponse(
        {
          error: "invalid_grant",
          error_description: "PKCE verification failed",
        },
        400,
        corsHeaders()
      );
    }
  }

  const accessToken = randomToken(32);
  const refreshToken = randomToken(32);
  const tokenToStore = encryptionKey
    ? await encryptToken(codeData.apiToken, encryptionKey)
    : codeData.apiToken;

  await kv.put(`access:${accessToken}`, tokenToStore, {
    expirationTtl: 60 * 60 * 24 * 30, // 30 days
  });

  await kv.put(`refresh:${refreshToken}`, tokenToStore, {
    expirationTtl: 60 * 60 * 24 * 365, // 1 year
  });

  return jsonResponse(
    {
      access_token: accessToken,
      token_type: "Bearer",
      expires_in: 60 * 60 * 24 * 30,
      refresh_token: refreshToken,
    },
    200,
    corsHeaders()
  );
}

async function handleTokenRefresh(
  params: URLSearchParams,
  kv: KVNamespace,
  encryptionKey?: string
): Promise<Response> {
  const refreshToken = params.get("refresh_token");
  if (!refreshToken) {
    return jsonResponse({ error: "invalid_request" }, 400, corsHeaders());
  }

  const storedRefresh = await kv.get(`refresh:${refreshToken}`);
  if (!storedRefresh) {
    return jsonResponse(
      {
        error: "invalid_grant",
        error_description: "Refresh token expired or invalid",
      },
      400,
      corsHeaders()
    );
  }

  const apiToken = encryptionKey
    ? await decryptToken(storedRefresh, encryptionKey)
    : storedRefresh;

  const accessToken = randomToken(32);
  const tokenToStore = encryptionKey
    ? await encryptToken(apiToken, encryptionKey)
    : apiToken;

  await kv.put(`access:${accessToken}`, tokenToStore, {
    expirationTtl: 60 * 60 * 24 * 30,
  });

  return jsonResponse(
    {
      access_token: accessToken,
      token_type: "Bearer",
      expires_in: 60 * 60 * 24 * 30,
      refresh_token: refreshToken,
    },
    200,
    corsHeaders()
  );
}

// ---------------------------------------------------------------------------
// Main export
// ---------------------------------------------------------------------------

/**
 * Creates a Cloudflare Workers fetch handler that wraps an MCP server with
 * a full OAuth 2.1 authorization flow. Users authenticate by pasting their
 * API token on a hosted /authorize page — no shared secrets needed.
 *
 * Usage:
 * ```ts
 * import { createOAuthMcpWorker } from "mcp-cloudflare-oauth";
 *
 * export default createOAuthMcpWorker({
 *   issuer: "https://mcp-foo.example.workers.dev",
 *   serviceName: "Foo",
 *   serviceTokenUrl: "https://foo.app/settings/tokens",
 *   buildServer: (token) => {
 *     const server = new McpServer({ name: "mcp-foo", version: "1.0.0" });
 *     server.tool("my_tool", "Description", {}, async () => {
 *       // use `token` to call the Foo API
 *     });
 *     return server;
 *   },
 * });
 * ```
 */
export function createOAuthMcpWorker(opts: OAuthMcpOptions): {
  fetch: (
    request: Request,
    env: OAuthMcpEnv,
    ctx: ExecutionContext
  ) => Promise<Response>;
} {
  return {
    async fetch(
      request: Request,
      env: OAuthMcpEnv,
      ctx: ExecutionContext
    ): Promise<Response> {
      const url = new URL(request.url);
      const { pathname } = url;

      // CORS preflight
      if (request.method === "OPTIONS") {
        return new Response(null, { status: 204, headers: corsHeaders() });
      }

      // OAuth discovery
      if (pathname === "/.well-known/oauth-protected-resource") {
        return handleProtectedResourceMetadata(opts.issuer);
      }
      if (pathname === "/.well-known/oauth-authorization-server") {
        return handleOAuthMetadata(opts.issuer);
      }

      // OAuth endpoints
      if (pathname === "/register" && request.method === "POST") {
        return handleRegister(request, env.MCP_AUTH_KV);
      }
      if (pathname === "/authorize" && request.method === "GET") {
        return handleAuthorize(request, opts);
      }
      if (pathname === "/authorize" && request.method === "POST") {
        return handleAuthorizePost(request, env.MCP_AUTH_KV, env.TOKEN_ENCRYPTION_KEY);
      }
      if (pathname === "/token" && request.method === "POST") {
        return handleToken(request, env.MCP_AUTH_KV, env.TOKEN_ENCRYPTION_KEY);
      }

      // MCP endpoint (Claude web connector sends traffic to "/" instead of "/mcp")
      if (pathname === "/mcp" || pathname === "/") {
        let token: string | undefined;
        const authHeader = request.headers.get("Authorization");
        if (authHeader?.startsWith("Bearer ")) {
          const accessToken = authHeader.slice(7);
          const stored = await env.MCP_AUTH_KV.get(`access:${accessToken}`);
          if (stored) {
            token = env.TOKEN_ENCRYPTION_KEY
              ? await decryptToken(stored, env.TOKEN_ENCRYPTION_KEY)
              : stored;
          }
        }

        // No valid token — tell Claude.ai to start the OAuth flow
        if (!token) {
          return new Response(null, {
            status: 401,
            headers: {
              "WWW-Authenticate": `Bearer realm="${opts.issuer}", resource_metadata="${opts.issuer}/.well-known/oauth-protected-resource"`,
              ...corsHeaders(),
            },
          });
        }

        const server = opts.buildServer(token);
        // Cast needed: `agents` bundles its own @modelcontextprotocol/sdk types
        // Use route: "" to disable the agents handler's built-in path check —
        // we already matched the pathname ourselves above.
        const handler = createMcpHandler(server as any, { route: "" } as any);
        return handler(request, env, ctx);
      }

      return new Response("Not found", { status: 404 });
    },
  };
}
