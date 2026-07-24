// Headless end-to-end proof of the whole chain (no browser, only Node's native fetch). For each user it:
//   1. identifies as the demo CIMD client — the client_id IS a URL; the authorization server fetches
//      the Client ID Metadata Document behind it and validates it (no registration step, nothing stored),
//   2. runs the scopeless auth-code + PKCE flow, federating the login to Keycloak (login + consent),
//   3. exchanges the code for an ES256 access token and prints the role-derived scopes,
//   4. calls the MCP server's tools and asserts the allow/deny matrix.
//
// Run: npm test   (or: npx tsx e2e.ts)   — needs `mise run demo` (or infra + both services) running.
//
//   alice (realm role: user ) → whoami, list_notes, create_note  ✓   purge_notes ✗
//   bob   (realm role: admin) → whoami, list_notes, create_note, purge_notes  ✓

import crypto from "node:crypto";

const AS = "http://localhost:9000";
const MCP = "http://localhost:9200";
// The client's identity IS this URL (CIMD): the authorization server dereferences it at authorization
// time and validates the document behind it (served by nginx behind Traefik — see support/cimd-client/).
const CLIENT_ID = "http://localhost/cimd-client/client.json";
const REDIRECT = "http://localhost:6274/oauth/callback"; // listed in the document's redirect_uris; nothing listens here — redirects are intercepted

// ── tiny per-host cookie jar ────────────────────────────────────────────────
const jar: Record<string, Record<string, string>> = {};
const hostOf = (u: string): string => new URL(u).host;

function store(url: string, res: Response): void {
  const h = (jar[hostOf(url)] ??= {});
  for (const c of res.headers.getSetCookie?.() ?? []) {
    const pair = c.split(";")[0];
    const i = pair.indexOf("=");
    if (i > 0) h[pair.slice(0, i).trim()] = pair.slice(i + 1).trim();
  }
}

const cookieHeader = (url: string): string =>
  Object.entries(jar[hostOf(url)] || {})
    .map(([k, v]) => `${k}=${v}`)
    .join("; ");

async function raw(url: string, opts: RequestInit = {}): Promise<Response> {
  const headers: Record<string, string> = {...((opts.headers as Record<string, string>) || {})};
  const ck = cookieHeader(url);
  if (ck) headers.cookie = ck;
  const res = await fetch(url, {...opts, headers, redirect: "manual"});
  store(url, res);
  return res;
}

type Step = { redirectedTo: string | null; res: Response; finalUrl: string };

// Follow 3xx redirects manually, stopping at a non-redirect response OR at the client's redirect_uri.
async function follow(url: string, opts: RequestInit = {}): Promise<Step> {
  let res = await raw(url, opts);
  let current = url;
  for (let i = 0; i < 15 && res.status >= 300 && res.status < 400; i++) {
    const loc = res.headers.get("location")!;
    const next = new URL(loc, current).toString();
    if (next.startsWith(REDIRECT)) return {redirectedTo: next, res, finalUrl: current};
    current = next;
    res = await raw(next);
  }
  return {redirectedTo: null, res, finalUrl: current};
}

// ── helpers ─────────────────────────────────────────────────────────────────
const b64url = (buf: Buffer): string =>
  buf.toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");

function formAction(html: string, baseUrl: string): string {
  const m = html.match(/<form[^>]*\saction="([^"]+)"/i);
  if (!m) throw new Error("no <form action> found in page");
  return new URL(m[1].replace(/&amp;/g, "&"), baseUrl).toString();
}

function hiddenInputs(html: string): Record<string, string> {
  const out: Record<string, string> = {};
  for (const tag of html.match(/<input[^>]*type="hidden"[^>]*>/gi) || []) {
    const n = tag.match(/\sname="([^"]+)"/i);
    const v = tag.match(/\svalue="([^"]*)"/i);
    if (n) out[n[1]] = v ? v[1].replace(/&amp;/g, "&") : "";
  }
  return out;
}

function decodeScopes(accessToken: string): string[] {
  const payload = JSON.parse(Buffer.from(accessToken.split(".")[1], "base64url").toString());
  const s = payload.scope ?? payload.scp ?? [];
  return Array.isArray(s) ? [...s].sort() : String(s).split(/\s+/).filter(Boolean).sort();
}

// Read a Streamable-HTTP response. It may be plain JSON, or an SSE stream the server keeps open —
// so for SSE we read incrementally and return the first JSON-RPC message for our id, then cancel.
async function readJsonRpc(res: Response, wantId: number | null): Promise<any> {
  const ct = res.headers.get("content-type") || "";
  if (ct.includes("application/json")) {
    const t = await res.text();
    return t ? JSON.parse(t) : null;
  }
  if (!ct.includes("text/event-stream") || !res.body) {
    try {
      await res.text();
    } catch {
      /* ignore */
    }
    return null;
  }
  const reader = res.body.getReader();
  const dec = new TextDecoder();
  let buf = "";
  try {
    for (; ;) {
      const {value, done} = await reader.read();
      if (done) break;
      buf += dec.decode(value, {stream: true});
      let idx: number;
      while ((idx = buf.indexOf("\n\n")) >= 0) {
        const evt = buf.slice(0, idx);
        buf = buf.slice(idx + 2);
        const data = evt
          .split("\n")
          .filter((l) => l.startsWith("data:"))
          .map((l) => l.slice(5).trim())
          .join("");
        if (!data) continue;
        let obj: any;
        try {
          obj = JSON.parse(data);
        } catch {
          continue;
        }
        if (wantId == null || obj.id === wantId || obj.error) return obj;
      }
    }
  } finally {
    try {
      await reader.cancel();
    } catch {
      /* ignore */
    }
  }
  return null;
}

// ── CIMD preflight ──────────────────────────────────────────────────────────
// The metadata document must be reachable and self-consistent before its URL is used as a
// client_id — this fails with a clearer message than the authorization server's invalid_client.
async function assertCimdDocumentServed(): Promise<void> {
  const res = await fetch(CLIENT_ID);
  if (!res.ok) {
    throw new Error(`CIMD document not served: GET ${CLIENT_ID} → ${res.status} (infra down? try: mise run infra:up)`);
  }
  const doc = (await res.json()) as { client_id?: string; client_name?: string; redirect_uris?: string[] };
  if (doc.client_id !== CLIENT_ID) {
    throw new Error(`CIMD document client_id must equal its own URL: got ${doc.client_id}, expected ${CLIENT_ID}`);
  }
  if (!doc.redirect_uris?.includes(REDIRECT)) {
    throw new Error(`CIMD document does not list the e2e redirect_uri ${REDIRECT}`);
  }
  console.log(`CIMD client "${doc.client_name}" — URL client_id: ${CLIENT_ID}`);
}

// ── OAuth flow for one user ───────────────────────────────────────────────────

async function getToken(user: string, pass: string): Promise<string> {
  Object.keys(jar).forEach((k) => delete jar[k]); // fresh session per user

  const verifier = b64url(crypto.randomBytes(48));
  const challenge = b64url(crypto.createHash("sha256").update(verifier).digest());

  // No registration step: the URL client_id goes straight into the authorization request; the
  // authorization server fetches + validates the metadata document on first sight (then caches it).
  const authorize =
    `${AS}/oauth2/authorize?response_type=code&client_id=${encodeURIComponent(CLIENT_ID)}` +
    `&redirect_uri=${encodeURIComponent(REDIRECT)}&state=e2e&resource=${encodeURIComponent(MCP + "/mcp")}` +
    `&code_challenge=${challenge}&code_challenge_method=S256`;

  // 1. authorize → (AS redirects to Keycloak) → Keycloak login page
  let step = await follow(authorize);
  if (step.redirectedTo) throw new Error("unexpected early redirect to callback (already authenticated?)");
  let html = await step.res.text();

  // 2. POST the Keycloak login form
  const loginAction = formAction(html, step.finalUrl);
  step = await follow(loginAction, {
    method: "POST",
    headers: {"content-type": "application/x-www-form-urlencoded"},
    body: new URLSearchParams({username: user, password: pass, credentialId: ""}).toString(),
  });

  // 3. Keycloak consent page (consentRequired on the keycloak client) → accept it
  if (!step.redirectedTo) {
    html = await step.res.text();
    const fields = hiddenInputs(html);
    fields.accept = "Yes";
    step = await follow(formAction(html, step.finalUrl), {
      method: "POST",
      headers: {"content-type": "application/x-www-form-urlencoded"},
      body: new URLSearchParams(fields).toString(),
    });
  }

  if (!step.redirectedTo) {
    throw new Error(`did not reach redirect_uri; last status ${step.res.status}: ${(await step.res.text()).slice(0, 300)}`);
  }
  const code = new URL(step.redirectedTo).searchParams.get("code");
  if (!code) throw new Error(`no authorization code in ${step.redirectedTo}`);

  // 4. exchange the code (PKCE, public client)
  const tokenRes = await fetch(`${AS}/oauth2/token`, {
    method: "POST",
    headers: {"content-type": "application/x-www-form-urlencoded"},
    body: new URLSearchParams({
      grant_type: "authorization_code",
      code,
      redirect_uri: REDIRECT,
      client_id: CLIENT_ID,
      code_verifier: verifier,
    }).toString(),
  });
  if (!tokenRes.ok) throw new Error(`token exchange failed: ${tokenRes.status} ${await tokenRes.text()}`);
  return ((await tokenRes.json()) as { access_token: string }).access_token;
}

// ── MCP calls (Streamable HTTP / JSON-RPC) ─────────────────────────────────────
let rpcId = 0;

type McpResult = { res: Response; sessionId: string | null; body: any };

async function mcp(token: string, method: string, params: unknown, sessionId?: string | null): Promise<McpResult> {
  const headers: Record<string, string> = {
    authorization: `Bearer ${token}`,
    "content-type": "application/json",
    accept: "application/json, text/event-stream",
  };
  if (sessionId) headers["mcp-session-id"] = sessionId;
  const isNotification = method.startsWith("notifications/");
  const id = ++rpcId;
  const payload = isNotification ? {jsonrpc: "2.0", method, params} : {jsonrpc: "2.0", id, method, params};

  const ac = new AbortController();
  const timer = setTimeout(() => ac.abort(), 20000);
  try {
    const res = await fetch(`${MCP}/mcp`, {
      method: "POST",
      headers,
      body: JSON.stringify(payload),
      signal: ac.signal,
    });
    const sid = res.headers.get("mcp-session-id") || sessionId || null;
    let body: any = null;
    if (isNotification) {
      try {
        await res.text();
      } catch {
        /* 202, no body */
      }
    } else {
      body = await readJsonRpc(res, id);
    }
    return {res, sessionId: sid, body};
  } finally {
    clearTimeout(timer);
  }
}

type ToolOutcome = { allowed: boolean; detail?: string; result?: any };

async function callTool(token: string, sessionId: string, name: string, args: unknown = {}): Promise<ToolOutcome> {
  const r = await mcp(token, "tools/call", {name, arguments: args}, sessionId);
  if (r.body?.error) return {allowed: false, detail: r.body.error.message};
  if (r.body?.result?.isError) {
    const text = (r.body.result.content || []).map((c: any) => c.text).join(" ");
    return {allowed: false, detail: text};
  }
  return {allowed: true, result: r.body?.result};
}

// Pull the tool's JSON payload out of a successful result (structuredContent, or the text content block).
function toolPayload(outcome: ToolOutcome): any {
  const result = outcome.result;
  if (!result) return null;
  if (result.structuredContent) return result.structuredContent;
  const text = (result.content || []).map((c: any) => c.text).filter(Boolean).join("");
  try {
    return text ? JSON.parse(text) : null;
  } catch {
    return null;
  }
}

async function runUser(user: string, pass: string, expectAdmin: boolean): Promise<void> {
  const label = `${user} (${expectAdmin ? "admin" : "user"})`;
  const token = await getToken(user, pass);
  console.log(`\n=== ${label} ===`);
  console.log(`  token scopes: [${decodeScopes(token).join(", ")}]`);

  const init = await mcp(token, "initialize", {
    protocolVersion: "2025-11-25",
    capabilities: {},
    clientInfo: {name: "e2e", version: "1"},
  });
  const session = init.sessionId;
  if (!session) throw new Error(`no Mcp-Session-Id from initialize (status ${init.res.status})`);
  await mcp(token, "notifications/initialized", {}, session);

  const results: Record<string, ToolOutcome> = {
    whoami: await callTool(token, session, "whoami"),
    list_notes: await callTool(token, session, "list_notes"),
    create_note: await callTool(token, session, "create_note", {text: `hello from ${user}`}),
    purge_notes: await callTool(token, session, "purge_notes"),
  };
  for (const [tool, r] of Object.entries(results))
    console.log(`  ${r.allowed ? "✓ ALLOW" : "✗ DENY "} ${tool}${r.allowed ? "" : `  (${r.detail})`}`);

  const expected: Record<string, boolean> = {
    whoami: true,
    list_notes: true,
    create_note: true,
    purge_notes: expectAdmin,
  };
  const failures = Object.entries(expected).filter(([t, exp]) => results[t].allowed !== exp);
  if (failures.length) {
    throw new Error(
      `matrix mismatch for ${label}: ${failures.map(([t, e]) => `${t} expected ${e ? "ALLOW" : "DENY"}`).join(", ")}`,
    );
  }

  // The headline is that the human identity flows end-to-end — assert it, don't just trust the allow/deny
  // matrix. whoami must echo the Keycloak identity and create_note must be authored by the user (not the
  // bare subject UUID). This is the regression guard for the token's identity-claim propagation.
  const who = toolPayload(results.whoami);
  const note = toolPayload(results.create_note);
  console.log(`  identity: username=${who?.username} email=${who?.email} note.author=${note?.author}`);
  const idChecks: Array<[string, unknown, unknown]> = [
    ["whoami.username", who?.username, user],
    ["whoami.email", who?.email, `${user}@example.com`],
    ["create_note.author", note?.author, user],
  ];
  const idFailures = idChecks.filter(([, actual, expect]) => actual !== expect);
  if (idFailures.length) {
    throw new Error(
      `identity not propagated for ${label}: ` +
      idFailures.map(([f, a, e]) => `${f}=${JSON.stringify(a)} (expected ${JSON.stringify(e)})`).join("; "),
    );
  }
  console.log(`  PASS: ${label}`);
}

async function main(): Promise<void> {
  await assertCimdDocumentServed();
  await runUser("alice", "alice", false);
  await runUser("bob", "bob", true);
  console.log("\nALL E2E CHECKS PASSED ✅");
}

main().catch((e: unknown) => {
  console.error(`\nE2E FAILED ❌  ${e instanceof Error ? e.message : String(e)}`);
  process.exit(1);
});
