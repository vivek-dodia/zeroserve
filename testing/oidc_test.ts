import { assert, assertEquals, assertStringIncludes } from "@std/assert";
import { join } from "@std/path";
import {
    getZeroservePath,
    hasBpfToolchain,
    packSite,
    repoRoot,
} from "./test_utils.ts";

const canRunScripts = await hasBpfToolchain();

const CLIENT_ID = "test-client-id";
const CLIENT_SECRET = "test-client-secret";
const COOKIE_SECRET = "test-cookie-secret-stable-1234";

function b64url(input: string): string {
    return btoa(input).replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
}

async function getFreePort(): Promise<number> {
    const l = Deno.listen({ port: 0 });
    const port = (l.addr as Deno.NetAddr).port;
    l.close();
    return port;
}

// A minimal OIDC provider: /authorize 302s back to the redirect_uri with a code,
// /token returns an unsigned-but-claims-valid id_token echoing the saved nonce.
function startMockIdp(): { origin: string; stop: () => Promise<void> } {
    const codeToNonce = new Map<string, string>();
    const server = Deno.serve({ port: 0, onListen() {} }, async (req) => {
        const url = new URL(req.url);
        if (url.pathname === "/authorize") {
            const state = url.searchParams.get("state") ?? "";
            const nonce = url.searchParams.get("nonce") ?? "";
            const redirect = url.searchParams.get("redirect_uri") ?? "";
            const code = `code-${crypto.randomUUID()}`;
            codeToNonce.set(code, nonce);
            const loc = `${redirect}?code=${encodeURIComponent(code)}&state=${
                encodeURIComponent(state)
            }`;
            return new Response(null, { status: 302, headers: { Location: loc } });
        }
        if (url.pathname === "/token" && req.method === "POST") {
            const form = new URLSearchParams(await req.text());
            const code = form.get("code") ?? "";
            const nonce = codeToNonce.get(code) ?? "";
            const claims = {
                sub: "user-1",
                email: "user@example.com",
                aud: CLIENT_ID,
                exp: Math.floor(Date.now() / 1000) + 3600,
                nonce,
            };
            const idToken = `eyJhbGciOiJub25lIn0.${b64url(JSON.stringify(claims))}.`;
            return Response.json({
                access_token: "access-token",
                token_type: "Bearer",
                id_token: idToken,
            });
        }
        return new Response("not found", { status: 404 });
    });
    const addr = server.addr as Deno.NetAddr;
    return {
        origin: `http://127.0.0.1:${addr.port}`,
        stop: () => server.shutdown(),
    };
}

// Tiny cookie jar keyed by cookie name (good enough for one host).
class CookieJar {
    private jar = new Map<string, string>();
    absorb(resp: Response) {
        for (const sc of resp.headers.getSetCookie()) {
            const [pair, ...attrs] = sc.split(";");
            const eq = pair.indexOf("=");
            if (eq < 0) continue;
            const name = pair.slice(0, eq).trim();
            const value = pair.slice(eq + 1).trim();
            const cleared = attrs.some((a) => {
                const t = a.trim().toLowerCase();
                return t === "max-age=0" || t.startsWith("expires=thu, 01 jan 1970");
            });
            if (cleared || value === "") this.jar.delete(name);
            else this.jar.set(name, value);
        }
    }
    header(): string {
        return [...this.jar.entries()].map(([k, v]) => `${k}=${v}`).join("; ");
    }
    has(name: string): boolean {
        return this.jar.has(name);
    }
    get(name: string): string | undefined {
        return this.jar.get(name);
    }
}

async function waitForServer(base: string): Promise<void> {
    const deadline = Date.now() + 10_000;
    while (Date.now() < deadline) {
        try {
            const r = await fetch(base, { redirect: "manual" });
            await r.body?.cancel();
            return;
        } catch {
            await new Promise((res) => setTimeout(res, 50));
        }
    }
    throw new Error("zeroserve did not start in time");
}

Deno.test({
    name: "e2e: OIDC Authorization Code + PKCE login flow",
    ignore: !canRunScripts,
    fn: async () => {
        const idp = startMockIdp();
        const zsPort = await getFreePort();
        const zsBase = `http://127.0.0.1:${zsPort}`;
        const redirectUri = `${zsBase}/callback`;

        const siteDir = await Deno.makeTempDir();
        let child: Deno.ChildProcess | undefined;
        try {
            const scriptsDir = join(siteDir, ".zeroserve", "scripts");
            await Deno.mkdir(scriptsDir, { recursive: true });
            await Deno.writeTextFile(join(siteDir, "index.html"), "home");

            const cfgJson = JSON.stringify({
                authorization_endpoint: `${idp.origin}/authorize`,
                token_endpoint: `${idp.origin}/token`,
                client_id: CLIENT_ID,
                client_secret: CLIENT_SECRET,
                redirect_uri: redirectUri,
                cookie_secret: COOKIE_SECRET,
            }).replaceAll("\\", "\\\\").replaceAll('"', '\\"');
            const script = `#include <zeroserve.h>

ZS_ENTRY
zs_u64 entry(void) {
    zs_s64 cfg = zs_json_parse(ZS_STR("${cfgJson}"));
    if (cfg < 0) { zs_respond(500, ZS_STR("config error")); return 0; }

    char path[256];
    zs_req_path(path, sizeof(path));

    if (zs_memcmp(path, "/callback", 9) == 0) {
        zs_oidc_handle_callback(cfg);
        return 0;
    }
    if (zs_memcmp(path, "/logout", 7) == 0) {
        zs_oidc_logout(cfg, ZS_STR(""));
        return 0;
    }

    zs_s64 session = zs_oidc_session_verify(cfg);
    if (session <= 0) {
        char uri[512];
        zs_req_uri(uri, sizeof(uri));
        zs_oidc_begin_login(cfg, ZS_STR(uri));
        return 0;
    }
    zs_object_free(session);
    zs_respond(200, ZS_STR("welcome"));
    return 0;
}
`;
            await Deno.writeTextFile(join(scriptsDir, "10-oidc.c"), script);

            const tarPath = await packSite(siteDir);
            try {
                const zeroservePath = await getZeroservePath();
                child = new Deno.Command(zeroservePath, {
                    args: [
                        "--addr",
                        `127.0.0.1:${zsPort}`,
                        "--disable-request-logging",
                        tarPath,
                    ],
                    cwd: repoRoot,
                    stdin: "null",
                    stdout: "null",
                    stderr: "inherit",
                }).spawn();
                await waitForServer(zsBase);

                const jar = new CookieJar();

                // 1. Unauthenticated request -> 302 to the IdP authorize endpoint.
                const start = await fetch(`${zsBase}/`, { redirect: "manual" });
                jar.absorb(start);
                assertEquals(start.status, 302, "initial request should redirect to IdP");
                const authorizeUrl = start.headers.get("location") ?? "";
                assertStringIncludes(authorizeUrl, `${idp.origin}/authorize`);
                assertStringIncludes(authorizeUrl, "code_challenge=");
                assertStringIncludes(authorizeUrl, "code_challenge_method=S256");
                assertStringIncludes(authorizeUrl, "state=");
                assert(jar.has("__zs_oidc_state"), "state cookie should be set");
                await start.body?.cancel();

                // 2. Follow to the IdP, which redirects back to /callback with a code.
                const authorized = await fetch(authorizeUrl, { redirect: "manual" });
                assertEquals(authorized.status, 302);
                const callbackUrl = authorized.headers.get("location") ?? "";
                assertStringIncludes(callbackUrl, `${zsBase}/callback`);
                assertStringIncludes(callbackUrl, "code=");
                await authorized.body?.cancel();

                // 3. Hit the callback (with the state cookie) -> session cookie + redirect.
                const callback = await fetch(callbackUrl, {
                    redirect: "manual",
                    headers: { cookie: jar.header() },
                });
                jar.absorb(callback);
                assertEquals(callback.status, 302, "callback should redirect post-login");
                assert(jar.has("__zs_oidc_session"), "session cookie should be set");
                assert(!jar.has("__zs_oidc_state"), "state cookie should be cleared");
                await callback.body?.cancel();

                // 4. Authenticated request now succeeds.
                const authed = await fetch(`${zsBase}/`, {
                    headers: { cookie: jar.header() },
                });
                assertEquals(authed.status, 200);
                assertEquals(await authed.text(), "welcome");

                // 5. Logout clears the session cookie.
                const loggedOut = await fetch(`${zsBase}/logout`, {
                    redirect: "manual",
                    headers: { cookie: jar.header() },
                });
                jar.absorb(loggedOut);
                assertEquals(loggedOut.status, 200);
                assert(!jar.has("__zs_oidc_session"), "session cookie should be cleared on logout");
                await loggedOut.body?.cancel();

                // 6. With no session cookie we are redirected to login again.
                const afterLogout = await fetch(`${zsBase}/`, {
                    redirect: "manual",
                    headers: { cookie: jar.header() },
                });
                assertEquals(afterLogout.status, 302);
                await afterLogout.body?.cancel();
            } finally {
                await Deno.remove(tarPath).catch(() => {});
            }
        } finally {
            if (child) {
                try {
                    child.kill("SIGTERM");
                } catch { /* already exited */ }
                await child.status;
            }
            await idp.stop();
            await Deno.remove(siteDir, { recursive: true }).catch(() => {});
        }
    },
});

Deno.test({
    name: "e2e: OIDC callback rejects a tampered/missing state",
    ignore: !canRunScripts,
    fn: async () => {
        const idp = startMockIdp();
        const zsPort = await getFreePort();
        const zsBase = `http://127.0.0.1:${zsPort}`;

        const siteDir = await Deno.makeTempDir();
        let child: Deno.ChildProcess | undefined;
        try {
            const scriptsDir = join(siteDir, ".zeroserve", "scripts");
            await Deno.mkdir(scriptsDir, { recursive: true });
            const cfgJson = JSON.stringify({
                authorization_endpoint: `${idp.origin}/authorize`,
                token_endpoint: `${idp.origin}/token`,
                client_id: CLIENT_ID,
                client_secret: CLIENT_SECRET,
                redirect_uri: `${zsBase}/callback`,
                cookie_secret: COOKIE_SECRET,
            }).replaceAll("\\", "\\\\").replaceAll('"', '\\"');
            const script = `#include <zeroserve.h>
ZS_ENTRY
zs_u64 entry(void) {
    zs_s64 cfg = zs_json_parse(ZS_STR("${cfgJson}"));
    if (cfg < 0) { zs_respond(500, ZS_STR("config error")); return 0; }
    zs_oidc_handle_callback(cfg);
    return 0;
}
`;
            await Deno.writeTextFile(join(scriptsDir, "10-oidc.c"), script);
            const tarPath = await packSite(siteDir);
            try {
                const zeroservePath = await getZeroservePath();
                child = new Deno.Command(zeroservePath, {
                    args: ["--addr", `127.0.0.1:${zsPort}`, "--disable-request-logging", tarPath],
                    cwd: repoRoot,
                    stdin: "null",
                    stdout: "null",
                    stderr: "inherit",
                }).spawn();
                await waitForServer(zsBase);

                // No state cookie at all -> 400.
                const noState = await fetch(`${zsBase}/callback?code=abc&state=xyz`, {
                    redirect: "manual",
                });
                assertEquals(noState.status, 400);
                await noState.body?.cancel();
            } finally {
                await Deno.remove(tarPath).catch(() => {});
            }
        } finally {
            if (child) {
                try {
                    child.kill("SIGTERM");
                } catch { /* already exited */ }
                await child.status;
            }
            await idp.stop();
            await Deno.remove(siteDir, { recursive: true }).catch(() => {});
        }
    },
});
