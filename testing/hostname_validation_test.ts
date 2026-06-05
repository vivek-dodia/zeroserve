import { assertEquals } from "@std/assert";
import { join } from "@std/path";
import { packSite, withZeroserve, withZeroserveTls, getZeroservePath } from "./test_utils.ts";
import * as http2 from "node:http2";
import { Buffer } from "node:buffer";

// Simple HTTP/1.1 request using raw TCP since Deno's fetch overrides the Host header
async function http1Request(
    hostname: string,
    port: number,
    path: string,
    hostHeader: string,
): Promise<{ status: number; body: string }> {
    const conn = await Deno.connect({ hostname, port });
    conn.setKeepAlive(false);

    try {
        const request =
            `GET ${path} HTTP/1.1\r\nHost: ${hostHeader}\r\nConnection: close\r\n\r\n`;
        await conn.write(new TextEncoder().encode(request));

        // Read with timeout
        const chunks: Uint8Array[] = [];
        const buf = new Uint8Array(4096);
        const timeout = 5000; // 5 second timeout
        const start = Date.now();

        while (Date.now() - start < timeout) {
            try {
                conn.setNoDelay(true);
                const n = await Promise.race([
                    conn.read(buf),
                    new Promise<null>((_, reject) =>
                        setTimeout(() => reject(new Error("timeout")), 1000)
                    ),
                ]);
                if (n === null) break;
                chunks.push(buf.slice(0, n as number));
            } catch (e) {
                if ((e as Error).message === "timeout") break;
                throw e;
            }
        }

        const totalLen = chunks.reduce((sum, c) => sum + c.length, 0);
        const response = new Uint8Array(totalLen);
        let offset = 0;
        for (const chunk of chunks) {
            response.set(chunk, offset);
            offset += chunk.length;
        }

        const text = new TextDecoder().decode(response);
        const headerEnd = text.indexOf("\r\n\r\n");
        if (headerEnd === -1) {
            return { status: 0, body: "" };
        }

        const headerSection = text.slice(0, headerEnd);
        const body = text.slice(headerEnd + 4);

        const statusMatch = headerSection.match(/HTTP\/1\.1 (\d+)/);
        const status = statusMatch ? parseInt(statusMatch[1], 10) : 0;

        return { status, body };
    } finally {
        conn.close();
    }
}

function h2cRequestWithHost(
    hostname: string,
    port: number,
    path: string,
    hostHeader: string,
): Promise<{ status: number; body: string }> {
    return new Promise((resolve, reject) => {
        // Connect to the actual server IP, but set :authority to the desired host
        const client = http2.connect(`http://${hostname}:${port}`);

        client.on("error", (err) => {
            client.close();
            reject(err);
        });

        const req = client.request({
            ":path": path,
            ":method": "GET",
            ":authority": hostHeader,
        });

        let status = 0;
        const chunks: Buffer[] = [];

        req.on("response", (hdrs) => {
            status = hdrs[":status"] as number;
        });

        req.on("data", (chunk: Buffer) => {
            chunks.push(chunk);
        });

        req.on("end", () => {
            client.close();
            const body = Buffer.concat(chunks).toString("utf-8");
            resolve({ status, body });
        });

        req.on("error", (err) => {
            client.close();
            reject(err);
        });

        req.end();
    });
}

async function h2TlsRequestsWithAuthorities(
    hostname: string,
    port: number,
    caPath: string,
    requests: { path: string; authority: string }[],
    serverName = hostname,
): Promise<{ status: number; body: string }[]> {
    const script = `
const http2 = require("node:http2");
const fs = require("node:fs");
const [hostname, port, caPath, serverName, requestsJson] = process.argv.slice(1);
const requests = JSON.parse(requestsJson);
const client = http2.connect(\`https://\${hostname}:\${port}\`, {
  ca: fs.readFileSync(caPath),
  rejectUnauthorized: true,
  servername: serverName,
});
const results = [];
let completed = 0;
let done = false;
function fail(err) {
  if (done) return;
  done = true;
  client.close();
  console.error(err && err.stack ? err.stack : String(err));
  process.exit(1);
}
client.on("error", fail);
for (let i = 0; i < requests.length; i++) {
  const item = requests[i];
  const req = client.request({
    ":path": item.path,
    ":method": "GET",
    ":authority": item.authority,
  });
  let status = 0;
  const chunks = [];
  req.on("response", (hdrs) => {
    status = hdrs[":status"];
  });
  req.on("data", (chunk) => chunks.push(chunk));
  req.on("error", fail);
  req.on("end", () => {
    results[i] = {
      status,
      body: Buffer.concat(chunks).toString("utf-8"),
    };
    completed++;
    if (completed === requests.length && !done) {
      done = true;
      client.close();
      console.log(JSON.stringify(results));
    }
  });
  req.end();
}
`;
    const output = await new Deno.Command("node", {
        args: [
            "-e",
            script,
            hostname,
            String(port),
            caPath,
            serverName,
            JSON.stringify(requests),
        ],
        stdout: "piped",
        stderr: "piped",
    }).output();
    if (!output.success) {
        throw new Error(new TextDecoder().decode(output.stderr));
    }
    return JSON.parse(new TextDecoder().decode(output.stdout));
}

async function generateCaSignedLocalhostCert(): Promise<{
    caPath: string;
    certPath: string;
    keyPath: string;
    cleanup: () => Promise<void>;
}> {
    const dir = await Deno.makeTempDir();
    const caPath = join(dir, "ca.pem");
    const caKeyPath = join(dir, "ca-key.pem");
    const certPath = join(dir, "certificate.pem");
    const keyPath = join(dir, "key.pem");
    const csrPath = join(dir, "leaf.csr");
    const serialPath = join(dir, "ca.srl");
    const extPath = join(dir, "leaf.ext");

    await runOpenSsl([
        "req",
        "-x509",
        "-newkey",
        "rsa:2048",
        "-keyout",
        caKeyPath,
        "-out",
        caPath,
        "-days",
        "1",
        "-nodes",
        "-subj",
        "/CN=zeroserve-test-ca",
        "-addext",
        "basicConstraints=critical,CA:TRUE",
        "-addext",
        "keyUsage=critical,keyCertSign,cRLSign",
    ]);

    await runOpenSsl([
        "req",
        "-newkey",
        "rsa:2048",
        "-keyout",
        keyPath,
        "-out",
        csrPath,
        "-nodes",
        "-subj",
        "/CN=localhost",
    ]);

    await Deno.writeTextFile(
        extPath,
        [
            "basicConstraints=CA:FALSE",
            "keyUsage=digitalSignature,keyEncipherment",
            "extendedKeyUsage=serverAuth",
            "subjectAltName=DNS:localhost,IP:127.0.0.1",
            "",
        ].join("\n"),
    );

    await runOpenSsl([
        "x509",
        "-req",
        "-in",
        csrPath,
        "-CA",
        caPath,
        "-CAkey",
        caKeyPath,
        "-CAserial",
        serialPath,
        "-CAcreateserial",
        "-out",
        certPath,
        "-days",
        "1",
        "-sha256",
        "-extfile",
        extPath,
    ]);

    return {
        caPath,
        certPath,
        keyPath,
        cleanup: async () => {
            await Deno.remove(dir, { recursive: true }).catch(() => {});
        },
    };
}

async function runOpenSsl(args: string[]): Promise<void> {
    const output = await new Deno.Command("openssl", {
        args,
        stdout: "null",
        stderr: "piped",
    }).output();
    if (!output.success) {
        throw new Error(new TextDecoder().decode(output.stderr));
    }
}

async function withZeroserveHostnames(
    tarPath: string,
    hostnames: string[],
    fn: (baseUrl: string) => Promise<void>,
): Promise<void> {
    const zeroservePath = await getZeroservePath();
    const port = await getFreePort();
    const child = new Deno.Command(zeroservePath, {
        args: [
            "--addr",
            `127.0.0.1:${port}`,
            "--disable-request-logging",
            "--validate-hostnames",
            hostnames.join(","),
            tarPath,
        ],
        cwd: repoRoot,
        stdin: "null",
        stdout: "null",
        stderr: "inherit",
    }).spawn();
    const statusPromise = child.status;
    try {
        await waitForServer("127.0.0.1", port, statusPromise);
        await fn(`http://127.0.0.1:${port}`);
    } finally {
        await stopProcess(child, statusPromise);
    }
}

async function getFreePort(): Promise<number> {
    const listener = Deno.listen({ hostname: "127.0.0.1", port: 0 });
    const port = (listener.addr as Deno.NetAddr).port;
    listener.close();
    return port;
}

async function waitForServer(
    hostname: string,
    port: number,
    statusPromise: Promise<Deno.CommandStatus>,
    timeoutMs = 10_000,
): Promise<void> {
    const deadline = Date.now() + timeoutMs;
    while (Date.now() < deadline) {
        const exited = await checkExited(statusPromise);
        if (exited) {
            throw new Error(
                `zeroserve exited early with code ${exited.code}`,
            );
        }
        try {
            const conn = await Deno.connect({ hostname, port });
            conn.close();
            return;
        } catch {
            await delay(100);
        }
    }
    throw new Error(`timed out waiting for zeroserve at ${hostname}:${port}`);
}

async function stopProcess(
    child: Deno.ChildProcess,
    statusPromise: Promise<Deno.CommandStatus>,
): Promise<void> {
    try {
        child.kill("SIGTERM");
    } catch {
        return;
    }

    const status = await raceWithTimeout(statusPromise, 1000);
    if (status) {
        return;
    }

    try {
        child.kill("SIGKILL");
    } catch {
        return;
    }
    await statusPromise;
}

async function checkExited(
    statusPromise: Promise<Deno.CommandStatus>,
): Promise<Deno.CommandStatus | null> {
    const exited = await Promise.race([
        statusPromise,
        immediate(),
    ]);
    return exited ?? null;
}

function delay(ms: number): Promise<void> {
    return new Promise((resolve) => setTimeout(resolve, ms));
}

function immediate(): Promise<null> {
    return new Promise((resolve) => queueMicrotask(() => resolve(null)));
}

async function raceWithTimeout<T>(
    promise: Promise<T>,
    timeoutMs: number,
): Promise<T | null> {
    let timer: number | null = null;
    try {
        return await Promise.race([
            promise,
            new Promise<null>((resolve) => {
                timer = setTimeout(() => resolve(null), timeoutMs);
            }),
        ]);
    } finally {
        if (timer !== null) {
            clearTimeout(timer);
        }
    }
}

import { fromFileUrl } from "@std/path";
const repoRoot = fromFileUrl(new URL("..", import.meta.url));

Deno.test("e2e: HTTP/1 hostname validation allows matching hostname", async () => {
    const siteDir = await Deno.makeTempDir();
    let tarPath: string | null = null;
    try {
        await Deno.writeTextFile(
            join(siteDir, "index.html"),
            "<h1>hello</h1>\n",
        );

        tarPath = await packSite(siteDir);

        await withZeroserveHostnames(tarPath, ["example.com", "test.local"], async (baseUrl) => {
            const url = new URL(baseUrl);
            const hostname = url.hostname;
            const port = Number(url.port);

            // Request with matching Host header should succeed
            const res = await http1Request(hostname, port, "/", "example.com");
            assertEquals(res.status, 200);
            assertEquals(res.body, "<h1>hello</h1>\n");

            // Request with another matching Host header should succeed
            const res2 = await http1Request(hostname, port, "/", "test.local");
            assertEquals(res2.status, 200);
            assertEquals(res2.body, "<h1>hello</h1>\n");
        });
    } finally {
        if (tarPath) {
            await Deno.remove(tarPath).catch(() => {});
        }
        await Deno.remove(siteDir, { recursive: true }).catch(() => {});
    }
});

Deno.test("e2e: HTTP/1 hostname validation rejects non-matching hostname with 421", async () => {
    const siteDir = await Deno.makeTempDir();
    let tarPath: string | null = null;
    try {
        await Deno.writeTextFile(
            join(siteDir, "index.html"),
            "<h1>hello</h1>\n",
        );

        tarPath = await packSite(siteDir);

        await withZeroserveHostnames(tarPath, ["example.com"], async (baseUrl) => {
            const url = new URL(baseUrl);
            const hostname = url.hostname;
            const port = Number(url.port);

            // Request with non-matching Host header should return 421
            const res = await http1Request(hostname, port, "/", "evil.com");
            assertEquals(res.status, 421);
            assertEquals(res.body, "Misdirected Request");
        });
    } finally {
        if (tarPath) {
            await Deno.remove(tarPath).catch(() => {});
        }
        await Deno.remove(siteDir, { recursive: true }).catch(() => {});
    }
});

Deno.test("e2e: HTTP/1 hostname validation is case-insensitive", async () => {
    const siteDir = await Deno.makeTempDir();
    let tarPath: string | null = null;
    try {
        await Deno.writeTextFile(
            join(siteDir, "index.html"),
            "<h1>hello</h1>\n",
        );

        tarPath = await packSite(siteDir);

        await withZeroserveHostnames(tarPath, ["Example.COM"], async (baseUrl) => {
            const url = new URL(baseUrl);
            const hostname = url.hostname;
            const port = Number(url.port);

            // Request with different case should match
            const res = await http1Request(hostname, port, "/", "example.com");
            assertEquals(res.status, 200);

            const res2 = await http1Request(hostname, port, "/", "EXAMPLE.COM");
            assertEquals(res2.status, 200);
        });
    } finally {
        if (tarPath) {
            await Deno.remove(tarPath).catch(() => {});
        }
        await Deno.remove(siteDir, { recursive: true }).catch(() => {});
    }
});

Deno.test("e2e: HTTP/1 hostname validation strips port", async () => {
    const siteDir = await Deno.makeTempDir();
    let tarPath: string | null = null;
    try {
        await Deno.writeTextFile(
            join(siteDir, "index.html"),
            "<h1>hello</h1>\n",
        );

        tarPath = await packSite(siteDir);

        await withZeroserveHostnames(tarPath, ["example.com"], async (baseUrl) => {
            const url = new URL(baseUrl);
            const hostname = url.hostname;
            const port = Number(url.port);

            // Request with port should match hostname without port
            const res = await http1Request(hostname, port, "/", "example.com:8080");
            assertEquals(res.status, 200);
        });
    } finally {
        if (tarPath) {
            await Deno.remove(tarPath).catch(() => {});
        }
        await Deno.remove(siteDir, { recursive: true }).catch(() => {});
    }
});

Deno.test("e2e: h2c hostname validation rejects non-matching hostname with 421", async () => {
    const siteDir = await Deno.makeTempDir();
    let tarPath: string | null = null;
    try {
        await Deno.writeTextFile(
            join(siteDir, "index.html"),
            "<h1>h2c hello</h1>\n",
        );

        tarPath = await packSite(siteDir);

        await withZeroserveHostnames(tarPath, ["example.com"], async (baseUrl) => {
            const url = new URL(baseUrl);
            const hostname = url.hostname;
            const port = Number(url.port);

            // h2c request with non-matching :authority should return 421
            const res = await h2cRequestWithHost(hostname, port, "/", "evil.com");
            assertEquals(res.status, 421);
            assertEquals(res.body, "Misdirected Request");
        });
    } finally {
        if (tarPath) {
            await Deno.remove(tarPath).catch(() => {});
        }
        await Deno.remove(siteDir, { recursive: true }).catch(() => {});
    }
});

Deno.test("e2e: h2 TLS rejects authority that differs from SNI", async () => {
    const siteDir = await Deno.makeTempDir();
    let tarPath: string | null = null;
    const cert = await generateCaSignedLocalhostCert();
    try {
        await Deno.writeTextFile(
            join(siteDir, "index.html"),
            "<h1>h2 sni hello</h1>\n",
        );

        tarPath = await packSite(siteDir);

        await withZeroserveTls(
            tarPath,
            cert.certPath,
            cert.keyPath,
            async (_httpUrl, httpsUrl) => {
                const url = new URL(httpsUrl);
                const results = await h2TlsRequestsWithAuthorities(
                    url.hostname,
                    Number(url.port),
                    cert.caPath,
                    [
                        { path: "/", authority: "localhost" },
                        { path: "/", authority: "evil.com" },
                    ],
                    "localhost",
                );

                assertEquals(results[0].status, 200);
                assertEquals(results[0].body, "<h1>h2 sni hello</h1>\n");
                assertEquals(results[1].status, 421);
                assertEquals(results[1].body, "Misdirected Request");
            },
        );
    } finally {
        await cert.cleanup();
        if (tarPath) {
            await Deno.remove(tarPath).catch(() => {});
        }
        await Deno.remove(siteDir, { recursive: true }).catch(() => {});
    }
});

Deno.test("e2e: HTTP/1 hostname validation handles IPv6 with port", async () => {
    const siteDir = await Deno.makeTempDir();
    let tarPath: string | null = null;
    try {
        await Deno.writeTextFile(
            join(siteDir, "index.html"),
            "<h1>hello</h1>\n",
        );

        tarPath = await packSite(siteDir);

        await withZeroserveHostnames(tarPath, ["::1"], async (baseUrl) => {
            const url = new URL(baseUrl);
            const hostname = url.hostname;
            const port = Number(url.port);

            // IPv6 with port [::1]:port should match ::1
            const res = await http1Request(hostname, port, "/", "[::1]:8080");
            assertEquals(res.status, 200);
        });
    } finally {
        if (tarPath) {
            await Deno.remove(tarPath).catch(() => {});
        }
        await Deno.remove(siteDir, { recursive: true }).catch(() => {});
    }
});

Deno.test("e2e: HTTP/1 hostname validation handles IPv6 without port", async () => {
    const siteDir = await Deno.makeTempDir();
    let tarPath: string | null = null;
    try {
        await Deno.writeTextFile(
            join(siteDir, "index.html"),
            "<h1>hello</h1>\n",
        );

        tarPath = await packSite(siteDir);

        await withZeroserveHostnames(tarPath, ["::1"], async (baseUrl) => {
            const url = new URL(baseUrl);
            const hostname = url.hostname;
            const port = Number(url.port);

            // IPv6 without port [::1] should match ::1
            const res = await http1Request(hostname, port, "/", "[::1]");
            assertEquals(res.status, 200);
        });
    } finally {
        if (tarPath) {
            await Deno.remove(tarPath).catch(() => {});
        }
        await Deno.remove(siteDir, { recursive: true }).catch(() => {});
    }
});

Deno.test("e2e: HTTP/1 hostname validation rejects non-matching IPv6", async () => {
    const siteDir = await Deno.makeTempDir();
    let tarPath: string | null = null;
    try {
        await Deno.writeTextFile(
            join(siteDir, "index.html"),
            "<h1>hello</h1>\n",
        );

        tarPath = await packSite(siteDir);

        await withZeroserveHostnames(tarPath, ["::1"], async (baseUrl) => {
            const url = new URL(baseUrl);
            const hostname = url.hostname;
            const port = Number(url.port);

            // Different IPv6 should be rejected
            const res = await http1Request(hostname, port, "/", "[2001:db8::1]");
            assertEquals(res.status, 421);
        });
    } finally {
        if (tarPath) {
            await Deno.remove(tarPath).catch(() => {});
        }
        await Deno.remove(siteDir, { recursive: true }).catch(() => {});
    }
});

// Note: h2c acceptance tests (matching hostname, case-insensitivity, port stripping)
// are covered by HTTP/1 tests. The h2c rejection test above verifies that HTTP/2
// hostname validation is active. Node's http2 client has stricter :authority
// validation that makes acceptance tests difficult without proper DNS/TLS setup.

Deno.test("e2e: server without hostname validation accepts any host", async () => {
    const siteDir = await Deno.makeTempDir();
    let tarPath: string | null = null;
    try {
        await Deno.writeTextFile(
            join(siteDir, "index.html"),
            "<h1>hello</h1>\n",
        );

        tarPath = await packSite(siteDir);

        // Use regular withZeroserve which doesn't specify --validate-hostnames
        await withZeroserve(tarPath, async (baseUrl) => {
            const url = new URL(baseUrl);
            const hostname = url.hostname;
            const port = Number(url.port);

            // Request with any Host header should succeed
            const res = await http1Request(hostname, port, "/", "any-host.com");
            assertEquals(res.status, 200);
            assertEquals(res.body, "<h1>hello</h1>\n");

            const res2 = await http1Request(hostname, port, "/", "another-host.org");
            assertEquals(res2.status, 200);
            assertEquals(res2.body, "<h1>hello</h1>\n");
        });
    } finally {
        if (tarPath) {
            await Deno.remove(tarPath).catch(() => {});
        }
        await Deno.remove(siteDir, { recursive: true }).catch(() => {});
    }
});
