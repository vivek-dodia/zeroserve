import { assert, assertEquals, assertRejects } from "@std/assert";
import { join } from "@std/path";
import {
    generateSelfSignedCert,
    packSite,
    raceWithTimeout,
    spawnZeroserve,
    withZeroserveTls,
} from "./test_utils.ts";

/**
 * Run `openssl s_client -msg` against a TLS endpoint and return the combined
 * stdout/stderr. With `-msg`, OpenSSL prints every handshake record it sees, so
 * a server-sent `CertificateRequest` (the TLS 1.3 message asking the client for
 * a certificate) shows up verbatim in the output.
 */
async function sClientHandshakeLog(
    hostname: string,
    port: number,
): Promise<string> {
    const child = new Deno.Command("openssl", {
        args: [
            "s_client",
            "-connect",
            `${hostname}:${port}`,
            "-servername",
            "localhost",
            "-tls1_3",
            "-msg",
        ],
        stdin: "piped",
        stdout: "piped",
        stderr: "piped",
    }).spawn();

    // `Q` is s_client's quit command; sending it makes the handshake complete
    // and the client disconnect cleanly instead of hanging on stdin.
    const writer = child.stdin.getWriter();
    await writer.write(new TextEncoder().encode("Q\n"));
    await writer.close();

    const output = await raceWithTimeout(child.output(), 10_000);
    if (output === null) {
        try {
            child.kill("SIGKILL");
        } catch { /* already exited */ }
        await child.status;
        throw new Error("openssl s_client timed out");
    }
    const decoder = new TextDecoder();
    return decoder.decode(output.stdout) + decoder.decode(output.stderr);
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

/**
 * Generate a CA and a leaf client certificate signed by it, for exercising the
 * mTLS (`client_auth`) path. Returns the CA cert (to be trusted by the server's
 * `trusted_ca_cert_file`) and the client cert/key (presented by the client).
 */
async function generateClientCert(): Promise<{
    caPath: string;
    clientCertPath: string;
    clientKeyPath: string;
    cleanup: () => Promise<void>;
}> {
    const dir = await Deno.makeTempDir();
    const caPath = join(dir, "ca.pem");
    const caKeyPath = join(dir, "ca-key.pem");
    const clientCertPath = join(dir, "client.pem");
    const clientKeyPath = join(dir, "client-key.pem");
    const csrPath = join(dir, "client.csr");
    const serialPath = join(dir, "ca.srl");
    const extPath = join(dir, "client.ext");

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
        "/CN=zeroserve-test-client-ca",
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
        clientKeyPath,
        "-out",
        csrPath,
        "-nodes",
        "-subj",
        "/CN=zeroserve-test-client",
    ]);

    // The extensions force an X.509 v3 leaf (rustls/Deno rejects v1) and mark it
    // as a client cert; the runtime verifies its chain against the trusted CA.
    await Deno.writeTextFile(
        extPath,
        [
            "basicConstraints=CA:FALSE",
            "keyUsage=digitalSignature",
            "extendedKeyUsage=clientAuth",
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
        clientCertPath,
        "-days",
        "1",
        "-sha256",
        "-extfile",
        extPath,
    ]);

    return {
        caPath,
        clientCertPath,
        clientKeyPath,
        cleanup: () => Deno.remove(dir, { recursive: true }).catch(() => {}),
    };
}

/**
 * Serve a single `localhost` site over the `--caddy` flow with `client_auth`
 * configured, then run `fn` against the HTTPS origin. The generated eBPF TLS
 * section enforces the client certificate, so this exercises the full
 * request-cert -> deliver-to-script -> verify pipeline at runtime.
 */
async function withCaddyClientAuth(
    mode: string,
    fn: (origin: string, serverCertPem: string, client: {
        caPath: string;
        clientCertPath: string;
        clientKeyPath: string;
    }) => Promise<void>,
): Promise<void> {
    const dir = await Deno.makeTempDir();
    const server = await generateSelfSignedCert();
    const client = await generateClientCert();
    try {
        const caddyfilePath = join(dir, "Caddyfile");
        await Deno.writeTextFile(
            caddyfilePath,
            `{
  admin off
  auto_https off
}

localhost {
  tls ${server.certPath} ${server.keyPath} {
    client_auth {
      mode ${mode}
      trusted_ca_cert_file ${client.caPath}
    }
  }
  respond "ok" 200
}
`,
        );

        const proc = await spawnZeroserve(
            ["--caddy", caddyfilePath, "--expose-filesystem"],
            { tls: true, quiet: true },
        );
        try {
            const serverCertPem = await Deno.readTextFile(server.certPath);
            await fn(
                `https://localhost:${proc.tlsPort}`,
                serverCertPem,
                client,
            );
        } finally {
            await proc.stop();
        }
    } finally {
        await server.cleanup();
        await client.cleanup();
        await Deno.remove(dir, { recursive: true }).catch(() => {});
    }
}

/**
 * Serve a `localhost` HTTPS site over the `--caddy` flow with a TLS certificate
 * but no `client_auth`, then run `fn` against the HTTPS origin. Used to assert
 * the script-selected flow only requests a client certificate when a
 * `client_auth` policy is actually configured.
 */
async function withCaddyTlsNoClientAuth(
    fn: (proc: { tlsPort: number | null }) => Promise<void>,
): Promise<void> {
    const dir = await Deno.makeTempDir();
    const server = await generateSelfSignedCert();
    try {
        const caddyfilePath = join(dir, "Caddyfile");
        await Deno.writeTextFile(
            caddyfilePath,
            `{
  admin off
  auto_https off
}

localhost {
  tls ${server.certPath} ${server.keyPath}
  respond "ok" 200
}
`,
        );

        const proc = await spawnZeroserve(
            ["--caddy", caddyfilePath],
            { tls: true, quiet: true },
        );
        try {
            await fn(proc);
        } finally {
            await proc.stop();
        }
    } finally {
        await server.cleanup();
        await Deno.remove(dir, { recursive: true }).catch(() => {});
    }
}

Deno.test(
    "e2e: client_auth require_and_verify accepts a CA-signed client certificate",
    async () => {
        await withCaddyClientAuth(
            "require_and_verify",
            async (origin, serverCertPem, client) => {
                const httpClient = Deno.createHttpClient({
                    caCerts: [serverCertPem],
                    cert: await Deno.readTextFile(client.clientCertPath),
                    key: await Deno.readTextFile(client.clientKeyPath),
                });
                try {
                    const res = await fetch(`${origin}/`, { client: httpClient });
                    assertEquals(res.status, 200);
                    assertEquals(await res.text(), "ok");
                } finally {
                    httpClient.close();
                }
            },
        );
    },
);

Deno.test(
    "e2e: client_auth require_and_verify rejects a client with no certificate",
    async () => {
        await withCaddyClientAuth(
            "require_and_verify",
            async (origin, serverCertPem) => {
                const httpClient = Deno.createHttpClient({
                    caCerts: [serverCertPem],
                });
                try {
                    // The TLS handshake succeeds (the cert is requested but
                    // optional at the BoringSSL layer); the eBPF client_auth
                    // check then aborts the request, so the connection is closed
                    // without a response and the fetch fails.
                    await assertRejects(() =>
                        fetch(`${origin}/`, { client: httpClient })
                    );
                } finally {
                    httpClient.close();
                }
            },
        );
    },
);

Deno.test(
    "e2e: caddy TLS site without client_auth does not request a client certificate",
    async () => {
        await withCaddyTlsNoClientAuth(async (proc) => {
            assert(proc.tlsPort !== null, "expected a TLS listener");
            const log = await sClientHandshakeLog("localhost", proc.tlsPort);
            assert(
                /Handshake/.test(log),
                `expected a TLS handshake to occur, got:\n${log}`,
            );
            assert(
                !/CertificateRequest/.test(log),
                `caddy server requested a client certificate even though no ` +
                    `client_auth is configured:\n${log}`,
            );
        });
    },
);

Deno.test(
    "e2e: TLS server does not request a client certificate without client_auth",
    async () => {
        const siteDir = await Deno.makeTempDir();
        const cert = await generateSelfSignedCert();
        let tarPath: string | null = null;
        try {
            await Deno.writeTextFile(join(siteDir, "index.html"), "hello\n");
            tarPath = await packSite(siteDir);

            await withZeroserveTls(
                tarPath,
                cert.certPath,
                cert.keyPath,
                async (_httpUrl, httpsUrl) => {
                    const url = new URL(httpsUrl);
                    const log = await sClientHandshakeLog(
                        url.hostname,
                        Number(url.port),
                    );
                    // Sanity check: the handshake actually happened.
                    assert(
                        /Handshake/.test(log),
                        `expected a TLS handshake to occur, got:\n${log}`,
                    );
                    assert(
                        !/CertificateRequest/.test(log),
                        `server requested a client certificate even though no ` +
                            `client_auth is configured:\n${log}`,
                    );
                },
            );
        } finally {
            if (tarPath) {
                await Deno.remove(tarPath).catch(() => {});
            }
            await Deno.remove(siteDir, { recursive: true }).catch(() => {});
            await cert.cleanup();
        }
    },
);
