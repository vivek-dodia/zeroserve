import { assert, assertEquals } from "@std/assert";
import { join } from "@std/path";
import {
    hasBpfToolchain,
    packSite,
    repoRoot,
    withZeroserve,
} from "./test_utils.ts";

const canRunScripts = await hasBpfToolchain();
const encoder = new TextEncoder();
const decoder = new TextDecoder();

// HMAC-SHA256 helper for test verification
async function hmacSha256(
    key: Uint8Array,
    message: Uint8Array,
): Promise<Uint8Array> {
    const cryptoKey = await crypto.subtle.importKey(
        "raw",
        key.buffer as ArrayBuffer,
        { name: "HMAC", hash: "SHA-256" },
        false,
        ["sign"],
    );
    return new Uint8Array(
        await crypto.subtle.sign(
            "HMAC",
            cryptoKey,
            message.buffer as ArrayBuffer,
        ),
    );
}

// Generate AWS SigV4 signing key
async function generateSigningKey(
    secretKey: string,
    date: string,
    region: string,
    service: string,
): Promise<Uint8Array> {
    const kDate = await hmacSha256(
        encoder.encode("AWS4" + secretKey),
        encoder.encode(date),
    );
    const kRegion = await hmacSha256(kDate, encoder.encode(region));
    const kService = await hmacSha256(kRegion, encoder.encode(service));
    const kSigning = await hmacSha256(kService, encoder.encode("aws4_request"));
    return kSigning;
}

// Calculate SHA256 hex
async function sha256Hex(data: string): Promise<string> {
    const digest = await crypto.subtle.digest("SHA-256", encoder.encode(data));
    return Array.from(new Uint8Array(digest))
        .map((b) => b.toString(16).padStart(2, "0"))
        .join("");
}

// Build canonical request
function buildCanonicalRequest(
    method: string,
    uri: string,
    query: string,
    headers: Record<string, string>,
    bodyHash: string,
): string {
    const sortedHeaders = Object.entries(headers)
        .map(([k, v]) => `${k.toLowerCase()}:${v.trim()}`)
        .sort()
        .join("\n");

    const signedHeaders = Object.keys(headers)
        .map((k) => k.toLowerCase())
        .sort()
        .join(";");

    return `${method.toUpperCase()}\n${uri}\n${query}\n${sortedHeaders}\n\n${signedHeaders}\n${bodyHash}`;
}

// Build string to sign
async function buildStringToSign(
    timestamp: string,
    date: string,
    region: string,
    service: string,
    canonicalRequest: string,
): Promise<string> {
    const canonicalHash = await sha256Hex(canonicalRequest);
    return `AWS4-HMAC-SHA256\n${timestamp}\n${date}/${region}/${service}/aws4_request\n${canonicalHash}`;
}

// Generate expected authorization header
async function generateExpectedAuth(
    method: string,
    uri: string,
    query: string,
    headers: Record<string, string>,
    bodyHash: string,
    timestamp: string,
    date: string,
    region: string,
    service: string,
    accessKey: string,
    secretKey: string,
): Promise<string> {
    const canonicalRequest = buildCanonicalRequest(
        method,
        uri,
        query,
        headers,
        bodyHash,
    );
    const stringToSign = await buildStringToSign(
        timestamp,
        date,
        region,
        service,
        canonicalRequest,
    );
    const signingKey = await generateSigningKey(
        secretKey,
        date,
        region,
        service,
    );
    const signature = await hmacSha256(
        signingKey,
        encoder.encode(stringToSign),
    );
    const signatureHex = Array.from(signature)
        .map((b) => b.toString(16).padStart(2, "0"))
        .join("");

    const signedHeaders = Object.keys(headers)
        .map((k) => k.toLowerCase())
        .sort()
        .join(";");

    return `AWS4-HMAC-SHA256 Credential=${accessKey}/${date}/${region}/${service}/aws4_request, SignedHeaders=${signedHeaders}, Signature=${signatureHex}`;
}

Deno.test({
    name: "e2e: aws sigv4 authorization header generation",
    ignore: !canRunScripts,
    fn: async () => {
        const siteDir = await Deno.makeTempDir();
        let tarPath: string | null = null;
        try {
            await Deno.writeTextFile(
                join(siteDir, "index.html"),
                "aws sigv4 test\n",
            );

            const scriptsDir = join(siteDir, ".zeroserve", "scripts");
            await Deno.mkdir(scriptsDir, { recursive: true });

            // AWS credentials for testing
            const accessKey = "AKIAIOSFODNN7EXAMPLE";
            const secretKey = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY";
            const region = "us-east-1";
            const service = "s3";

            // Script that generates Authorization header for a GET request
            const scriptSource = `#include <zeroserve.h>

ZS_ENTRY
zs_u64 entry(void) {
  char path[64];
  zs_req_path(path, sizeof(path));

  if (zs_strcmp(path, "/aws-sigv4") != 0) {
    return 0;
  }

  // Create headers JSON
  zs_s64 headers = zs_json_new_object();
  zs_s64 host_val = zs_json_parse(ZS_STR("\\"s3.amazonaws.com\\""));
  zs_json_set(headers, ZS_STR("host"), host_val);
  zs_object_free(host_val);

  // Empty body hash
  const char *body_hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

  zs_aws_v4_sign_params p = {
    .access_key = "${accessKey}",
    .access_key_len = ${accessKey.length},
    .secret_key = "${secretKey}",
    .secret_key_len = ${secretKey.length},
    .region = "${region}",
    .region_len = ${region.length},
    .service = "${service}",
    .service_len = ${service.length},
    .method = "GET",
    .method_len = 3,
    .uri = "/my-bucket/test-object",
    .uri_len = 22,
    .headers_json = headers,
    .body_hash = body_hash,
    .body_hash_len = 64,
    .timestamp_ms = 1704067200000, // 2024-01-01T00:00:00Z
    .out = 0,
    .out_len = 0
  };

  // Query required length
  zs_s64 needed = zs_aws_v4_authorization_header(&p, sizeof(p));
  if (needed <= 0) {
    zs_respond(500, ZS_STR("failed to query length\\n"));
    zs_object_free(headers);
    return 0;
  }

  char auth[512];
  p.out = auth;
  p.out_len = sizeof(auth);

  zs_s64 len = zs_aws_v4_authorization_header(&p, sizeof(p));
  zs_object_free(headers);

  if (len <= 0) {
    zs_respond(500, ZS_STR("failed to generate auth header\\n"));
    return 0;
  }

  // Return the authorization header in JSON
  char body[1024];
  char *bp = zs_stpcpy(body, "{\\"authorization\\":\\"");
  zs_memcpy(bp, auth, len);
  bp += len;
  bp = zs_stpcpy(bp, "\\",\\"len\\":");
  bp += zs_utoa10(len, bp, 16);
  bp = zs_stpcpy(bp, "}\\n");

  zs_meta_set(ZS_STR("zs.response.header.content-type"), ZS_STR("application/json"));
  zs_respond(200, body, bp - body);
  return 0;
}
`;

            await Deno.writeTextFile(
                join(scriptsDir, "10-aws-sigv4.c"),
                scriptSource,
            );

            tarPath = await packSite(siteDir);

            await withZeroserve(tarPath, async (baseUrl) => {
                const res = await fetch(`${baseUrl}/aws-sigv4`);
                assertEquals(res.status, 200);
                const payload = (await res.json()) as {
                    authorization: string;
                    len: number;
                };

                // Verify we got an authorization header
                assert(payload.authorization.length > 0);
                assert(payload.authorization.startsWith("AWS4-HMAC-SHA256"));

                // Generate expected signature and verify it matches
                const timestamp = "20240101T000000Z";
                const date = "20240101";
                const headers = { host: "s3.amazonaws.com" };
                const bodyHash =
                    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

                const expectedAuth = await generateExpectedAuth(
                    "GET",
                    "/my-bucket/test-object",
                    "",
                    headers,
                    bodyHash,
                    timestamp,
                    date,
                    region,
                    service,
                    accessKey,
                    secretKey,
                );

                assertEquals(payload.authorization, expectedAuth);
            });
        } finally {
            if (tarPath) {
                await Deno.remove(tarPath).catch(() => {});
            }
            await Deno.remove(siteDir, { recursive: true }).catch(() => {});
        }
    },
});

Deno.test({
    name: "e2e: aws sigv4 with query string",
    ignore: !canRunScripts,
    fn: async () => {
        const siteDir = await Deno.makeTempDir();
        let tarPath: string | null = null;
        try {
            await Deno.writeTextFile(
                join(siteDir, "index.html"),
                "aws sigv4 query test\n",
            );

            const scriptsDir = join(siteDir, ".zeroserve", "scripts");
            await Deno.mkdir(scriptsDir, { recursive: true });

            const accessKey = "AKIAIOSFODNN7EXAMPLE";
            const secretKey = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY";
            const region = "us-east-1";
            const service = "execute-api";

            const scriptSource = `#include <zeroserve.h>

ZS_ENTRY
zs_u64 entry(void) {
  char path[64];
  zs_req_path(path, sizeof(path));

  if (zs_strcmp(path, "/aws-sigv4-query") != 0) {
    return 0;
  }

  zs_s64 headers = zs_json_new_object();
  zs_s64 host_val = zs_json_parse(ZS_STR("\\"api.example.com\\""));
  zs_json_set(headers, ZS_STR("host"), host_val);
  zs_object_free(host_val);

  const char *body_hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

  zs_aws_v4_sign_params p = {
    .access_key = "${accessKey}",
    .access_key_len = ${accessKey.length},
    .secret_key = "${secretKey}",
    .secret_key_len = ${secretKey.length},
    .region = "${region}",
    .region_len = ${region.length},
    .service = "${service}",
    .service_len = ${service.length},
    .method = "POST",
    .method_len = 4,
    .uri = "/v1/data?key=value&foo=bar",
    .uri_len = 26,
    .headers_json = headers,
    .body_hash = body_hash,
    .body_hash_len = 64,
    .timestamp_ms = 1704153600000, // 2024-01-02T00:00:00Z
    .out = 0,
    .out_len = 0
  };

  char auth[512];
  p.out = auth;
  p.out_len = sizeof(auth);

  zs_s64 len = zs_aws_v4_authorization_header(&p, sizeof(p));
  zs_object_free(headers);

  if (len <= 0) {
    zs_respond(500, ZS_STR("failed to generate auth header\\n"));
    return 0;
  }

  char body[1024];
  char *bp = zs_stpcpy(body, "{\\"authorization\\":\\"");
  zs_memcpy(bp, auth, len);
  bp += len;
  bp = zs_stpcpy(bp, "\\"}\\n");

  zs_meta_set(ZS_STR("zs.response.header.content-type"), ZS_STR("application/json"));
  zs_respond(200, body, bp - body);
  return 0;
}
`;

            await Deno.writeTextFile(
                join(scriptsDir, "11-aws-sigv4-query.c"),
                scriptSource,
            );

            tarPath = await packSite(siteDir);

            await withZeroserve(tarPath, async (baseUrl) => {
                const res = await fetch(`${baseUrl}/aws-sigv4-query`);
                assertEquals(res.status, 200);
                const payload = (await res.json()) as {
                    authorization: string;
                };

                assert(payload.authorization.startsWith("AWS4-HMAC-SHA256"));

                // Verify signature with query string
                const timestamp = "20240102T000000Z";
                const date = "20240102";
                const headers = { host: "api.example.com" };
                const bodyHash =
                    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

                const expectedAuth = await generateExpectedAuth(
                    "POST",
                    "/v1/data",
                    "foo=bar&key=value", // sorted query string
                    headers,
                    bodyHash,
                    timestamp,
                    date,
                    region,
                    service,
                    accessKey,
                    secretKey,
                );

                assertEquals(payload.authorization, expectedAuth);
            });
        } finally {
            if (tarPath) {
                await Deno.remove(tarPath).catch(() => {});
            }
            await Deno.remove(siteDir, { recursive: true }).catch(() => {});
        }
    },
});

Deno.test({
    name: "e2e: aws sigv4 presigned url generation",
    ignore: !canRunScripts,
    fn: async () => {
        const siteDir = await Deno.makeTempDir();
        let tarPath: string | null = null;
        try {
            await Deno.writeTextFile(
                join(siteDir, "index.html"),
                "aws sigv4 presigned url test\n",
            );

            const scriptsDir = join(siteDir, ".zeroserve", "scripts");
            await Deno.mkdir(scriptsDir, { recursive: true });

            const accessKey = "AKIAIOSFODNN7EXAMPLE";
            const secretKey = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY";
            const region = "us-east-1";
            const service = "s3";

            const scriptSource = `#include <zeroserve.h>

ZS_ENTRY
zs_u64 entry(void) {
  char path[64];
  zs_req_path(path, sizeof(path));

  if (zs_strcmp(path, "/aws-presigned") != 0) {
    return 0;
  }

  zs_s64 headers = zs_json_new_object();
  zs_s64 host_val = zs_json_parse(ZS_STR("\\"s3.amazonaws.com\\""));
  zs_json_set(headers, ZS_STR("host"), host_val);
  zs_object_free(host_val);

  zs_aws_v4_sign_params p = {
    .access_key = "${accessKey}",
    .access_key_len = ${accessKey.length},
    .secret_key = "${secretKey}",
    .secret_key_len = ${secretKey.length},
    .region = "${region}",
    .region_len = ${region.length},
    .service = "${service}",
    .service_len = ${service.length},
    .method = "GET",
    .method_len = 3,
    .uri = "/my-bucket/test-object?prefix=docs/",
    .uri_len = 35,
    .headers_json = headers,
    .timestamp_ms = 1704067200000, // 2024-01-01T00:00:00Z
    .out = 0,
    .out_len = 0
  };

  char url[1024];
  p.out = url;
  p.out_len = sizeof(url);

  zs_s64 len = zs_aws_v4_presigned_url(&p, sizeof(p), 3600);
  zs_object_free(headers);

  if (len <= 0) {
    zs_respond(500, ZS_STR("failed to generate presigned url\\n"));
    return 0;
  }

  char body[2048];
  char *bp = zs_stpcpy(body, "{\\"url\\":\\"");
  zs_memcpy(bp, url, len);
  bp += len;
  bp = zs_stpcpy(bp, "\\"}\\n");

  zs_meta_set(ZS_STR("zs.response.header.content-type"), ZS_STR("application/json"));
  zs_respond(200, body, bp - body);
  return 0;
}
`;

            await Deno.writeTextFile(
                join(scriptsDir, "12-aws-presigned.c"),
                scriptSource,
            );

            tarPath = await packSite(siteDir);

            await withZeroserve(tarPath, async (baseUrl) => {
                const res = await fetch(`${baseUrl}/aws-presigned`);
                assertEquals(res.status, 200);
                const payload = (await res.json()) as {
                    url: string;
                };

                // Verify URL contains expected components
                assert(payload.url.includes("X-Amz-Algorithm=AWS4-HMAC-SHA256"));
                assert(payload.url.includes("X-Amz-Credential="));
                assert(payload.url.includes("X-Amz-Date=20240101T000000Z"));
                assert(payload.url.includes("X-Amz-Expires=3600"));
                assert(payload.url.includes("X-Amz-SignedHeaders=host"));
                assert(payload.url.includes("X-Amz-Signature="));
                assert(payload.url.includes("prefix=docs%2F"));

                // Verify the path is correct
                assert(payload.url.startsWith("/my-bucket/test-object?"));
            });
        } finally {
            if (tarPath) {
                await Deno.remove(tarPath).catch(() => {});
            }
            await Deno.remove(siteDir, { recursive: true }).catch(() => {});
        }
    },
});
