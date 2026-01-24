import { assertEquals } from "@std/assert";
import { join } from "@std/path";
import {
    generateSelfSignedCert,
    hasBpfToolchain,
    packSite,
    withZeroserveTls,
} from "./test_utils.ts";
import * as http2 from "node:http2";
import { Buffer } from "node:buffer";

const canRunScripts = await hasBpfToolchain();
const encoder = new TextEncoder();
const decoder = new TextDecoder();

// HTTP/2 cleartext POST request helper
function h2cPostRequest(
    hostname: string,
    port: number,
    path: string,
    body: string,
    contentType = "application/json",
): Promise<{ status: number; headers: Record<string, string>; body: string }> {
    return new Promise((resolve, reject) => {
        const client = http2.connect(`http://${hostname}:${port}`);

        client.on("error", (err) => {
            client.close();
            reject(err);
        });

        const req = client.request({
            ":path": path,
            ":method": "POST",
            "content-type": contentType,
        });

        let status = 0;
        let headers: Record<string, string> = {};
        const chunks: Buffer[] = [];

        req.on("response", (hdrs) => {
            status = hdrs[":status"] as number;
            for (const [key, value] of Object.entries(hdrs)) {
                if (!key.startsWith(":")) {
                    headers[key] = Array.isArray(value) ? value[0] : (value as string);
                }
            }
        });

        req.on("data", (chunk: Buffer) => {
            chunks.push(chunk);
        });

        req.on("end", () => {
            client.close();
            const respBody = Buffer.concat(chunks).toString("utf-8");
            resolve({ status, headers, body: respBody });
        });

        req.on("error", (err) => {
            client.close();
            reject(err);
        });

        req.write(body);
        req.end();
    });
}

// HTTP/2 cleartext GET request helper
function h2cGetRequest(
    hostname: string,
    port: number,
    path: string,
): Promise<{ status: number; headers: Record<string, string>; body: string }> {
    return new Promise((resolve, reject) => {
        const client = http2.connect(`http://${hostname}:${port}`);

        client.on("error", (err) => {
            client.close();
            reject(err);
        });

        const req = client.request({
            ":path": path,
            ":method": "GET",
        });

        let status = 0;
        let headers: Record<string, string> = {};
        const chunks: Buffer[] = [];

        req.on("response", (hdrs) => {
            status = hdrs[":status"] as number;
            for (const [key, value] of Object.entries(hdrs)) {
                if (!key.startsWith(":")) {
                    headers[key] = Array.isArray(value) ? value[0] : (value as string);
                }
            }
        });

        req.on("data", (chunk: Buffer) => {
            chunks.push(chunk);
        });

        req.on("end", () => {
            client.close();
            const respBody = Buffer.concat(chunks).toString("utf-8");
            resolve({ status, headers, body: respBody });
        });

        req.on("error", (err) => {
            client.close();
            reject(err);
        });

        req.end();
    });
}

// HTTP/2 over TLS POST request helper
async function h2PostRequest(
    hostname: string,
    port: number,
    path: string,
    body: string,
    certPath: string,
    contentType = "application/json",
): Promise<{ status: number; headers: Record<string, string>; body: string }> {
    const caCert = await Deno.readTextFile(certPath);
    const client = Deno.createHttpClient({
        caCerts: [caCert],
        http2: true,
    });

    try {
        const res = await fetch(`https://${hostname}:${port}${path}`, {
            client,
            method: "POST",
            headers: { "content-type": contentType },
            body,
        });
        const respBody = await res.text();
        const headers: Record<string, string> = {};
        for (const [key, value] of res.headers.entries()) {
            headers[key] = value;
        }
        return { status: res.status, headers, body: respBody };
    } finally {
        client.close();
    }
}

// HTTP/2 over TLS GET request helper
async function h2GetRequest(
    hostname: string,
    port: number,
    path: string,
    certPath: string,
): Promise<{ status: number; headers: Record<string, string>; body: string }> {
    const caCert = await Deno.readTextFile(certPath);
    const client = Deno.createHttpClient({
        caCerts: [caCert],
        http2: true,
    });

    try {
        const res = await fetch(`https://${hostname}:${port}${path}`, { client });
        const respBody = await res.text();
        const headers: Record<string, string> = {};
        for (const [key, value] of res.headers.entries()) {
            headers[key] = value;
        }
        return { status: res.status, headers, body: respBody };
    } finally {
        client.close();
    }
}

// Script that echoes back parsed JSON fields
const ECHO_JSON_SCRIPT = `
#include <zeroserve.h>

ZS_ENTRY
zs_u64 entry(void) {
    char path[256];
    zs_req_path(path, sizeof(path));

    if (zs_strcmp(path, "/echo-json") != 0) {
        return 0;
    }

    zs_s64 json = zs_req_body_json();
    if (json < 0) {
        zs_respond(400, ZS_STR("{\\"error\\":\\"invalid json\\"}"));
        return 0;
    }

    zs_s64 resp = zs_json_new_object();

    // Read "name" field
    zs_s64 name_ref = zs_json_get(json, ZS_STR("name"));
    if (name_ref >= 0) {
        zs_s64 name_out = zs_json_clone(name_ref);
        zs_json_set(resp, ZS_STR("name"), name_out);
    }

    // Read "count" field
    zs_s64 count_ref = zs_json_get(json, ZS_STR("count"));
    if (count_ref >= 0) {
        zs_s64 count_out = zs_json_clone(count_ref);
        zs_json_set(resp, ZS_STR("count"), count_out);
    }

    // Read "active" field
    zs_s64 active_ref = zs_json_get(json, ZS_STR("active"));
    if (active_ref >= 0) {
        zs_s64 active_out = zs_json_clone(active_ref);
        zs_json_set(resp, ZS_STR("active"), active_out);
    }

    zs_object_free(json);
    zs_json_respond(200, resp);
    return 0;
}
`;

// Script for testing parse failures
const PARSE_JSON_SCRIPT = `
#include <zeroserve.h>

ZS_ENTRY
zs_u64 entry(void) {
    char path[256];
    zs_req_path(path, sizeof(path));

    if (zs_strcmp(path, "/parse-json") != 0) {
        return 0;
    }

    zs_s64 json = zs_req_body_json();
    if (json < 0) {
        zs_respond(400, ZS_STR("{\\"error\\":\\"parse_failed\\"}"));
        return 0;
    }

    zs_respond(200, ZS_STR("{\\"ok\\":true}"));
    return 0;
}
`;

// Script for nested JSON testing
const NESTED_JSON_SCRIPT = `
#include <zeroserve.h>

ZS_ENTRY
zs_u64 entry(void) {
    char path[256];
    zs_req_path(path, sizeof(path));

    if (zs_strcmp(path, "/nested") != 0) {
        return 0;
    }

    zs_s64 json = zs_req_body_json();
    if (json < 0) {
        zs_respond(400, ZS_STR("{\\"error\\":\\"invalid json\\"}"));
        return 0;
    }

    zs_s64 resp = zs_json_new_object();

    // Navigate: user.name
    zs_s64 user = zs_json_get(json, ZS_STR("user"));
    if (user >= 0) {
        zs_s64 name = zs_json_get(user, ZS_STR("name"));
        if (name >= 0) {
            zs_s64 name_out = zs_json_clone(name);
            zs_json_set(resp, ZS_STR("user_name"), name_out);
        }
    }

    // Navigate: items array
    zs_s64 items = zs_json_get(json, ZS_STR("items"));
    if (items >= 0) {
        zs_s64 len = zs_json_len(items);
        zs_s64 len_out = zs_json_new_object();
        zs_json_set_i64(len_out, len);
        zs_json_set(resp, ZS_STR("items_count"), len_out);

        zs_s64 item1 = zs_json_array_get(items, 1);
        if (item1 >= 0) {
            zs_s64 item1_out = zs_json_clone(item1);
            zs_json_set(resp, ZS_STR("second_item"), item1_out);
        }
    }

    zs_object_free(json);
    zs_json_respond(200, resp);
    return 0;
}
`;

// Script for testing multiple reads (caching)
const MULTI_READ_SCRIPT = `
#include <zeroserve.h>

ZS_ENTRY
zs_u64 entry(void) {
    char path[256];
    zs_req_path(path, sizeof(path));

    if (zs_strcmp(path, "/multi-read") != 0) {
        return 0;
    }

    // Call zs_req_body_json twice - should return same data
    zs_s64 json1 = zs_req_body_json();
    zs_s64 json2 = zs_req_body_json();

    if (json1 < 0 || json2 < 0) {
        zs_respond(400, ZS_STR("{\\"error\\":\\"parse_failed\\"}"));
        return 0;
    }

    zs_s64 resp = zs_json_new_object();

    zs_s64 v1 = zs_json_get(json1, ZS_STR("value"));
    zs_s64 v2 = zs_json_get(json2, ZS_STR("value"));

    if (v1 >= 0 && v2 >= 0) {
        zs_s64 val1 = 0, val2 = 0;
        zs_json_read_i64(v1, &val1, sizeof(val1));
        zs_json_read_i64(v2, &val2, sizeof(val2));

        zs_s64 v1_out = zs_json_new_object();
        zs_json_set_i64(v1_out, val1);
        zs_json_set(resp, ZS_STR("first_read"), v1_out);

        zs_s64 v2_out = zs_json_new_object();
        zs_json_set_i64(v2_out, val2);
        zs_json_set(resp, ZS_STR("second_read"), v2_out);
    }

    zs_json_respond(200, resp);
    return 0;
}
`;

// Script that doesn't read body
const NO_BODY_SCRIPT = `
#include <zeroserve.h>

ZS_ENTRY
zs_u64 entry(void) {
    char path[256];
    zs_req_path(path, sizeof(path));

    if (zs_strcmp(path, "/no-body-read") != 0) {
        return 0;
    }

    // Don't read body, just respond
    zs_respond(200, ZS_STR("{\\"status\\":\\"ok\\"}"));
    return 0;
}
`;

Deno.test({
    name: "e2e: zs_req_body_json - parse valid JSON (h1, h2c, h2)",
    ignore: !canRunScripts,
    fn: async () => {
        const siteDir = await Deno.makeTempDir();
        let tarPath: string | null = null;
        const cert = await generateSelfSignedCert();
        try {
            const scriptsDir = join(siteDir, ".zeroserve", "scripts");
            await Deno.mkdir(scriptsDir, { recursive: true });
            await Deno.writeTextFile(join(scriptsDir, "body_json.c"), ECHO_JSON_SCRIPT);

            tarPath = await packSite(siteDir);

            await withZeroserveTls(tarPath, cert.certPath, cert.keyPath, async (httpUrl, httpsUrl) => {
                const httpUrlObj = new URL(httpUrl);
                const httpsUrlObj = new URL(httpsUrl);
                const testBody = JSON.stringify({
                    name: "test-user",
                    count: 42,
                    active: true,
                });

                // Test HTTP/1.1
                const h1Res = await fetch(`${httpUrl}/echo-json`, {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: testBody,
                });
                assertEquals(h1Res.status, 200, "h1 status");
                const h1Body = await h1Res.json();
                assertEquals(h1Body.name, "test-user", "h1 name");
                assertEquals(h1Body.count, 42, "h1 count");
                assertEquals(h1Body.active, true, "h1 active");

                // Test h2c (HTTP/2 cleartext)
                const h2cRes = await h2cPostRequest(
                    httpUrlObj.hostname,
                    Number(httpUrlObj.port),
                    "/echo-json",
                    testBody,
                );
                assertEquals(h2cRes.status, 200, "h2c status");
                const h2cBody = JSON.parse(h2cRes.body);
                assertEquals(h2cBody.name, "test-user", "h2c name");
                assertEquals(h2cBody.count, 42, "h2c count");
                assertEquals(h2cBody.active, true, "h2c active");

                // Test h2 (HTTP/2 over TLS)
                const h2Res = await h2PostRequest(
                    httpsUrlObj.hostname,
                    Number(httpsUrlObj.port),
                    "/echo-json",
                    testBody,
                    cert.certPath,
                );
                assertEquals(h2Res.status, 200, "h2 status");
                const h2Body = JSON.parse(h2Res.body);
                assertEquals(h2Body.name, "test-user", "h2 name");
                assertEquals(h2Body.count, 42, "h2 count");
                assertEquals(h2Body.active, true, "h2 active");
            });
        } finally {
            await Deno.remove(siteDir, { recursive: true }).catch(() => {});
            if (tarPath) await Deno.remove(tarPath).catch(() => {});
            await cert.cleanup();
        }
    },
});

Deno.test({
    name: "e2e: zs_req_body_json - invalid JSON returns -1 (h1, h2c, h2)",
    ignore: !canRunScripts,
    fn: async () => {
        const siteDir = await Deno.makeTempDir();
        let tarPath: string | null = null;
        const cert = await generateSelfSignedCert();
        try {
            const scriptsDir = join(siteDir, ".zeroserve", "scripts");
            await Deno.mkdir(scriptsDir, { recursive: true });
            await Deno.writeTextFile(join(scriptsDir, "body_json.c"), PARSE_JSON_SCRIPT);

            tarPath = await packSite(siteDir);

            await withZeroserveTls(tarPath, cert.certPath, cert.keyPath, async (httpUrl, httpsUrl) => {
                const httpUrlObj = new URL(httpUrl);
                const httpsUrlObj = new URL(httpsUrl);
                const invalidJson = "{ invalid json }";

                // Test HTTP/1.1
                const h1Res = await fetch(`${httpUrl}/parse-json`, {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: invalidJson,
                });
                assertEquals(h1Res.status, 400, "h1 status");
                const h1Body = await h1Res.json();
                assertEquals(h1Body.error, "parse_failed", "h1 error");

                // Test h2c
                const h2cRes = await h2cPostRequest(
                    httpUrlObj.hostname,
                    Number(httpUrlObj.port),
                    "/parse-json",
                    invalidJson,
                );
                assertEquals(h2cRes.status, 400, "h2c status");
                const h2cBody = JSON.parse(h2cRes.body);
                assertEquals(h2cBody.error, "parse_failed", "h2c error");

                // Test h2
                const h2Res = await h2PostRequest(
                    httpsUrlObj.hostname,
                    Number(httpsUrlObj.port),
                    "/parse-json",
                    invalidJson,
                    cert.certPath,
                );
                assertEquals(h2Res.status, 400, "h2 status");
                const h2Body = JSON.parse(h2Res.body);
                assertEquals(h2Body.error, "parse_failed", "h2 error");
            });
        } finally {
            await Deno.remove(siteDir, { recursive: true }).catch(() => {});
            if (tarPath) await Deno.remove(tarPath).catch(() => {});
            await cert.cleanup();
        }
    },
});

Deno.test({
    name: "e2e: zs_req_body_json - empty body returns -1 (h1, h2c, h2)",
    ignore: !canRunScripts,
    fn: async () => {
        const siteDir = await Deno.makeTempDir();
        let tarPath: string | null = null;
        const cert = await generateSelfSignedCert();
        try {
            const scriptsDir = join(siteDir, ".zeroserve", "scripts");
            await Deno.mkdir(scriptsDir, { recursive: true });
            await Deno.writeTextFile(join(scriptsDir, "body_json.c"), PARSE_JSON_SCRIPT);

            tarPath = await packSite(siteDir);

            await withZeroserveTls(tarPath, cert.certPath, cert.keyPath, async (httpUrl, httpsUrl) => {
                const httpUrlObj = new URL(httpUrl);
                const httpsUrlObj = new URL(httpsUrl);

                // Test HTTP/1.1 (GET = no body)
                const h1Res = await fetch(`${httpUrl}/parse-json`, { method: "GET" });
                assertEquals(h1Res.status, 400, "h1 status");
                const h1Body = await h1Res.json();
                assertEquals(h1Body.error, "parse_failed", "h1 error");

                // Test h2c (GET = no body)
                const h2cRes = await h2cGetRequest(
                    httpUrlObj.hostname,
                    Number(httpUrlObj.port),
                    "/parse-json",
                );
                assertEquals(h2cRes.status, 400, "h2c status");
                const h2cBody = JSON.parse(h2cRes.body);
                assertEquals(h2cBody.error, "parse_failed", "h2c error");

                // Test h2 (GET = no body)
                const h2Res = await h2GetRequest(
                    httpsUrlObj.hostname,
                    Number(httpsUrlObj.port),
                    "/parse-json",
                    cert.certPath,
                );
                assertEquals(h2Res.status, 400, "h2 status");
                const h2Body = JSON.parse(h2Res.body);
                assertEquals(h2Body.error, "parse_failed", "h2 error");
            });
        } finally {
            await Deno.remove(siteDir, { recursive: true }).catch(() => {});
            if (tarPath) await Deno.remove(tarPath).catch(() => {});
            await cert.cleanup();
        }
    },
});

Deno.test({
    name: "e2e: zs_req_body_json - nested objects and arrays (h1, h2c, h2)",
    ignore: !canRunScripts,
    fn: async () => {
        const siteDir = await Deno.makeTempDir();
        let tarPath: string | null = null;
        const cert = await generateSelfSignedCert();
        try {
            const scriptsDir = join(siteDir, ".zeroserve", "scripts");
            await Deno.mkdir(scriptsDir, { recursive: true });
            await Deno.writeTextFile(join(scriptsDir, "body_json.c"), NESTED_JSON_SCRIPT);

            tarPath = await packSite(siteDir);

            await withZeroserveTls(tarPath, cert.certPath, cert.keyPath, async (httpUrl, httpsUrl) => {
                const httpUrlObj = new URL(httpUrl);
                const httpsUrlObj = new URL(httpsUrl);
                const nestedBody = JSON.stringify({
                    user: { name: "alice", age: 30 },
                    items: ["first", "second", "third"],
                });

                // Test HTTP/1.1
                const h1Res = await fetch(`${httpUrl}/nested`, {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: nestedBody,
                });
                assertEquals(h1Res.status, 200, "h1 status");
                const h1Body = await h1Res.json();
                assertEquals(h1Body.user_name, "alice", "h1 user_name");
                assertEquals(h1Body.items_count, 3, "h1 items_count");
                assertEquals(h1Body.second_item, "second", "h1 second_item");

                // Test h2c
                const h2cRes = await h2cPostRequest(
                    httpUrlObj.hostname,
                    Number(httpUrlObj.port),
                    "/nested",
                    nestedBody,
                );
                assertEquals(h2cRes.status, 200, "h2c status");
                const h2cBody = JSON.parse(h2cRes.body);
                assertEquals(h2cBody.user_name, "alice", "h2c user_name");
                assertEquals(h2cBody.items_count, 3, "h2c items_count");
                assertEquals(h2cBody.second_item, "second", "h2c second_item");

                // Test h2
                const h2Res = await h2PostRequest(
                    httpsUrlObj.hostname,
                    Number(httpsUrlObj.port),
                    "/nested",
                    nestedBody,
                    cert.certPath,
                );
                assertEquals(h2Res.status, 200, "h2 status");
                const h2Body = JSON.parse(h2Res.body);
                assertEquals(h2Body.user_name, "alice", "h2 user_name");
                assertEquals(h2Body.items_count, 3, "h2 items_count");
                assertEquals(h2Body.second_item, "second", "h2 second_item");
            });
        } finally {
            await Deno.remove(siteDir, { recursive: true }).catch(() => {});
            if (tarPath) await Deno.remove(tarPath).catch(() => {});
            await cert.cleanup();
        }
    },
});

Deno.test({
    name: "e2e: zs_req_body_json - multiple calls return cached result (h1, h2c, h2)",
    ignore: !canRunScripts,
    fn: async () => {
        const siteDir = await Deno.makeTempDir();
        let tarPath: string | null = null;
        const cert = await generateSelfSignedCert();
        try {
            const scriptsDir = join(siteDir, ".zeroserve", "scripts");
            await Deno.mkdir(scriptsDir, { recursive: true });
            await Deno.writeTextFile(join(scriptsDir, "body_json.c"), MULTI_READ_SCRIPT);

            tarPath = await packSite(siteDir);

            await withZeroserveTls(tarPath, cert.certPath, cert.keyPath, async (httpUrl, httpsUrl) => {
                const httpUrlObj = new URL(httpUrl);
                const httpsUrlObj = new URL(httpsUrl);
                const testBody = JSON.stringify({ value: 123 });

                // Test HTTP/1.1
                const h1Res = await fetch(`${httpUrl}/multi-read`, {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: testBody,
                });
                assertEquals(h1Res.status, 200, "h1 status");
                const h1Body = await h1Res.json();
                assertEquals(h1Body.first_read, 123, "h1 first_read");
                assertEquals(h1Body.second_read, 123, "h1 second_read");

                // Test h2c
                const h2cRes = await h2cPostRequest(
                    httpUrlObj.hostname,
                    Number(httpUrlObj.port),
                    "/multi-read",
                    testBody,
                );
                assertEquals(h2cRes.status, 200, "h2c status");
                const h2cBody = JSON.parse(h2cRes.body);
                assertEquals(h2cBody.first_read, 123, "h2c first_read");
                assertEquals(h2cBody.second_read, 123, "h2c second_read");

                // Test h2
                const h2Res = await h2PostRequest(
                    httpsUrlObj.hostname,
                    Number(httpsUrlObj.port),
                    "/multi-read",
                    testBody,
                    cert.certPath,
                );
                assertEquals(h2Res.status, 200, "h2 status");
                const h2Body = JSON.parse(h2Res.body);
                assertEquals(h2Body.first_read, 123, "h2 first_read");
                assertEquals(h2Body.second_read, 123, "h2 second_read");
            });
        } finally {
            await Deno.remove(siteDir, { recursive: true }).catch(() => {});
            if (tarPath) await Deno.remove(tarPath).catch(() => {});
            await cert.cleanup();
        }
    },
});

Deno.test({
    name: "e2e: zs_req_body_json - body not read if not requested (h1, h2c, h2)",
    ignore: !canRunScripts,
    fn: async () => {
        const siteDir = await Deno.makeTempDir();
        let tarPath: string | null = null;
        const cert = await generateSelfSignedCert();
        try {
            const scriptsDir = join(siteDir, ".zeroserve", "scripts");
            await Deno.mkdir(scriptsDir, { recursive: true });
            await Deno.writeTextFile(join(scriptsDir, "no_body.c"), NO_BODY_SCRIPT);

            tarPath = await packSite(siteDir);

            await withZeroserveTls(tarPath, cert.certPath, cert.keyPath, async (httpUrl, httpsUrl) => {
                const httpUrlObj = new URL(httpUrl);
                const httpsUrlObj = new URL(httpsUrl);
                const testBody = JSON.stringify({ data: "ignored" });

                // Test HTTP/1.1
                const h1Res = await fetch(`${httpUrl}/no-body-read`, {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: testBody,
                });
                assertEquals(h1Res.status, 200, "h1 status");
                const h1Body = await h1Res.json();
                assertEquals(h1Body.status, "ok", "h1 body not read");

                // Test h2c
                const h2cRes = await h2cPostRequest(
                    httpUrlObj.hostname,
                    Number(httpUrlObj.port),
                    "/no-body-read",
                    testBody,
                );
                assertEquals(h2cRes.status, 200, "h2c status");
                const h2cBody = JSON.parse(h2cRes.body);
                assertEquals(h2cBody.status, "ok", "h2c body not read");

                // Test h2
                const h2Res = await h2PostRequest(
                    httpsUrlObj.hostname,
                    Number(httpsUrlObj.port),
                    "/no-body-read",
                    testBody,
                    cert.certPath,
                );
                assertEquals(h2Res.status, 200, "h2 status");
                const h2Body = JSON.parse(h2Res.body);
                assertEquals(h2Body.status, "ok", "h2 body not read");
            });
        } finally {
            await Deno.remove(siteDir, { recursive: true }).catch(() => {});
            if (tarPath) await Deno.remove(tarPath).catch(() => {});
            await cert.cleanup();
        }
    },
});

Deno.test({
    name: "e2e: zs_req_body_json - chunked transfer encoding (h1)",
    ignore: !canRunScripts,
    fn: async () => {
        const siteDir = await Deno.makeTempDir();
        let tarPath: string | null = null;
        const cert = await generateSelfSignedCert();
        try {
            const scriptsDir = join(siteDir, ".zeroserve", "scripts");
            await Deno.mkdir(scriptsDir, { recursive: true });

            await Deno.writeTextFile(
                join(scriptsDir, "body_json.c"),
                `
#include <zeroserve.h>

ZS_ENTRY
zs_u64 entry(void) {
    char path[256];
    zs_req_path(path, sizeof(path));

    if (zs_strcmp(path, "/chunked") != 0) {
        return 0;
    }

    zs_s64 json = zs_req_body_json();
    if (json < 0) {
        zs_respond(400, ZS_STR("{\\"error\\":\\"parse_failed\\"}"));
        return 0;
    }

    zs_s64 msg = zs_json_get(json, ZS_STR("message"));
    if (msg >= 0) {
        zs_s64 resp = zs_json_new_object();
        zs_s64 echo = zs_json_clone(msg);
        zs_json_set(resp, ZS_STR("echo"), echo);
        zs_json_respond(200, resp);
        return 0;
    }

    zs_respond(400, ZS_STR("{\\"error\\":\\"missing_message\\"}"));
    return 0;
}
`,
            );

            tarPath = await packSite(siteDir);

            await withZeroserveTls(tarPath, cert.certPath, cert.keyPath, async (httpUrl, _httpsUrl) => {
                const url = new URL(httpUrl);

                // Send chunked request using raw connection (HTTP/1.1 only)
                const conn = await Deno.connect({
                    hostname: url.hostname,
                    port: parseInt(url.port),
                });

                try {
                    const body = JSON.stringify({ message: "hello-chunked" });
                    const chunk1 = body.slice(0, 10);
                    const chunk2 = body.slice(10);

                    const request = [
                        `POST /chunked HTTP/1.1`,
                        `Host: ${url.host}`,
                        `Content-Type: application/json`,
                        `Transfer-Encoding: chunked`,
                        ``,
                        ``,
                    ].join("\r\n");

                    await writeAll(conn, encoder.encode(request));

                    // Send chunks
                    await writeAll(conn, encoder.encode(`${chunk1.length.toString(16)}\r\n${chunk1}\r\n`));
                    await writeAll(conn, encoder.encode(`${chunk2.length.toString(16)}\r\n${chunk2}\r\n`));
                    await writeAll(conn, encoder.encode("0\r\n\r\n"));

                    // Read response
                    const response = await readHttpResponse(conn);
                    assertEquals(response.status, 200, "chunked h1 status");
                    const respBody = JSON.parse(decoder.decode(response.body));
                    assertEquals(respBody.echo, "hello-chunked", "chunked h1 echo");
                } finally {
                    conn.close();
                }
            });
        } finally {
            await Deno.remove(siteDir, { recursive: true }).catch(() => {});
            if (tarPath) await Deno.remove(tarPath).catch(() => {});
            await cert.cleanup();
        }
    },
});

// Helper functions for raw HTTP

async function writeAll(conn: Deno.Conn, data: Uint8Array): Promise<void> {
    let offset = 0;
    while (offset < data.length) {
        offset += await conn.write(data.subarray(offset));
    }
}

async function readHttpResponse(conn: Deno.Conn): Promise<{ status: number; headers: Headers; body: Uint8Array }> {
    const buf = new Uint8Array(8192);
    let data = new Uint8Array(0);

    // Read until we have headers
    while (!decoder.decode(data).includes("\r\n\r\n")) {
        const n = await conn.read(buf);
        if (n === null) break;
        const newData = new Uint8Array(data.length + n);
        newData.set(data);
        newData.set(buf.subarray(0, n), data.length);
        data = newData;
    }

    const text = decoder.decode(data);
    const headerEnd = text.indexOf("\r\n\r\n");
    const headerText = text.slice(0, headerEnd);
    const bodyStart = headerEnd + 4;

    const lines = headerText.split("\r\n");
    const statusLine = lines[0];
    const status = parseInt(statusLine.split(" ")[1], 10);

    const headers = new Headers();
    for (const line of lines.slice(1)) {
        const idx = line.indexOf(":");
        if (idx !== -1) {
            headers.append(line.slice(0, idx).trim(), line.slice(idx + 1).trim());
        }
    }

    // Read body based on Content-Length
    const contentLength = parseInt(headers.get("content-length") || "0", 10);
    let body = data.subarray(encoder.encode(text.slice(0, bodyStart)).length);

    while (body.length < contentLength) {
        const n = await conn.read(buf);
        if (n === null) break;
        const newBody = new Uint8Array(body.length + n);
        newBody.set(body);
        newBody.set(buf.subarray(0, n), body.length);
        body = newBody;
    }

    return { status, headers, body: body.subarray(0, contentLength) };
}
