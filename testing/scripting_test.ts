import { assert, assertEquals } from "@std/assert";
import { join } from "@std/path";
import {
  hasBpfToolchain,
  packSite,
  repoRoot,
  withZeroserve,
} from "./test_utils.ts";

const canRunScripts = await hasBpfToolchain();

async function startBackend(
  handler: (req: Request) => Response,
): Promise<{ url: string; close: () => Promise<void> }> {
  const controller = new AbortController();
  let port = 0;
  const server = Deno.serve(
    {
      hostname: "127.0.0.1",
      port: 0,
      signal: controller.signal,
      onListen: ({ port: listenPort }) => {
        port = listenPort;
      },
    },
    handler,
  );

  if (port === 0) {
    await new Promise((resolve) => setTimeout(resolve, 0));
  }

  if (port === 0) {
    controller.abort();
    await server.finished;
    throw new Error("failed to start backend server");
  }

  return {
    url: `http://127.0.0.1:${port}`,
    close: async () => {
      controller.abort();
      await server.finished;
    },
  };
}

Deno.test({
  name: "e2e: scripting APIs",
  ignore: !canRunScripts,
  fn: async () => {
    const siteDir = await Deno.makeTempDir();
    let tarPath: string | null = null;
    try {
      await Deno.writeTextFile(
        join(siteDir, "index.html"),
        "Hello <zs-meta>name</zs-meta> via <zs-meta>method</zs-meta> at <zs-meta>now_ms</zs-meta>\n",
      );

      const scriptsDir = join(siteDir, ".zeroserve", "scripts");
      await Deno.mkdir(scriptsDir, { recursive: true });
      await Deno.copyFile(
        join(repoRoot, "examples", "template.c"),
        join(scriptsDir, "template.c"),
      );
      await Deno.copyFile(
        join(repoRoot, "examples", "health_response.c"),
        join(scriptsDir, "health_response.c"),
      );

      tarPath = await packSite(siteDir);

      await withZeroserve(tarPath, async (baseUrl) => {
        const healthRes = await fetch(`${baseUrl}/health`);
        assertEquals(healthRes.status, 200);
        const healthJson = await healthRes.json() as {
          status: string;
          year: string;
        };
        assertEquals(healthJson.status, "ok");
        const year = Number.parseInt(healthJson.year, 10);
        assert(!Number.isNaN(year));
        assert(year >= 1970 && year <= 3000);

        const templatedRes = await fetch(
          `${baseUrl}/index.html?name=user`,
        );
        assertEquals(templatedRes.status, 200);
        const templatedBody = await templatedRes.text();
        assert(templatedBody.includes("Hello user via GET"));
        assert(!templatedBody.includes("<zs-meta>name</zs-meta>"));
        assert(!templatedBody.includes("<zs-meta>method</zs-meta>"));
        assert(!templatedBody.includes("<zs-meta>now_ms</zs-meta>"));
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
  name: "e2e: request mutations (set_uri, set_header)",
  ignore: !canRunScripts,
  fn: async () => {
    const backend = await startBackend((req) => {
      const url = new URL(req.url);
      const payload = {
        path: url.pathname,
        query: url.search.slice(1),
        headers: {
          "x-original": req.headers.get("x-original"),
          "x-remove": req.headers.get("x-remove"),
          "x-script-set": req.headers.get("x-script-set"),
        },
      };
      return new Response(JSON.stringify(payload), {
        headers: { "content-type": "application/json" },
      });
    });

    const siteDir = await Deno.makeTempDir();
    let tarPath: string | null = null;
    try {
      await Deno.writeTextFile(
        join(siteDir, "index.html"),
        "proxy target\n",
      );
      const scriptsDir = join(siteDir, ".zeroserve", "scripts");
      await Deno.mkdir(scriptsDir, { recursive: true });

      const backendUrl = backend.url;
      const scriptSource = `#include <zeroserve.h>

ZS_ENTRY
zs_u64 entry(void) {
  const char *uri = "/proxy/rewritten?name=changed&flag=1";
  zs_req_set_uri(uri, sizeof("/proxy/rewritten?name=changed&flag=1") - 1);

  const char *set_name = "x-script-set";
  const char *set_value = "from-script";
  zs_req_set_header(set_name, sizeof("x-script-set") - 1, set_value, sizeof("from-script") - 1);

  const char *remove_name = "x-remove";
  zs_req_set_header(remove_name, sizeof("x-remove") - 1, "", 0);

  const char *backend = "${backendUrl}";
  zs_reverse_proxy(backend, sizeof("${backendUrl}") - 1);
  return 0;
}
`;
      await Deno.writeTextFile(
        join(scriptsDir, "10-rewrite_proxy.c"),
        scriptSource,
      );

      tarPath = await packSite(siteDir);

      await withZeroserve(tarPath, async (baseUrl) => {
        const res = await fetch(
          `${baseUrl}/original/path?name=orig`,
          {
            headers: {
              "x-original": "keep",
              "x-remove": "drop",
            },
          },
        );
        assertEquals(res.status, 200);
        const payload = await res.json() as {
          path: string;
          query: string;
          headers: Record<string, string | null>;
        };
        assertEquals(payload.path, "/proxy/rewritten");
        assertEquals(payload.query, "name=changed&flag=1");
        assertEquals(payload.headers["x-original"], "keep");
        assertEquals(payload.headers["x-script-set"], "from-script");
        assertEquals(payload.headers["x-remove"], null);
      });
    } finally {
      await backend.close().catch(() => {});
      if (tarPath) {
        await Deno.remove(tarPath).catch(() => {});
      }
      await Deno.remove(siteDir, { recursive: true }).catch(() => {});
    }
  },
});
