import { assert, assertEquals } from "@std/assert";
import { join } from "@std/path";
import { hasBpfToolchain, spawnZeroserve } from "./test_utils.ts";

const canRunScripts = await hasBpfToolchain();

// A single callee script exposing one ZS_CALL_ENTRY per `zeroserve_call`
// function we exercise. The Caddyfile directive `zeroserve_call gate <fn>`
// resolves "gate" to this plugin (loaded as the script name "gate.o") and
// invokes <fn> via the runtime's zs_call path, exactly like a stock Caddy
// route would invoke a native handler.
const GATE_SCRIPT = `#include <zeroserve.h>

/* Read input.config.<key> into a fixed buffer; leaves it empty when absent. */
static void read_config_string(zs_u64 input, const char *key, zs_u64 key_len,
                               char *out, zs_u64 out_len) {
  out[0] = '\\0';
  zs_s64 config = zs_json_get(input, ZS_STR("config"));
  if (config < 0) {
    return;
  }
  zs_s64 node = zs_json_get(config, key, key_len);
  if (node >= 0) {
    zs_json_read_string(node, out, out_len);
    zs_object_free(node);
  }
  zs_object_free(config);
}

/* Set out["action"] = "<name>". */
static void set_action(zs_u64 out, const char *name) {
  zs_s64 action = zs_json_new_object();
  zs_json_set_string(action, ZS_STR(name));
  zs_json_set(out, ZS_STR("action"), action);
  zs_object_free(action);
}

/* decide: deny -> terminal 403 response; anything else -> continue. */
ZS_CALL_ENTRY(decide, input) {
  char mode[32];
  read_config_string(input, ZS_STR("mode"), mode, sizeof(mode));

  zs_s64 out = zs_json_new_object();
  if (zs_strcmp(mode, "deny") == 0) {
    set_action(out, "respond");

    zs_s64 status = zs_json_new_object();
    zs_json_set_i64(status, 403);
    zs_json_set(out, ZS_STR("status"), status);
    zs_object_free(status);

    zs_s64 body = zs_json_new_object();
    zs_json_set_string(body, ZS_STR("denied by gate\\n"));
    zs_json_set(out, ZS_STR("body"), body);
    zs_object_free(body);

    /* headers: { "X-Gate": ["denied"] } */
    zs_s64 value = zs_json_new_object();
    zs_json_set_string(value, ZS_STR("denied"));
    zs_s64 list = zs_json_new_array();
    zs_json_array_push(list, value);
    zs_object_free(value);
    zs_s64 headers = zs_json_new_object();
    zs_json_set(headers, ZS_STR("X-Gate"), list);
    zs_object_free(list);
    zs_json_set(out, ZS_STR("headers"), headers);
    zs_object_free(headers);
  } else {
    set_action(out, "continue");
  }
  return out;
}

/* mutate: add a request header then continue, proving request mutations made
 * inside the call survive into later Caddy handlers (here, reverse_proxy). */
ZS_CALL_ENTRY(mutate, input) {
  zs_req_set_header(ZS_STR("X-Gate"), ZS_STR("passed"));
  zs_s64 out = zs_json_new_object();
  set_action(out, "continue");
  return out;
}

/* sdk_respond: call a native terminal response helper, then ask zs_call to
 * translate that callee-local response into a Caddy adoptable action. */
ZS_CALL_ENTRY(sdk_respond, input) {
  zs_respond(202, ZS_STR("sdk response\\n"));
  zs_s64 out = zs_json_new_object();
  set_action(out, "adopt_response");
  return out;
}

/* proxy: terminal reverse-proxy to input.config.url. */
ZS_CALL_ENTRY(proxy, input) {
  char url[256];
  read_config_string(input, ZS_STR("url"), url, sizeof(url));

  zs_s64 out = zs_json_new_object();
  set_action(out, "proxy");
  zs_s64 value = zs_json_new_object();
  zs_json_set_string(value, ZS_STR(url));
  zs_json_set(out, ZS_STR("url"), value);
  zs_object_free(value);
  return out;
}

/* fault: enter Caddy error handling with status 401. */
ZS_CALL_ENTRY(fault, input) {
  zs_s64 out = zs_json_new_object();
  set_action(out, "error");
  zs_s64 status = zs_json_new_object();
  zs_json_set_i64(status, 401);
  zs_json_set(out, ZS_STR("status"), status);
  zs_object_free(status);
  return out;
}

/* bogus: an unknown action, which the adoption helper must treat as failure. */
ZS_CALL_ENTRY(bogus, input) {
  zs_s64 out = zs_json_new_object();
  set_action(out, "teleport");
  return out;
}
`;

interface Backend {
  url: string;
  close: () => Promise<void>;
}

async function startBackend(
  handler: (req: Request) => Response | Promise<Response>,
): Promise<Backend> {
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

/**
 * Serve a Caddyfile through the `--caddy` flow with the gate callee attached as
 * a plugin, then run `fn` against the listening HTTP base URL. This drives the
 * full Caddyfile -> adapt -> compile -> zeroserve_call -> zs_call -> adopt
 * pipeline at runtime, which is what we actually want to verify.
 */
async function withGate(
  caddyfile: string,
  fn: (baseUrl: string) => Promise<void>,
): Promise<void> {
  const dir = await Deno.makeTempDir();
  try {
    const caddyfilePath = join(dir, "Caddyfile");
    await Deno.writeTextFile(caddyfilePath, caddyfile);
    const gatePath = join(dir, "gate.c");
    await Deno.writeTextFile(gatePath, GATE_SCRIPT);

    const proc = await spawnZeroserve([
      "--caddy",
      caddyfilePath,
      "--plugin",
      gatePath,
    ]);
    try {
      await fn(`http://127.0.0.1:${proc.httpPort}`);
    } finally {
      await proc.stop();
    }
  } finally {
    await Deno.remove(dir, { recursive: true }).catch(() => {});
  }
}

Deno.test({
  name: "e2e: zeroserve_call respond action stops the route with config-driven status",
  ignore: !canRunScripts,
  fn: async () => {
    await withGate(
      `:80 {
  route {
    zeroserve_call gate decide {
      mode deny
    }
    respond "allowed" 200
  }
}
`,
      async (baseUrl) => {
        const res = await fetch(`${baseUrl}/anything`);
        assertEquals(res.status, 403);
        assertEquals(res.headers.get("x-gate"), "denied");
        assertEquals(await res.text(), "denied by gate\n");
      },
    );
  },
});

Deno.test({
  name: "e2e: zeroserve_call continue action falls through to the next handler",
  ignore: !canRunScripts,
  fn: async () => {
    await withGate(
      `:80 {
  route {
    zeroserve_call gate decide {
      mode allow
    }
    respond "allowed" 200
  }
}
`,
      async (baseUrl) => {
        const res = await fetch(`${baseUrl}/anything`);
        assertEquals(res.status, 200);
        assertEquals(await res.text(), "allowed");
      },
    );
  },
});

Deno.test({
  name: "e2e: zeroserve_call request mutation survives into later handlers",
  ignore: !canRunScripts,
  fn: async () => {
    const backend = await startBackend((req) =>
      new Response(req.headers.get("x-gate") ?? "absent", {
        headers: { "content-type": "text/plain" },
      })
    );
    try {
      await withGate(
        `:80 {
  route {
    zeroserve_call gate mutate
    reverse_proxy ${backend.url}
  }
}
`,
        async (baseUrl) => {
          const res = await fetch(`${baseUrl}/anything`);
          assertEquals(res.status, 200);
          assertEquals(await res.text(), "passed");
        },
      );
    } finally {
      await backend.close();
    }
  },
});

Deno.test({
  name: "e2e: zeroserve_call can adopt a native helper response from the callee",
  ignore: !canRunScripts,
  fn: async () => {
    await withGate(
      `:80 {
  route {
    zeroserve_call gate sdk_respond
    respond "fallback" 200
  }
}
`,
      async (baseUrl) => {
        const res = await fetch(`${baseUrl}/anything`);
        assertEquals(res.status, 202);
        assertEquals(await res.text(), "sdk response\n");
      },
    );
  },
});

Deno.test({
  name: "e2e: zeroserve_call proxy action reverse-proxies to the configured url",
  ignore: !canRunScripts,
  fn: async () => {
    const backend = await startBackend(() =>
      new Response("from backend", {
        headers: { "content-type": "text/plain" },
      })
    );
    try {
      await withGate(
        `:80 {
  zeroserve_call gate proxy {
    url ${backend.url}
  }
}
`,
        async (baseUrl) => {
          const res = await fetch(`${baseUrl}/anything`);
          assertEquals(res.status, 200);
          assertEquals(await res.text(), "from backend");
        },
      );
    } finally {
      await backend.close();
    }
  },
});

Deno.test({
  name: "e2e: zeroserve_call error action enters handle_errors routes",
  ignore: !canRunScripts,
  fn: async () => {
    // The error action enters Caddy error handling even when raised from inside
    // a `route {}` subroute: the subroute inherits the server-level handle_errors
    // routes rather than emitting a bare status response.
    await withGate(
      `:80 {
  route {
    zeroserve_call gate fault
    respond "should not reach" 200
  }
  handle_errors {
    respond "handled {err.status_code}" {err.status_code}
  }
}
`,
      async (baseUrl) => {
        const res = await fetch(`${baseUrl}/anything`);
        assertEquals(res.status, 401);
        assertEquals(await res.text(), "handled 401");
      },
    );
  },
});

Deno.test({
  name: "e2e: zeroserve_call unknown action is treated as handler failure",
  ignore: !canRunScripts,
  fn: async () => {
    await withGate(
      `:80 {
  zeroserve_call gate bogus
  respond "nope" 200
}
`,
      async (baseUrl) => {
        const res = await fetch(`${baseUrl}/anything`);
        assertEquals(res.status, 500);
        await res.body?.cancel();
      },
    );
  },
});
