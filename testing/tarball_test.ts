import { assert, assertEquals } from "@std/assert";
import { join } from "@std/path";
import {
  checkExited,
  compileScriptObject,
  delay,
  getZeroservePath,
  hasBpfToolchain,
  packSite,
  raceWithTimeout,
  spawnZeroserve,
  withZeroserve,
  type ZeroserveProc,
} from "./test_utils.ts";

const canRunScripts = await hasBpfToolchain();

Deno.test("e2e: serves tarball content", async () => {
  const siteDir = await Deno.makeTempDir();
  let tarPath: string | null = null;
  try {
    await Deno.writeTextFile(
      join(siteDir, "index.html"),
      "<!doctype html><h1>hello tarball</h1>\n",
    );
    await Deno.mkdir(join(siteDir, "docs"), { recursive: true });
    await Deno.writeTextFile(join(siteDir, "docs", "note.txt"), "docs ok\n");

    tarPath = await packSite(siteDir);

    await withZeroserve(tarPath, async (baseUrl) => {
      const res = await fetch(`${baseUrl}/`);
      assertEquals(res.status, 200);
      const body = await res.text();
      assertEquals(body, "<!doctype html><h1>hello tarball</h1>\n");

      const noteRes = await fetch(`${baseUrl}/docs/note.txt`);
      assertEquals(noteRes.status, 200);
      assertEquals(await noteRes.text(), "docs ok\n");
    });
  } finally {
    if (tarPath) {
      await Deno.remove(tarPath).catch(() => {});
    }
    await Deno.remove(siteDir, { recursive: true }).catch(() => {});
  }
});

Deno.test({
  name: "e2e: plugin scripts run before site scripts and reload",
  ignore: !canRunScripts,
  fn: async () => {
    const pluginDir = await Deno.makeTempDir();
    const replacementPluginDir = await Deno.makeTempDir();
    const siteDir = await Deno.makeTempDir();
    let pluginTarPath: string | null = null;
    let replacementPluginTarPath: string | null = null;
    let siteTarPath: string | null = null;
    let proc: ZeroserveProc | null = null;
    try {
      await writePluginSite(pluginDir, "v1");
      await writePluginSite(replacementPluginDir, "v2");

      await Deno.writeTextFile(join(siteDir, "index.html"), "site\n");
      const siteScriptsDir = join(siteDir, ".zeroserve", "scripts");
      await Deno.mkdir(siteScriptsDir, { recursive: true });
      await Deno.writeTextFile(
        join(siteScriptsDir, "20-site.c"),
        `#include <zeroserve.h>

ZS_ENTRY
zs_u64 entry(void) {
  char path[64];
  zs_req_path(path, sizeof(path));
  if (zs_strcmp(path, "/plugin-order") != 0) {
    return 0;
  }

  char value[32];
  zs_s64 value_len = zs_meta_get(ZS_STR("plugin-order"), value, sizeof(value));
  if (value_len <= 0) {
    zs_respond(500, ZS_STR("plugin did not run first\\n"));
    return 0;
  }
  zs_respond(200, value, value_len);
  return 0;
}
`,
      );

      pluginTarPath = await packSite(pluginDir);
      replacementPluginTarPath = await packSite(replacementPluginDir);
      siteTarPath = await packSite(siteDir);

      proc = await spawnZeroserve([
        "--plugin",
        pluginTarPath,
        siteTarPath,
      ]);
      const port = proc.httpPort;

      await assertPluginVersion(port, "v1");

      await Deno.rename(replacementPluginTarPath, pluginTarPath);
      replacementPluginTarPath = null;
      proc.child.kill("SIGHUP");

      for (let i = 0; i < 30; i++) {
        const exited = await checkExited(proc.statusPromise);
        assert(
          exited === null,
          `zeroserve exited during plugin reload with code ${exited?.code}`,
        );
        const res = await fetch(`http://127.0.0.1:${port}/plugin-order`);
        if (res.status === 200 && await res.text() === "v2") {
          return;
        }
        await delay(100);
      }
      await assertPluginVersion(port, "v2");
    } finally {
      if (proc) {
        await proc.stop();
      }
      if (pluginTarPath) {
        await Deno.remove(pluginTarPath).catch(() => {});
      }
      if (replacementPluginTarPath) {
        await Deno.remove(replacementPluginTarPath).catch(() => {});
      }
      if (siteTarPath) {
        await Deno.remove(siteTarPath).catch(() => {});
      }
      await Deno.remove(pluginDir, { recursive: true }).catch(() => {});
      await Deno.remove(replacementPluginDir, { recursive: true }).catch(
        () => {},
      );
      await Deno.remove(siteDir, { recursive: true }).catch(() => {});
    }
  },
});

Deno.test({
  name: "e2e: plugin directories run before site scripts and hot reload",
  ignore: !canRunScripts,
  fn: async () => {
    const pluginDir = await Deno.makeTempDir();
    const siteDir = await Deno.makeTempDir();
    let siteTarPath: string | null = null;
    let proc: ZeroserveProc | null = null;
    try {
      await writePluginSite(pluginDir, "dir-v1");
      await writePluginOrderSite(siteDir);
      siteTarPath = await packSite(siteDir);

      proc = await spawnZeroserve([
        "--plugin-dir",
        pluginDir,
        siteTarPath,
      ]);
      const port = proc.httpPort;

      await assertPluginVersion(port, "dir-v1");

      await writePluginSite(pluginDir, "dir-v2");
      proc.child.kill("SIGHUP");
      await waitForPluginVersion(proc, "dir-v2", "plugin directory reload");

      await Deno.writeTextFile(
        join(pluginDir, ".zeroserve", "scripts", "10-plugin.c"),
        "this is not valid C\n",
      );
      proc.child.kill("SIGHUP");
      for (let i = 0; i < 20; i++) {
        const exited = await checkExited(proc.statusPromise);
        assert(
          exited === null,
          `zeroserve exited during failed plugin directory reload with code ${exited?.code}`,
        );
        await assertPluginVersion(port, "dir-v2");
        await delay(100);
      }
    } finally {
      if (proc) {
        await proc.stop();
      }
      if (siteTarPath) {
        await Deno.remove(siteTarPath).catch(() => {});
      }
      await Deno.remove(pluginDir, { recursive: true }).catch(() => {});
      await Deno.remove(siteDir, { recursive: true }).catch(() => {});
    }
  },
});

Deno.test({
  name: "e2e: direct script objects load as plugins and site and reload",
  ignore: !canRunScripts,
  fn: async () => {
    const tempDir = await Deno.makeTempDir();
    const pluginPath = join(tempDir, "10-plugin.o");
    const replacementPluginPath = join(tempDir, "10-plugin-v2.o");
    const sitePath = join(tempDir, "20-site.o");
    const replacementSitePath = join(tempDir, "20-site-v2.o");
    let proc: ZeroserveProc | null = null;
    try {
      await compileScriptObject(pluginObjectSource("plugin-v1"), pluginPath);
      await compileScriptObject(
        pluginObjectSource("plugin-v2"),
        replacementPluginPath,
      );
      await compileScriptObject(siteObjectSource("site-v1"), sitePath);
      await compileScriptObject(siteObjectSource("site-v2"), replacementSitePath);

      proc = await spawnZeroserve(["--plugin", pluginPath, sitePath], {
        quiet: true,
      });
      const port = proc.httpPort;

      await assertDirectObjectResponse(port, "site-v1:plugin-v1");

      await Deno.rename(replacementPluginPath, pluginPath);
      proc.child.kill("SIGHUP");
      await waitForDirectObjectResponse(
        proc,
        "site-v1:plugin-v2",
        "plugin object reload",
      );

      await Deno.rename(replacementSitePath, sitePath);
      proc.child.kill("SIGHUP");
      await waitForDirectObjectResponse(
        proc,
        "site-v2:plugin-v2",
        "site object reload",
      );

      await Deno.writeTextFile(sitePath, "not an elf object\n");
      proc.child.kill("SIGHUP");
      for (let i = 0; i < 20; i++) {
        const exited = await checkExited(proc.statusPromise);
        assert(
          exited === null,
          `zeroserve exited during failed site object reload with code ${exited?.code}`,
        );
        await assertDirectObjectResponse(port, "site-v2:plugin-v2");
        await delay(100);
      }
    } finally {
      if (proc) {
        await proc.stop();
      }
      await Deno.remove(tempDir, { recursive: true }).catch(() => {});
    }
  },
});

Deno.test({
  name: "e2e: direct C scripts compile as plugins and site and reload",
  ignore: !canRunScripts,
  fn: async () => {
    const tempDir = await Deno.makeTempDir();
    const pluginPath = join(tempDir, "10-plugin.c");
    const sitePath = join(tempDir, "20-site.c");
    let proc: ZeroserveProc | null = null;
    try {
      await Deno.writeTextFile(pluginPath, pluginObjectSource("plugin-c-v1"));
      await Deno.writeTextFile(sitePath, siteObjectSource("site-c-v1"));

      proc = await spawnZeroserve(["--plugin", pluginPath, sitePath], {
        quiet: true,
      });
      const port = proc.httpPort;

      await assertDirectObjectResponse(port, "site-c-v1:plugin-c-v1");

      await Deno.writeTextFile(pluginPath, pluginObjectSource("plugin-c-v2"));
      proc.child.kill("SIGHUP");
      await waitForDirectObjectResponse(
        proc,
        "site-c-v1:plugin-c-v2",
        "plugin C reload",
      );

      await Deno.writeTextFile(sitePath, siteObjectSource("site-c-v2"));
      proc.child.kill("SIGHUP");
      await waitForDirectObjectResponse(
        proc,
        "site-c-v2:plugin-c-v2",
        "site C reload",
      );

      await Deno.writeTextFile(sitePath, "this is not valid C\n");
      proc.child.kill("SIGHUP");
      for (let i = 0; i < 20; i++) {
        const exited = await checkExited(proc.statusPromise);
        assert(
          exited === null,
          `zeroserve exited during failed site C reload with code ${exited?.code}`,
        );
        await assertDirectObjectResponse(port, "site-c-v2:plugin-c-v2");
        await delay(100);
      }
    } finally {
      if (proc) {
        await proc.stop();
      }
      await Deno.remove(tempDir, { recursive: true }).catch(() => {});
    }
  },
});

Deno.test("e2e: refuses to start when a script object fails to load", async () => {
  const siteDir = await Deno.makeTempDir();
  let tarPath: string | null = null;
  try {
    await writeSite(siteDir, "should not start\n", true);
    tarPath = await packSite(siteDir);

    const zeroservePath = await getZeroservePath();
    const child = new Deno.Command(zeroservePath, {
      args: [
        "--addr",
        "127.0.0.1:0",
        "--disable-request-logging",
        tarPath,
      ],
      stdout: "null",
      stderr: "null",
    }).spawn();
    const status = await waitForExit(child, child.status, 3000);

    assert(
      status !== null,
      "zeroserve kept running with an invalid script object",
    );
    assert(
      status.code !== 0,
      "zeroserve exited successfully with an invalid script object",
    );
  } finally {
    if (tarPath) {
      await Deno.remove(tarPath).catch(() => {});
    }
    await Deno.remove(siteDir, { recursive: true }).catch(() => {});
  }
});

Deno.test("e2e: failed script reload keeps serving the previous tarball", async () => {
  const initialSiteDir = await Deno.makeTempDir();
  const replacementSiteDir = await Deno.makeTempDir();
  let tarPath: string | null = null;
  let replacementTarPath: string | null = null;
  let proc: ZeroserveProc | null = null;
  try {
    await writeSite(initialSiteDir, "before reload\n", false);
    await writeSite(replacementSiteDir, "after reload\n", true);
    tarPath = await packSite(initialSiteDir);
    replacementTarPath = await packSite(replacementSiteDir);

    proc = await spawnZeroserve([tarPath], { quiet: true });
    const port = proc.httpPort;

    assertEquals(await fetchText(port), "before reload\n");

    await Deno.rename(replacementTarPath, tarPath);
    replacementTarPath = null;
    proc.child.kill("SIGHUP");

    for (let i = 0; i < 20; i++) {
      const exited = await checkExited(proc.statusPromise);
      assert(
        exited === null,
        `zeroserve exited during reload with code ${exited?.code}`,
      );
      assertEquals(await fetchText(port), "before reload\n");
      await delay(100);
    }
  } finally {
    if (proc) {
      await proc.stop();
    }
    if (tarPath) {
      await Deno.remove(tarPath).catch(() => {});
    }
    if (replacementTarPath) {
      await Deno.remove(replacementTarPath).catch(() => {});
    }
    await Deno.remove(initialSiteDir, { recursive: true }).catch(() => {});
    await Deno.remove(replacementSiteDir, { recursive: true }).catch(() => {});
  }
});

async function writeSite(
  siteDir: string,
  body: string,
  includeInvalidScript: boolean,
): Promise<void> {
  await Deno.writeTextFile(join(siteDir, "index.html"), body);
  if (!includeInvalidScript) {
    return;
  }
  const scriptsDir = join(siteDir, ".zeroserve", "scripts");
  await Deno.mkdir(scriptsDir, { recursive: true });
  await Deno.writeTextFile(
    join(scriptsDir, "10-invalid.o"),
    "not an elf object\n",
  );
}

async function writePluginOrderSite(siteDir: string): Promise<void> {
  await Deno.writeTextFile(join(siteDir, "index.html"), "site\n");
  const siteScriptsDir = join(siteDir, ".zeroserve", "scripts");
  await Deno.mkdir(siteScriptsDir, { recursive: true });
  await Deno.writeTextFile(
    join(siteScriptsDir, "20-site.c"),
    `#include <zeroserve.h>

ZS_ENTRY
zs_u64 entry(void) {
  char path[64];
  zs_req_path(path, sizeof(path));
  if (zs_strcmp(path, "/plugin-order") != 0) {
    return 0;
  }

  char value[32];
  zs_s64 value_len = zs_meta_get(ZS_STR("plugin-order"), value, sizeof(value));
  if (value_len <= 0) {
    zs_respond(500, ZS_STR("plugin did not run first\\n"));
    return 0;
  }
  zs_respond(200, value, value_len);
  return 0;
}
`,
  );
}

async function writePluginSite(
  pluginDir: string,
  version: string,
): Promise<void> {
  await Deno.writeTextFile(join(pluginDir, "plugin.txt"), "plugin\n");
  const pluginScriptsDir = join(pluginDir, ".zeroserve", "scripts");
  await Deno.mkdir(pluginScriptsDir, { recursive: true });
  await Deno.writeTextFile(
    join(pluginScriptsDir, "10-plugin.c"),
    `#include <zeroserve.h>

ZS_ENTRY
zs_u64 entry(void) {
  char path[64];
  zs_req_path(path, sizeof(path));
  if (zs_strcmp(path, "/plugin-order") == 0) {
    zs_meta_set(ZS_STR("plugin-order"), ZS_STR("${version}"));
  }
  return 0;
}
`,
  );
}

function pluginObjectSource(version: string): string {
  return `#include <zeroserve.h>

ZS_ENTRY
zs_u64 entry(void) {
  char path[64];
  zs_req_path(path, sizeof(path));
  if (zs_strcmp(path, "/direct-object") == 0) {
    zs_meta_set(ZS_STR("direct-plugin"), ZS_STR("${version}"));
  }
  return 0;
}
`;
}

function siteObjectSource(version: string): string {
  return `#include <zeroserve.h>

ZS_ENTRY
zs_u64 entry(void) {
  char path[64];
  zs_req_path(path, sizeof(path));
  if (zs_strcmp(path, "/direct-object") != 0) {
    return 0;
  }

  char plugin[32];
  zs_s64 plugin_len = zs_meta_get(ZS_STR("direct-plugin"), plugin, sizeof(plugin));
  if (plugin_len <= 0) {
    zs_respond(500, ZS_STR("plugin did not run\\n"));
    return 0;
  }

  char body[64];
  zs_u64 pos = 0;
  const char prefix[] = "${version}:";
  for (zs_u64 i = 0; i < sizeof(prefix) - 1 && pos < sizeof(body); i++) {
    body[pos++] = prefix[i];
  }
  for (zs_u64 i = 0; i < 32 && i < (zs_u64)plugin_len && pos < sizeof(body); i++) {
    body[pos++] = plugin[i];
  }
  zs_respond(200, body, pos);
  return 0;
}
`;
}

async function assertDirectObjectResponse(
  port: number,
  expected: string,
): Promise<void> {
  const res = await fetch(`http://127.0.0.1:${port}/direct-object`);
  assertEquals(res.status, 200);
  assertEquals(await res.text(), expected);
}

async function waitForDirectObjectResponse(
  proc: ZeroserveProc,
  expected: string,
  label: string,
): Promise<void> {
  for (let i = 0; i < 30; i++) {
    const exited = await checkExited(proc.statusPromise);
    assert(
      exited === null,
      `zeroserve exited during ${label} with code ${exited?.code}`,
    );
    const res = await fetch(`http://127.0.0.1:${proc.httpPort}/direct-object`);
    if (res.status === 200 && await res.text() === expected) {
      return;
    }
    await delay(100);
  }
  await assertDirectObjectResponse(proc.httpPort, expected);
}

async function assertPluginVersion(
  port: number,
  version: string,
): Promise<void> {
  const res = await fetch(`http://127.0.0.1:${port}/plugin-order`);
  assertEquals(res.status, 200);
  assertEquals(await res.text(), version);
}

async function waitForPluginVersion(
  proc: ZeroserveProc,
  expected: string,
  label: string,
): Promise<void> {
  for (let i = 0; i < 30; i++) {
    const exited = await checkExited(proc.statusPromise);
    assert(
      exited === null,
      `zeroserve exited during ${label} with code ${exited?.code}`,
    );
    const res = await fetch(`http://127.0.0.1:${proc.httpPort}/plugin-order`);
    if (res.status === 200 && await res.text() === expected) {
      return;
    }
    await delay(100);
  }
  await assertPluginVersion(proc.httpPort, expected);
}

async function fetchText(port: number): Promise<string> {
  const res = await fetch(`http://127.0.0.1:${port}/`);
  assertEquals(res.status, 200);
  return await res.text();
}

async function waitForExit(
  child: Deno.ChildProcess,
  statusPromise: Promise<Deno.CommandStatus>,
  timeoutMs: number,
): Promise<Deno.CommandStatus | null> {
  const status = await raceWithTimeout(statusPromise, timeoutMs);
  if (status) {
    return status;
  }

  try {
    child.kill("SIGKILL");
  } catch {
    return null;
  }
  await statusPromise;
  return null;
}
