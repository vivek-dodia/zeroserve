import { assert, assertEquals } from "@std/assert";
import { join } from "@std/path";
import {
  checkExited,
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

async function assertPluginVersion(
  port: number,
  version: string,
): Promise<void> {
  const res = await fetch(`http://127.0.0.1:${port}/plugin-order`);
  assertEquals(res.status, 200);
  assertEquals(await res.text(), version);
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
