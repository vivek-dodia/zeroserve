import { assert, assertEquals } from "@std/assert";
import { join } from "@std/path";
import {
  checkExited,
  delay,
  getFreePort,
  getZeroservePath,
  packSite,
  raceWithTimeout,
  stopProcess,
  waitForServer,
  withZeroserve,
} from "./test_utils.ts";

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
  let child: Deno.ChildProcess | null = null;
  let statusPromise: Promise<Deno.CommandStatus> | null = null;
  try {
    await writeSite(initialSiteDir, "before reload\n", false);
    await writeSite(replacementSiteDir, "after reload\n", true);
    tarPath = await packSite(initialSiteDir);
    replacementTarPath = await packSite(replacementSiteDir);

    const zeroservePath = await getZeroservePath();
    const port = await getFreePort();
    child = new Deno.Command(zeroservePath, {
      args: [
        "--addr",
        `127.0.0.1:${port}`,
        "--disable-request-logging",
        tarPath,
      ],
      stdout: "null",
      stderr: "null",
    }).spawn();
    statusPromise = child.status;

    await waitForServer("127.0.0.1", port, statusPromise);
    assertEquals(await fetchText(port), "before reload\n");

    await Deno.rename(replacementTarPath, tarPath);
    replacementTarPath = null;
    child.kill("SIGHUP");

    for (let i = 0; i < 20; i++) {
      const exited = await checkExited(statusPromise);
      assert(
        exited === null,
        `zeroserve exited during reload with code ${exited?.code}`,
      );
      assertEquals(await fetchText(port), "before reload\n");
      await delay(100);
    }
  } finally {
    if (child && statusPromise) {
      await stopProcess(child, statusPromise);
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
