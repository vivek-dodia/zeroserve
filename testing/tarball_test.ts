import { assertEquals } from "@std/assert";
import { join } from "@std/path";
import { packSite, withZeroserve } from "./test_utils.ts";

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
