import { assertEquals } from "@std/assert";
import { dirname, join } from "@std/path";
import {
  getFreePort,
  getZeroservePath,
  hasBpfToolchain,
  packSite,
  repoRoot,
  stopProcess,
  waitForServer,
  withZeroserve,
} from "./test_utils.ts";

const decoder = new TextDecoder();
const canRunScripts = await hasBpfToolchain();
// The Caddy binary to compare against. Override with CADDY_BIN to pin a
// specific build (CI pins a known-good commit; see .github/workflows/ci.yml).
const caddyBin = Deno.env.get("CADDY_BIN") ?? "caddy";
const canRunCaddy = await hasCommand(caddyBin);

type Probe = {
  path: string;
  method?: string;
  headers?: Record<string, string>;
  body?: BodyInit;
  redirect?: RequestRedirect;
  compareHeaders?: string[];
  compareBody?: boolean;
  normalizeBrowseJson?: boolean;
  // Compare only the number of browse entries, not which ones. `file_limit`
  // truncates "in directory order" (per Caddy), and Caddy reads from disk while
  // zeroserve reads from the packed tarball, so the two backends legitimately
  // pick different subsets; only the count is deterministic across them.
  normalizeBrowseCount?: boolean;
};

type ObservedResponse = {
  status: number;
  body: string;
  headers: Record<string, string | null>;
};

type GeneratedCase = {
  name: string;
  files: Record<string, string | Uint8Array>;
  prelude?: string;
  site?: string | ((ctx: { upstreamPort: number }) => string);
  fullCaddyfile?:
    | string
    | ((ctx: { caddyPort: number; upstreamPort: number }) => string);
  probes: Probe[] | ((ctx: { upstreamPort: number }) => Probe[]);
  upstream?: boolean;
};

Deno.test({
  name: "e2e: generated Caddyfiles match stock Caddy for supported behavior",
  ignore: !canRunScripts || !canRunCaddy,
  async fn() {
    await compareGeneratedCaddyfile({
      name: "static responses and response headers",
      files: {},
      site: `
  header /ok X-Route ok
  respond /ok "ok" 201
  respond "fallback" 404
`,
      probes: [
        {
          path: "/ok",
          compareHeaders: ["x-route"],
        },
        {
          path: "/missing",
        },
      ],
    });

    await compareGeneratedCaddyfile({
      name: "URI strip-prefix rewrite before route matching",
      files: {},
      site: `
  uri /rewrite/* strip_prefix /rewrite
  respond /old "rewritten" 202
  respond "fallback" 404
`,
      probes: [
        {
          path: "/rewrite/old?from=test",
        },
        {
          path: "/rewrite/other",
        },
      ],
    });

    // Ported from Caddy's caddytest/integration/caddyfile_adapt/method_directive.caddyfiletest.
    await compareGeneratedCaddyfile({
      name: "Caddy method directive fixture",
      files: {},
      site: `
  method FOO
  respond "{http.request.method}|{http.request.orig_method}"
`,
      probes: [
        {
          path: "/method",
        },
        {
          path: "/method",
          method: "POST",
        },
      ],
    });

    // Ported from Caddy's caddytest/integration/caddyfile_adapt/rewrite_directive_permutations.caddyfiletest.
    await compareGeneratedCaddyfile({
      name: "Caddy rewrite explicit wildcard fixture",
      files: {},
      site: `
  rewrite * /a
  respond "{uri}"
`,
      probes: [
        {
          path: "/before?x=1",
        },
      ],
    });

    // Ported from Caddy's caddytest/integration/caddyfile_adapt/rewrite_directive_permutations.caddyfiletest.
    await compareGeneratedCaddyfile({
      name: "Caddy rewrite path matcher fixture",
      files: {},
      site: `
  rewrite /path /b
  respond "{uri}"
`,
      probes: [
        {
          path: "/path?x=1",
        },
        {
          path: "/other?x=1",
        },
      ],
    });

    // Ported from Caddy's caddytest/integration/caddyfile_adapt/rewrite_directive_permutations.caddyfiletest.
    await compareGeneratedCaddyfile({
      name: "Caddy rewrite named matcher fixture",
      files: {},
      site: `
  @named method GET
  rewrite @named /c
  respond "{uri}"
`,
      probes: [
        {
          path: "/before?x=1",
        },
        {
          path: "/before?x=1",
          method: "POST",
        },
      ],
    });

    // Ported from Caddy's caddytest/integration/caddyfile_adapt/rewrite_directive_permutations.caddyfiletest.
    await compareGeneratedCaddyfile({
      name: "Caddy rewrite implicit wildcard fixture",
      files: {},
      site: `
  rewrite /d
  respond "{uri}"
`,
      probes: [
        {
          path: "/before?x=1",
        },
      ],
    });

    // Ported from Caddy's caddytest/integration/caddyfile_adapt/root_directive_permutations.caddyfiletest.
    await compareGeneratedCaddyfile({
      name: "Caddy root directive permutations fixture",
      files: {},
      site: `
  route {
    root * /a
  }

  route {
    root /path /b
  }

  route {
    @named method GET
    root @named /c
  }

  route {
    root /d
  }

  respond "{http.vars.root}"
`,
      probes: [
        {
          path: "/other",
        },
        {
          path: "/path",
        },
        {
          path: "/path",
          method: "POST",
        },
      ],
    });

    // Adapted from Caddy's caddytest/integration/caddyfile_adapt/import_args_file.caddyfiletest.
    await compareGeneratedCaddyfile({
      name: "Caddy file import args fixture",
      files: {
        "testdata/import_respond.txt":
          `respond /{args[0]} "'I am {args[1]}', hears {args[2]}"`,
      },
      site: `
  import testdata/import_respond.txt groot Groot Rocket
  import testdata/import_respond.txt you you "the confused man"
`,
      probes: [
        {
          path: "/groot",
        },
        {
          path: "/you",
        },
      ],
    });

    // Ported from Caddy's caddytest/integration/caddyfile_adapt/import_block_snippet.caddyfiletest.
    await compareGeneratedCaddyfile({
      name: "Caddy snippet block import fixture",
      files: {},
      prelude: `
(block_snippet) {
  header {
    {block}
  }
}
`,
      site: `
  import block_snippet {
    foo bar
  }
  respond "ok"
`,
      probes: [
        {
          path: "/snippet-block",
          compareHeaders: ["foo"],
        },
      ],
    });

    // Ported from Caddy's caddytest/integration/caddyfile_adapt/import_block_snippet_args.caddyfiletest.
    await compareGeneratedCaddyfile({
      name: "Caddy direct snippet block import fixture",
      files: {},
      prelude: `
(direct_block_snippet) {
  {block}
}
`,
      site: `
  import direct_block_snippet {
    header foo bar
  }
  respond "ok"
`,
      probes: [
        {
          path: "/direct-snippet-block",
          compareHeaders: ["foo"],
        },
      ],
    });

    // Ported from Caddy's caddytest/integration/caddyfile_adapt/import_block_snippet_non_replaced_block.caddyfiletest.
    await compareGeneratedCaddyfile({
      name: "Caddy unused snippet block placeholder fixture",
      files: {},
      prelude: `
(unused_block_snippet) {
  header {
    reverse_proxy localhost:3000
    {block}
  }
}
`,
      site: `
  import unused_block_snippet
  respond "ok"
`,
      probes: [
        {
          path: "/unused-snippet-block",
          compareHeaders: ["reverse-proxy"],
        },
      ],
    });

    // Ported from Caddy's caddytest/integration/caddyfile_adapt/import_block_snippet_non_replaced_block_from_separate_file.caddyfiletest.
    await compareGeneratedCaddyfile({
      name: "Caddy unused imported-file snippet block placeholder fixture",
      files: {
        "snippet.conf": `
(snippet) {
  header {
    reverse_proxy localhost:3000
    {block}
  }
}
`,
      },
      prelude: `
import snippet.conf
`,
      site: `
  import snippet
  respond "ok"
`,
      probes: [
        {
          path: "/unused-file-snippet-block",
          compareHeaders: ["reverse-proxy"],
        },
      ],
    });

    // Ported from Caddy's caddytest/integration/caddyfile_adapt/import_block_snippet_non_replaced_key_block.caddyfiletest.
    await compareGeneratedCaddyfile({
      name: "Caddy unused named snippet block placeholder fixture",
      files: {},
      prelude: `
(unused_named_block_snippet) {
  header {
    reverse_proxy localhost:3000
    {blocks.content_type}
  }
}
`,
      site: `
  import unused_named_block_snippet
  respond "ok"
`,
      probes: [
        {
          path: "/unused-named-snippet-block",
          compareHeaders: ["reverse-proxy"],
        },
      ],
    });

    // Ported from Caddy's caddytest/integration/caddyfile_adapt/import_blocks_snippet.caddyfiletest.
    await compareGeneratedCaddyfile({
      name: "Caddy snippet named blocks import fixture",
      files: {},
      prelude: `
(blocks_snippet) {
  header {
    {blocks.foo}
  }
  header {
    {blocks.bar}
  }
}
`,
      site: `
  import blocks_snippet {
    foo {
      foo a
    }
    bar {
      bar b
    }
  }
  respond "ok"
`,
      probes: [
        {
          path: "/snippet-blocks",
          compareHeaders: ["foo", "bar"],
        },
      ],
    });

    // Ported from Caddy's caddytest/integration/caddyfile_adapt/import_blocks_snippet_nested.caddyfiletest.
    await compareGeneratedCaddyfile({
      name: "Caddy nested snippet named blocks import fixture",
      files: {},
      prelude: `
(nested_blocks_snippet) {
  header {
    {blocks.bar}
  }
  import nested_sub_snippet {
    bar {
      {blocks.foo}
    }
  }
}

(nested_sub_snippet) {
  header {
    {blocks.bar}
  }
}
`,
      site: `
  import nested_blocks_snippet {
    foo {
      foo a
    }
    bar {
      bar b
    }
  }
  respond "ok"
`,
      probes: [
        {
          path: "/snippet-nested-blocks",
          compareHeaders: ["foo", "bar"],
        },
      ],
    });

    // Adapted from Caddy's caddytest/integration/caddyfile_adapt/import_block_with_site_block.caddyfiletest.
    await compareGeneratedCaddyfile({
      name: "Caddy top-level site block import fixture",
      files: {},
      fullCaddyfile: ({ caddyPort }) =>
        `{
  admin off
  auto_https off
}

(site_import) {
  :{args[0]} {
    {block}
  }
}

import site_import ${caddyPort} {
  header X-Imported-Site yes
  respond "top-level import"
}
`,
      probes: [
        {
          path: "/top-level-import",
          compareHeaders: ["x-imported-site"],
        },
      ],
    });

    // Ported from Caddy's caddytest/integration/caddyfile_adapt/heredoc.caddyfiletest.
    await compareGeneratedCaddyfile({
      name: "Caddy heredoc fixture",
      files: {},
      site: `
  respond /heredoc <<EOF
    <html>
      <head><title>Foo</title>
      <body>Foo</body>
    </html>
    EOF 200
`,
      probes: [
        {
          path: "/heredoc",
        },
      ],
    });

    // Ported from Caddy's caddytest/integration/caddyfile_adapt/heredoc_extra_indentation.caddyfiletest.
    await compareGeneratedCaddyfile({
      name: "Caddy heredoc extra indentation fixture",
      files: {},
      site: `
  handle /heredoc-indent {
    respond <<END
        line1
        line2
  END
  }
`,
      probes: [
        {
          path: "/heredoc-indent",
        },
      ],
    });

    // Ported from Caddy's caddytest/integration/caddyfile_adapt/handle_path.caddyfiletest.
    await compareGeneratedCaddyfile({
      name: "Caddy handle_path fixture",
      files: {},
      site: `
  handle_path /api/v1/* {
    respond "API v1 {uri}"
  }
`,
      probes: [
        {
          path: "/api/v1/users?id=1",
        },
        {
          path: "/api/v2/users",
        },
      ],
    });

    // Ported from Caddy's caddytest/integration/caddyfile_adapt/handle_path_sorting.caddyfiletest.
    await compareGeneratedCaddyfile({
      name: "Caddy handle_path sorting fixture",
      files: {},
      site: `
  handle /api/* {
    respond "api {uri}"
  }

  handle_path /static/* {
    respond "static {uri}"
  }

  handle {
    respond "handle {uri}"
  }
`,
      probes: [
        {
          path: "/static/app.css?x=1",
        },
        {
          path: "/api/users",
        },
        {
          path: "/other",
        },
      ],
    });

    // Ported from Caddy's caddytest/integration/caddyfile_adapt/handle_nested_in_route.caddyfiletest.
    await compareGeneratedCaddyfile({
      name: "Caddy nested handle in route fixture",
      files: {},
      site: `
  route {
    handle /foo/* {
      respond "Foo"
    }
    handle {
      respond "Bar"
    }
  }
`,
      probes: [
        {
          path: "/foo/item",
        },
        {
          path: "/other",
        },
      ],
    });

    // Ported from Caddy's caddytest/integration/caddyfile_adapt/matchers_in_route.caddyfiletest.
    await compareGeneratedCaddyfile({
      name: "Caddy unused matchers in route fixture",
      files: {},
      site: `
  route {
    @matcher1 path /path1
    @matcher2 path /path2
  }
`,
      probes: [
        {
          path: "/path1",
        },
        {
          path: "/path2",
        },
      ],
    });

    // Adapted from Caddy's caddytest/integration/caddyfile_adapt/invoke_named_routes.caddyfiletest.
    await compareGeneratedCaddyfile({
      name: "Caddy invoke named routes fixture",
      files: {},
      prelude: `
&(first) {
  @first path /first
  vars @first first 1
  respond "first {http.vars.first}"
}

&(second) {
  respond "second"
}
`,
      site: `
  handle /first {
    invoke first
  }
  handle /second {
    invoke second
  }
  respond "no invoke"
`,
      probes: [
        {
          path: "/first",
        },
        {
          path: "/second",
        },
        {
          path: "/other",
        },
      ],
    });

    // Ported from Caddy's caddytest/integration/caddyfile_adapt/sort_directives_within_handle.caddyfiletest.
    await compareGeneratedCaddyfile({
      name: "Caddy nested handle directive sorting fixture",
      files: {},
      site: `
  @foo host foo.example.com
  handle @foo {
    handle_path /strip {
      respond "this should be first"
    }
    handle_path /strip* {
      respond "this should be second"
    }
    handle {
      respond "this should be last"
    }
  }
  handle {
    respond "this should be last"
  }
`,
      probes: [
        {
          path: "/strip",
          headers: { Host: "foo.example.com" },
        },
        {
          path: "/strip/more",
          headers: { Host: "foo.example.com" },
        },
        {
          path: "/other",
          headers: { Host: "foo.example.com" },
        },
        {
          path: "/strip",
          headers: { Host: "bar.example.com" },
        },
      ],
    });

    // Adapted from Caddy's caddytest/integration/caddyfile_adapt/site_block_sorting.caddyfiletest.
    await compareGeneratedCaddyfile({
      name: "Caddy site block sorting fixture",
      files: {},
      fullCaddyfile: ({ caddyPort }) =>
        `{
  admin off
  auto_https off
}

http://abcdef:${caddyPort} {
  respond "abcdef"
}

http://abcdefg:${caddyPort} {
  respond "abcdefg"
}

http://abc:${caddyPort} {
  respond "abc"
}

http://abcde:${caddyPort} {
  respond "abcde"
}

:${caddyPort}, http://ab:${caddyPort} {
  respond "port or ab"
}
`,
      probes: [
        {
          path: "/",
          headers: { Host: "abcdefg" },
        },
        {
          path: "/",
          headers: { Host: "abcdef" },
        },
        {
          path: "/",
          headers: { Host: "abcde" },
        },
        {
          path: "/",
          headers: { Host: "abc" },
        },
        {
          path: "/",
          headers: { Host: "ab" },
        },
        {
          path: "/",
          headers: { Host: "unknown" },
        },
      ],
    });

    // Ported from Caddy's caddytest/integration/caddyfile_adapt/sort_directives_with_any_matcher_first.caddyfiletest.
    await compareGeneratedCaddyfile({
      name: "Caddy matched response sorted before catch-all fixture",
      files: {},
      site: `
  respond 200

  @untrusted not remote_ip 10.1.1.0/24
  respond @untrusted 401
`,
      probes: [
        {
          path: "/sorted",
        },
      ],
    });

    // Ported from Caddy's caddytest/integration/caddyfile_adapt/not_block_merging.caddyfiletest.
    await compareGeneratedCaddyfile({
      name: "Caddy not block merging fixture",
      files: {},
      site: `
  @test {
    not {
      header Abc "123"
      header Bcd "123"
    }
  }
  respond @test 403
`,
      probes: [
        {
          path: "/not",
        },
        {
          path: "/not",
          headers: { Abc: "123" },
        },
        {
          path: "/not",
          headers: { Abc: "123", Bcd: "123" },
        },
      ],
    });

    // Ported from Caddy's caddytest/integration/caddyfile_adapt/uri_query_operations.caddyfiletest.
    await compareGeneratedCaddyfile({
      name: "Caddy uri query operations fixture",
      files: {},
      site: `
  uri query +foo bar
  uri query -baz
  uri query taz test
  uri query key=value example
  uri query changethis>changed
  uri query {
    findme value replacement
    +foo1 baz
  }

  respond "{query}"
`,
      probes: [
        {
          path: "/query?foo=orig&baz=remove&changethis=old&findme=value",
        },
        {
          path: "/query?findme=prevaluepost&other=1",
        },
      ],
    });

    // Ported from Caddy's caddytest/integration/caddyfile_test.go::TestUriReplace.
    await compareGeneratedCaddyfile({
      name: "Caddy integration TestUriReplace",
      files: {},
      site: `
  uri replace "\\}" %7D
  uri replace "\\{" %7B

  respond "{query}"
`,
      probes: [
        {
          path: "/endpoint?test={%20content%20}",
        },
      ],
    });

    // Ported from Caddy's caddytest/integration/caddyfile_test.go::TestUriOps.
    await compareGeneratedCaddyfile({
      name: "Caddy integration TestUriOps",
      files: {},
      site: `
  uri query +foo bar
  uri query -baz
  uri query taz test
  uri query key=value example
  uri query changethis>changed

  respond "{query}"
`,
      probes: [
        {
          path: "/endpoint?foo=bar0&baz=buz&taz=nottest&changethis=val",
        },
      ],
    });

    // Ported from Caddy's caddytest/integration/caddyfile_test.go::TestSetThenAddQueryParams.
    await compareGeneratedCaddyfile({
      name: "Caddy integration TestSetThenAddQueryParams",
      files: {},
      site: `
  uri query foo bar
  uri query +foo baz

  respond "{query}"
`,
      probes: [
        {
          path: "/endpoint",
        },
      ],
    });

    // Ported from Caddy's caddytest/integration/caddyfile_test.go::TestSetThenDeleteParams.
    await compareGeneratedCaddyfile({
      name: "Caddy integration TestSetThenDeleteParams",
      files: {},
      site: `
  uri query bar foo{query.foo}
  uri query -foo

  respond "{query}"
`,
      probes: [
        {
          path: "/endpoint?foo=bar",
        },
      ],
    });

    // Ported from Caddy's caddytest/integration/caddyfile_test.go::TestRenameAndOtherOps.
    await compareGeneratedCaddyfile({
      name: "Caddy integration TestRenameAndOtherOps",
      files: {},
      site: `
  uri query foo>bar
  uri query bar taz
  uri query +bar baz

  respond "{query}"
`,
      probes: [
        {
          path: "/endpoint?foo=bar",
        },
      ],
    });

    // Ported from Caddy's caddytest/integration/caddyfile_test.go::TestReplaceOps.
    await compareGeneratedCaddyfile({
      name: "Caddy integration TestReplaceOps",
      files: {},
      site: `
  uri query foo bar baz

  respond "{query}"
`,
      probes: [
        {
          path: "/endpoint?foo=bar",
        },
      ],
    });

    // Ported from Caddy's caddytest/integration/caddyfile_test.go::TestReplaceWithReplacementPlaceholder.
    await compareGeneratedCaddyfile({
      name: "Caddy integration TestReplaceWithReplacementPlaceholder",
      files: {},
      site: `
  uri query foo bar {query.placeholder}

  respond "{query}"
`,
      probes: [
        {
          path: "/endpoint?placeholder=baz&foo=bar",
        },
      ],
    });

    // Ported from Caddy's caddytest/integration/caddyfile_test.go::TestReplaceWithKeyPlaceholder.
    await compareGeneratedCaddyfile({
      name: "Caddy integration TestReplaceWithKeyPlaceholder",
      files: {},
      site: `
  uri query {query.placeholder} bar baz

  respond "{query}"
`,
      probes: [
        {
          path: "/endpoint?placeholder=foo&foo=bar",
        },
      ],
    });

    // Ported from Caddy's caddytest/integration/caddyfile_test.go::TestPartialReplacement.
    await compareGeneratedCaddyfile({
      name: "Caddy integration TestPartialReplacement",
      files: {},
      site: `
  uri query foo ar az

  respond "{query}"
`,
      probes: [
        {
          path: "/endpoint?foo=bar",
        },
      ],
    });

    // Ported from Caddy's caddytest/integration/caddyfile_test.go::TestNonExistingSearch.
    await compareGeneratedCaddyfile({
      name: "Caddy integration TestNonExistingSearch",
      files: {},
      site: `
  uri query foo var baz

  respond "{query}"
`,
      probes: [
        {
          path: "/endpoint?foo=bar",
        },
      ],
    });

    // Ported from Caddy's caddytest/integration/caddyfile_test.go::TestReplaceAllOps.
    await compareGeneratedCaddyfile({
      name: "Caddy integration TestReplaceAllOps",
      files: {},
      site: `
  uri query * bar baz

  respond "{query}"
`,
      probes: [
        {
          path: "/endpoint?foo=bar&baz=bar",
        },
      ],
    });

    // Ported from Caddy's caddytest/integration/caddyfile_test.go::TestUriOpsBlock.
    await compareGeneratedCaddyfile({
      name: "Caddy integration TestUriOpsBlock",
      files: {},
      site: `
  uri query {
    +foo bar
    -baz
    taz test
  }

  respond "{query}"
`,
      probes: [
        {
          path: "/endpoint?foo=bar0&baz=buz&taz=nottest",
        },
      ],
    });

    // Ported from Caddy's caddytest/integration/caddyfile_adapt/request_header.caddyfiletest.
    await compareGeneratedCaddyfile({
      name: "Caddy request_header fixture",
      files: {},
      site: `
  @matcher path /something*
  request_header @matcher Denis "Ritchie"

  request_header +Edsger "Dijkstra"
  request_header -Wolfram

  @images path /images/*
  request_header @images Cache-Control "public, max-age=3600, stale-while-revalidate=86400"

  respond "{http.request.header.Denis}|{http.request.header.Edsger}|{http.request.header.Wolfram}|{http.request.header.Cache-Control}"
`,
      probes: [
        {
          path: "/something",
          headers: { Wolfram: "Mathematica" },
        },
        {
          path: "/images/logo.png",
          headers: { Wolfram: "Mathematica" },
        },
        {
          path: "/other",
          headers: { Wolfram: "Mathematica" },
        },
      ],
    });

    // Ported from Caddy's caddytest/integration/caddyfile_adapt/header.caddyfiletest.
    await compareGeneratedCaddyfile({
      name: "Caddy header fixture",
      files: {},
      site: `
  header Denis "Ritchie"
  header +Edsger "Dijkstra"
  header ?John "von Neumann"
  header -Wolfram
  header {
    Grace: "Hopper"
    +Ray "Solomonoff"
    ?Tim "Berners-Lee"
    defer
  }
  @images path /images/*
  header @images {
    Cache-Control "public, max-age=3600, stale-while-revalidate=86400"
    match {
      status 200
    }
  }
  header {
    +Link "Foo"
    +Link "Bar"
    match status 200
  }
  header >Set Defer
  header >Replace Deferred Replacement

  respond "ok"
`,
      probes: [
        {
          path: "/other",
          compareHeaders: [
            "denis",
            "edsger",
            "john",
            "wolfram",
            "grace",
            "ray",
            "tim",
            "link",
            "set",
            "replace",
            "cache-control",
          ],
        },
        {
          path: "/images/logo.png",
          compareHeaders: [
            "denis",
            "edsger",
            "john",
            "wolfram",
            "grace",
            "ray",
            "tim",
            "link",
            "set",
            "replace",
            "cache-control",
          ],
        },
      ],
    });

    // Ported from Caddy's caddytest/integration/caddyfile_adapt/header_placeholder_search.caddyfiletest.
    await compareGeneratedCaddyfile({
      name: "Caddy header placeholder search fixture",
      files: {},
      site: `
  route {
    header Test-Static ":443"
    header Test-Dynamic ":{http.request.local.port}"
    header Test-Complex "port-{http.request.local.port}-end"
    header Test-Static ":443" "STATIC-WORKS"
    header Test-Dynamic ":{http.request.local.port}" "DYNAMIC-WORKS"
    header Test-Complex "port-{http.request.local.port}-end" "COMPLEX-{http.request.method}"
    respond "ok"
  }
`,
      probes: [
        {
          path: "/headers",
          compareHeaders: ["test-static", "test-dynamic", "test-complex"],
        },
        {
          path: "/headers",
          method: "POST",
          compareHeaders: ["test-static", "test-dynamic", "test-complex"],
        },
      ],
    });

    await compareGeneratedCaddyfile({
      name: "try_files fallback with file_server",
      files: {
        "exact.txt": "exact bytes\n",
        "fallback.txt": "fallback bytes\n",
      },
      site: `
  root * .
  try_files {path} /fallback.txt
  file_server
`,
      probes: [
        {
          path: "/exact.txt",
          compareHeaders: ["content-type"],
        },
        {
          path: "/missing.txt",
          compareHeaders: ["content-type"],
        },
      ],
    });

    // Ported from Caddy's caddytest/integration/caddyfile_adapt/file_server_pass_thru.caddyfiletest.
    await compareGeneratedCaddyfile({
      name: "Caddy file_server pass_thru fixture",
      files: {
        "exact.txt": "exact bytes\n",
      },
      site: `
  root * .
  file_server {
    pass_thru
  }
  respond "fallback" 404
`,
      probes: [
        {
          path: "/exact.txt",
          compareHeaders: ["content-type"],
        },
        {
          path: "/missing.txt",
          compareHeaders: ["content-type"],
        },
      ],
    });

    // Ported from Caddy's caddytest/integration/caddyfile_adapt/file_server_status.caddyfiletest.
    await compareGeneratedCaddyfile({
      name: "Caddy file_server status fixture",
      files: {
        "nope.txt": "nope bytes\n",
        "custom-status.txt": "custom status bytes\n",
      },
      site: `
  root * .

  handle /nope* {
    file_server {
      status 403
    }
  }

  handle /custom-status* {
    file_server {
      status 299
    }
  }
`,
      probes: [
        {
          path: "/nope.txt",
          compareHeaders: ["content-type"],
        },
        {
          path: "/custom-status.txt",
          compareHeaders: ["content-type"],
        },
        {
          path: "/nope-missing.txt",
          compareHeaders: ["content-type"],
        },
      ],
    });

    // Ported from Caddy's caddytest/integration/caddyfile_adapt/file_server_disable_canonical_uris.caddyfiletest.
    await compareGeneratedCaddyfile({
      name: "Caddy file_server disable canonical URIs fixture",
      files: {
        "dir/index.html": "directory index\n",
      },
      site: `
  root * .
  file_server {
    disable_canonical_uris
  }
`,
      probes: [
        {
          path: "/dir",
          compareHeaders: ["content-type", "location"],
        },
        {
          path: "/dir/",
          compareHeaders: ["content-type", "location"],
        },
      ],
    });

    // Adapted from Caddy's modules/caddyhttp/fileserver/staticfiles_test.go::TestFileHidden.
    await compareGeneratedCaddyfile({
      name: "Caddy file_server hide matching fixture",
      files: {
        "public/visible.txt": "visible\n",
        "public/secret.secret": "hidden basename glob\n",
        "public/private/nested.txt": "hidden descendant\n",
        "public/private-ish.txt": "visible near miss\n",
        "public/one/blocked.txt": "hidden path glob\n",
        "public/one/allowed.txt": "visible path glob near miss\n",
      },
      site: `
  root * .
  file_server {
    hide *.secret public/private public/*/blocked.txt
  }
`,
      probes: [
        {
          path: "/public/visible.txt",
          compareHeaders: ["content-type"],
        },
        {
          path: "/public/secret.secret",
        },
        {
          path: "/public/private/nested.txt",
        },
        {
          path: "/public/private-ish.txt",
          compareHeaders: ["content-type"],
        },
        {
          path: "/public/one/blocked.txt",
        },
        {
          path: "/public/one/allowed.txt",
          compareHeaders: ["content-type"],
        },
      ],
    });

    // Ported from Caddy's caddytest/integration/caddyfile_adapt/file_server_etag_file_extensions.caddyfiletest.
    await compareGeneratedCaddyfile({
      name: "Caddy file_server etag file extensions fixture",
      files: {
        "asset.txt": "etag body\n",
        "asset.txt.b3sum": "alpha-sidecar",
        "asset.txt.sha256": "beta-sidecar",
      },
      site: `
  root * .
  file_server {
    etag_file_extensions .b3sum .sha256
  }
`,
      probes: [
        {
          path: "/asset.txt",
          compareHeaders: ["content-type", "etag"],
        },
      ],
    });

    await compareGeneratedCaddyfile({
      name: "Caddy file_server ETag preconditions fixture",
      files: {
        "asset.txt": "etag precondition body\n",
        "asset.txt.etag": "stable-sidecar",
      },
      site: `
  root * .
  file_server {
    etag_file_extensions .etag
  }
`,
      probes: [
        {
          path: "/asset.txt",
          headers: { "If-None-Match": `"stable-sidecar"` },
          compareHeaders: ["etag", "last-modified", "content-length"],
        },
        {
          path: "/asset.txt",
          headers: { "If-None-Match": `"other-sidecar"` },
          compareHeaders: ["etag", "last-modified", "content-length"],
        },
        {
          path: "/asset.txt",
          headers: { "If-Match": `"other-sidecar"` },
          compareHeaders: ["etag", "last-modified", "content-length"],
          compareBody: false,
        },
      ],
    });

    // Ported from Caddy's caddytest/integration/caddyfile_adapt/file_server_precompressed.caddyfiletest.
    await compareGeneratedCaddyfile({
      name: "Caddy file_server precompressed explicit order fixture",
      files: {
        "asset.txt": "plain body\n",
        "asset.txt.zst": new TextEncoder().encode("zstd sidecar"),
        "asset.txt.br": new TextEncoder().encode("br sidecar"),
        "asset.txt.gz": new TextEncoder().encode("gzip sidecar"),
      },
      site: `
  root * .
  file_server {
    precompressed zstd br gzip
  }
`,
      probes: [
        {
          path: "/asset.txt",
          headers: { "Accept-Encoding": "gzip, br, zstd" },
          compareHeaders: ["content-encoding", "content-type"],
          compareBody: false,
        },
      ],
    });

    // Ported from Caddy's caddytest/integration/caddyfile_adapt/file_server_precompressed.caddyfiletest.
    await compareGeneratedCaddyfile({
      name: "Caddy file_server precompressed default order fixture",
      files: {
        "asset.txt": "plain body\n",
        "asset.txt.zst": new TextEncoder().encode("zstd sidecar"),
        "asset.txt.br": new TextEncoder().encode("br sidecar"),
        "asset.txt.gz": new TextEncoder().encode("gzip sidecar"),
      },
      site: `
  root * .
  file_server {
    precompressed
  }
`,
      probes: [
        {
          path: "/asset.txt",
          headers: { "Accept-Encoding": "gzip, br, zstd" },
          compareHeaders: ["content-encoding", "content-type"],
          compareBody: false,
        },
      ],
    });

    // Ported from Caddy's caddytest/integration/caddyfile_adapt/file_server_sort.caddyfiletest.
    await compareGeneratedCaddyfile({
      name: "Caddy file_server browse sort fixture",
      files: {
        "public/small.txt": "a",
        "public/medium.txt": "abcd",
        "public/large.txt": "abcdefgh",
      },
      site: `
  root * public
  file_server {
    browse {
      sort size desc
    }
  }
`,
      probes: [
        {
          path: "/",
          headers: { Accept: "application/json" },
          compareHeaders: ["content-type"],
          normalizeBrowseJson: true,
        },
      ],
    });

    // Ported from Caddy's caddytest/integration/caddyfile_adapt/file_server_file_limit.caddyfiletest.
    await compareGeneratedCaddyfile({
      name: "Caddy file_server browse file_limit fixture",
      files: {
        "public/a.txt": "a",
        "public/b.txt": "b",
        "public/c.txt": "c",
      },
      site: `
  root * public
  file_server {
    browse {
      file_limit 2
    }
  }
`,
      probes: [
        {
          path: "/",
          headers: { Accept: "application/json" },
          compareHeaders: ["content-type"],
          normalizeBrowseCount: true,
        },
      ],
    });

    // Ported from Caddy's caddytest/integration/map_test.go::TestMap.
    await compareGeneratedCaddyfile({
      name: "Caddy integration TestMap",
      files: {},
      site: `
  map {http.request.method} {dest-1} {dest-2} {
    default unknown1 unknown2
    ~G(.)(.) G\${1}\${2}-called
    POST post-called foobar
  }

  respond /version 200 {
    body "hello from localhost {dest-1} {dest-2}"
  }
`,
      probes: [
        {
          path: "/version",
        },
        {
          path: "/version",
          method: "POST",
        },
      ],
    });

    // Ported from Caddy's caddytest/integration/map_test.go::TestMapRespondWithDefault.
    await compareGeneratedCaddyfile({
      name: "Caddy integration TestMapRespondWithDefault",
      files: {},
      site: `
  map {http.request.method} {dest-name} {
    default unknown
    GET get-called
  }

  respond /version 200 {
    body "hello from localhost {dest-name}"
  }
`,
      probes: [
        {
          path: "/version",
        },
        {
          path: "/version",
          method: "POST",
        },
      ],
    });

    // Ported from Caddy's caddytest/integration/caddyfile_adapt/map_and_vars_with_raw_types.caddyfiletest.
    await compareGeneratedCaddyfile({
      name: "Caddy map and vars raw types fixture",
      files: {},
      site: `
  map {host} {my_placeholder} {magic_number} {
    example.com true 3
    foo.example.com "string value"
    (.*)\\.example.com "\${1} subdomain" "5"
    ~.*\\.net$ - \`7\`
    ~.*\\.xyz$ 123.456 "false"
    default "unknown domain" \\\\""
  }

  vars foo bar
  vars {
    abc true
    def 1
    ghi 2.3
    jkl "mn op"
  }

  respond "{my_placeholder}|{magic_number}|{http.vars.foo}|{http.vars.abc}|{http.vars.def}|{http.vars.ghi}|{http.vars.jkl}"
`,
      probes: [
        {
          path: "/map",
          headers: { Host: "example.com" },
        },
        {
          path: "/map",
          headers: { Host: "foo.example.com" },
        },
        {
          path: "/map",
          headers: { Host: "bar.example.com" },
        },
        {
          path: "/map",
          headers: { Host: "thing.net" },
        },
        {
          path: "/map",
          headers: { Host: "thing.xyz" },
        },
        {
          path: "/map",
          headers: { Host: "other.test" },
        },
      ],
    });

    // Ported from Caddy's caddytest/integration/caddyfile_adapt/request_body.caddyfiletest.
    await compareGeneratedCaddyfile({
      name: "Caddy request_body max_size fixture",
      files: {},
      site: `
  request_body {
    max_size 8
  }
  respond "accepted"
`,
      probes: [
        {
          path: "/upload",
          method: "POST",
          body: "12345678",
        },
        {
          path: "/upload",
          method: "POST",
          body: "123456789",
          compareBody: false,
        },
      ],
    });

    // Ported from Caddy's caddytest/integration/caddyfile_adapt/sort_vars_in_reverse.caddyfiletest.
    await compareGeneratedCaddyfile({
      name: "Caddy vars route sorting fixture",
      files: {},
      site: `
  vars /foobar foo last
  vars /foo foo middle-last
  vars /foo* foo middle-first
  vars * foo first
  respond "{http.vars.foo}"
`,
      probes: [
        {
          path: "/other",
        },
        {
          path: "/foo/bar",
        },
        {
          path: "/foo",
        },
        {
          path: "/foobar",
        },
      ],
    });

    await compareGeneratedCaddyfile({
      name: "reverse proxy request and response headers",
      files: {},
      upstream: true,
      site: ({ upstreamPort }) => `
  reverse_proxy /proxy-* 127.0.0.1:${upstreamPort} {
    header_up X-Upstream-Token compared
    header_down X-Downstream-Token proxied
  }
  respond "fallback" 404
`,
      probes: [
        {
          path: "/proxy-ok",
          compareHeaders: ["x-backend-token", "x-downstream-token"],
        },
        {
          path: "/proxy-created",
          compareHeaders: ["x-backend-token", "x-downstream-token"],
        },
      ],
    });

    // Adapted from Caddy's caddytest/integration/caddyfile_adapt/reverse_proxy_handle_response.caddyfiletest,
    // limited to status replacement and response-header placeholders because
    // zeroserve intentionally does not implement Caddy response body replacement.
    await compareGeneratedCaddyfile({
      name: "Caddy reverse_proxy response matcher status fixture",
      files: {},
      upstream: true,
      site: ({ upstreamPort }) => `
  reverse_proxy /proxy-* 127.0.0.1:${upstreamPort} {
    @backend {
      status 2xx
      header X-Backend-Token backend
    }
    replace_status @backend 203
    header_down X-Upstream-Status {http.reverse_proxy.status_code}
    header_down X-Upstream-Token {http.reverse_proxy.header.X-Backend-Token}
  }
  respond "fallback" 404
`,
      probes: [
        {
          path: "/proxy-ok",
          compareHeaders: [
            "x-backend-token",
            "x-upstream-status",
            "x-upstream-token",
          ],
        },
        {
          path: "/proxy-created",
          compareHeaders: [
            "x-backend-token",
            "x-upstream-status",
            "x-upstream-token",
          ],
        },
        {
          path: "/other",
          compareHeaders: [
            "x-backend-token",
            "x-upstream-status",
            "x-upstream-token",
          ],
        },
      ],
    });

    // Adapted from Caddy's caddytest/integration/caddyfile_adapt/reverse_proxy_upstream_placeholder.caddyfiletest.
    await compareGeneratedCaddyfile({
      name: "Caddy reverse_proxy upstream placeholder fixture",
      files: {},
      upstream: true,
      site: ({ upstreamPort }) => `
  map {host} {upstream} {
    alpha.example.test 127.0.0.1:${upstreamPort}
    default 127.0.0.1:${upstreamPort}
  }

  @proxied host alpha.example.test beta.example.test
  reverse_proxy @proxied {upstream} {
    header_up X-Upstream-Token placeholder
  }

  redir * http://fallback.example.test{uri}
`,
      probes: [
        {
          path: "/proxy-ok",
          headers: { Host: "alpha.example.test" },
          compareHeaders: ["x-backend-token"],
        },
        {
          path: "/proxy-created",
          headers: { Host: "beta.example.test" },
          compareHeaders: ["x-backend-token"],
        },
        {
          path: "/proxy-ok",
          headers: { Host: "gamma.example.test" },
          redirect: "manual",
          compareHeaders: ["location"],
          compareBody: false,
        },
      ],
    });

    // Adapted from Caddy's caddytest/integration/caddyfile_adapt/replaceable_upstream.caddyfiletest.
    await compareGeneratedCaddyfile({
      name: "Caddy reverse_proxy replaceable upstream fixture",
      files: {},
      upstream: true,
      site: () => `
  @targetUpstream {
    header_regexp target X-Upstream ^(.+)$
  }
  handle @targetUpstream {
    reverse_proxy {re.target.1}
  }
  handle {
    redir {scheme}://application.localhost
  }
`,
      probes: ({ upstreamPort }) => [
        {
          path: "/proxy-ok",
          headers: { "X-Upstream": `127.0.0.1:${upstreamPort}` },
          compareHeaders: ["x-backend-token"],
        },
        {
          path: "/proxy-ok",
          redirect: "manual",
          compareHeaders: ["location"],
          compareBody: false,
        },
      ],
    });

    // Adapted from Caddy's caddytest/integration/caddyfile_adapt/replaceable_upstream_port.caddyfiletest.
    await compareGeneratedCaddyfile({
      name: "Caddy reverse_proxy placeholder port fixture",
      files: {},
      upstream: true,
      site: ({ upstreamPort }) => `
  @sandboxPort {
    header_regexp port Host ^port-([0-9]+)\\.sandbox\\.
  }
  handle @sandboxPort {
    reverse_proxy 127.0.0.1:{re.port.1}
  }
  handle {
    redir {scheme}://application.localhost
  }
`,
      probes: ({ upstreamPort }) => [
        {
          path: "/proxy-ok",
          headers: { Host: `port-${upstreamPort}.sandbox.localhost` },
          compareHeaders: ["x-backend-token"],
        },
        {
          path: "/proxy-ok",
          headers: { Host: "application.localhost" },
          redirect: "manual",
          compareHeaders: ["location"],
          compareBody: false,
        },
      ],
    });

    // Adapted from Caddy's caddytest/integration/caddyfile_adapt/replaceable_upstream_partial_port.caddyfiletest.
    await compareGeneratedCaddyfile({
      name: "Caddy reverse_proxy partial placeholder port fixture",
      files: {},
      upstream: true,
      site: ({ upstreamPort }) => {
        const port = String(upstreamPort);
        return `
  @sandboxPort {
    header_regexp port Host ^port-${port.slice(1)}\\.sandbox\\.
  }
  handle @sandboxPort {
    reverse_proxy 127.0.0.1:${port[0]}{re.port.0}
  }
  handle {
    redir {scheme}://application.localhost
  }
`;
      },
      probes: ({ upstreamPort }) => [
        {
          path: "/proxy-ok",
          headers: {
            Host: `port-${String(upstreamPort).slice(1)}.sandbox.localhost`,
          },
          compareHeaders: ["x-backend-token"],
        },
        {
          path: "/proxy-ok",
          headers: { Host: "application.localhost" },
          redirect: "manual",
          compareHeaders: ["location"],
          compareBody: false,
        },
      ],
    });

    // Adapted from Caddy's caddytest/integration/caddyfile_adapt/forward_auth_copy_headers_strip.caddyfiletest.
    await compareGeneratedCaddyfile({
      name: "Caddy forward_auth copied headers fixture",
      files: {},
      upstream: true,
      site: ({ upstreamPort }) => `
  forward_auth 127.0.0.1:${upstreamPort} {
    uri /auth
    copy_headers X-User-Id X-Empty-Auth
  }
  reverse_proxy 127.0.0.1:${upstreamPort}
`,
      probes: [
        {
          path: "/allowed",
          compareHeaders: ["x-backend-token", "x-seen-user"],
        },
        {
          path: "/denied",
          compareHeaders: ["x-backend-token", "x-seen-user"],
        },
      ],
    });

    // Adapted from Caddy's caddytest/integration/caddyfile_adapt/forward_auth_rename_headers.caddyfiletest.
    await compareGeneratedCaddyfile({
      name: "Caddy forward_auth renamed headers fixture",
      files: {},
      upstream: true,
      site: ({ upstreamPort }) => `
  forward_auth 127.0.0.1:${upstreamPort} {
    uri /auth
    copy_headers X-User-Id>X-Auth-User X-Role
  }
  reverse_proxy 127.0.0.1:${upstreamPort}
`,
      probes: [
        {
          path: "/allowed",
          compareHeaders: [
            "x-backend-token",
            "x-seen-auth-user",
            "x-seen-role",
          ],
        },
      ],
    });

    // Adapted from Caddy's caddytest/integration/intercept_test.go, limited to
    // header-only response hooks because zeroserve intentionally does not
    // rewrite response bodies for Caddy compatibility.
    await compareGeneratedCaddyfile({
      name: "Caddy intercept header response hook fixture",
      files: {},
      site: `
  respond /intercept "tea" 408
  header /intercept To-Intercept ok
  respond /no-intercept "no"

  intercept {
    @teapot status 408
    handle_response @teapot {
      header /intercept Intercepted {http.intercept.header.To-Intercept}
    }
  }
`,
      probes: [
        {
          path: "/intercept",
          compareHeaders: ["to-intercept", "intercepted"],
        },
        {
          path: "/no-intercept",
          compareHeaders: ["intercepted"],
        },
      ],
    });

    // Ported from Caddy's caddytest/integration/caddyfile_adapt/shorthand_parameterized_placeholders.caddyfiletest.
    await compareGeneratedCaddyfile({
      name: "Caddy shorthand parameterized placeholders fixture",
      files: {},
      site: `
  @match path_regexp ^/foo(.*)$
  respond @match "{re.1}"

  respond * "{header.content-type} {labels.0} {query.p} {path.0} {re.name.0}"
`,
      probes: [
        {
          path: "/foo-rest?p=value",
          headers: { "Content-Type": "text/plain", Host: "localhost" },
        },
        {
          path: "/one/two?p=value",
          headers: {
            "Content-Type": "application/json",
            Host: "www.example.test",
          },
        },
      ],
    });

    await compareGeneratedCaddyfile({
      name: "basic auth challenge and user placeholder",
      files: {},
      site: `
  basic_auth /admin/* bcrypt "Admin Area" {
    alice $2a$14$gqs5yvNgSqb/ksrUoam91ewSE1TjpYIgCuaiuZH395DQEPsiCVIei
  }
  respond /admin/* "hello {http.auth.user.id}"
  respond "public"
`,
      probes: [
        {
          path: "/admin/panel",
          compareHeaders: ["www-authenticate"],
        },
        {
          path: "/admin/panel",
          headers: {
            Authorization: `Basic ${btoa("alice:wrong")}`,
          },
          compareHeaders: ["www-authenticate"],
        },
        {
          path: "/admin/panel",
          headers: {
            Authorization: `Basic ${btoa("alice:secret")}`,
          },
          compareHeaders: ["www-authenticate"],
        },
        {
          path: "/public",
        },
      ],
    });

    // Uses Caddy's modules/caddyhttp/caddyauth/argon2id.go FakeHash fixture.
    await compareGeneratedCaddyfile({
      name: "Caddy basic_auth argon2id fixture",
      files: {},
      site: `
  basic_auth /argon/* argon2id "Argon Area" {
    alice $argon2id$v=19$m=47104,t=1,p=1$P2nzckEdTZ3bxCiBCkRTyA$xQL3Z32eo5jKl7u5tcIsnEKObYiyNZQQf5/4sAau6Pg
  }
  respond /argon/* "argon {http.auth.user.id}"
  respond "public"
`,
      probes: [
        {
          path: "/argon/panel",
          compareHeaders: ["www-authenticate"],
        },
        {
          path: "/argon/panel",
          headers: {
            Authorization: `Basic ${btoa("alice:wrong")}`,
          },
          compareHeaders: ["www-authenticate"],
        },
        {
          path: "/argon/panel",
          headers: {
            Authorization: `Basic ${btoa("alice:antitiming")}`,
          },
          compareHeaders: ["www-authenticate"],
        },
        {
          path: "/public",
        },
      ],
    });

    // Ported from Caddy's caddytest/integration/caddyfile_test.go::TestRedirect.
    await compareGeneratedCaddyfile({
      name: "Caddy integration TestRedirect",
      files: {},
      site: `
  redir / /hello 301
  respond /hello 200 {
    body "hello from localhost"
  }
`,
      probes: [
        {
          path: "/",
          redirect: "manual",
          compareHeaders: ["location"],
          compareBody: false,
        },
        {
          path: "/",
          redirect: "follow",
        },
      ],
    });

    await compareGeneratedCaddyfile({
      name: "redirect location and html body",
      files: {},
      site: `
  redir /go/* https://example.test{uri} permanent
  redir /html https://example.org/a?b=<tag> html
  respond "fallback"
`,
      probes: [
        {
          path: "/go/path?x=1",
          compareHeaders: ["location"],
        },
        {
          path: "/html",
          compareHeaders: ["content-type", "location"],
        },
        {
          path: "/other",
        },
      ],
    });

    // Adapted from Caddy's caddytest/integration/caddyfile_adapt/wildcard_pattern.caddyfiletest,
    // limited to HTTP host routing because TLS automation is outside zeroserve's eBPF surface.
    await compareGeneratedCaddyfile({
      name: "Caddy wildcard host routing fixture",
      files: {},
      fullCaddyfile: ({ caddyPort }) =>
        `{
  admin off
  auto_https off
}

http://*.example.test:${caddyPort} {
  @foo host foo.example.test
  handle @foo {
    respond "Foo!"
  }

  @bar host bar.example.test
  handle @bar {
    respond "Bar!"
  }

  handle {
    respond "Fallback" 404
  }
}
`,
      probes: [
        {
          path: "/",
          headers: { Host: "foo.example.test" },
        },
        {
          path: "/",
          headers: { Host: "bar.example.test" },
        },
        {
          path: "/",
          headers: { Host: "baz.example.test" },
        },
        {
          path: "/",
          headers: { Host: "outside.test" },
        },
      ],
    });

    // Ported from Caddy's caddytest/integration/caddyfile_adapt/http_only_hostnames.caddyfiletest.
    await compareGeneratedCaddyfile({
      name: "Caddy HTTP wildcard hostname fixture",
      files: {},
      fullCaddyfile: ({ caddyPort }) =>
        `{
  admin off
  auto_https off
}

http://*:${caddyPort} {
  respond "Hello, world!"
}
`,
      probes: [
        {
          path: "/",
          headers: { Host: "alpha.example.test" },
        },
        {
          path: "/",
          headers: { Host: "beta.localhost" },
        },
      ],
    });

    await compareGeneratedCaddyfile({
      name: "named matchers and regexp placeholders",
      files: {},
      site: `
  @api {
    path_regexp item ^/api/items/([0-9]+)$
    method POST
    query mode=debug
    header X-Mode debug
  }
  respond @api "item {http.regexp.item.1}" 202
  respond "fallback" 404
`,
      probes: [
        {
          path: "/api/items/42?mode=debug",
          method: "POST",
          headers: { "X-Mode": "debug" },
        },
        {
          path: "/api/items/42?mode=release",
          method: "POST",
          headers: { "X-Mode": "debug" },
        },
        {
          path: "/api/items/42?mode=debug",
          method: "GET",
          headers: { "X-Mode": "debug" },
        },
        {
          path: "/api/items/not-number?mode=debug",
          method: "POST",
          headers: { "X-Mode": "debug" },
        },
      ],
    });

    // Adapted from Caddy's caddytest/integration/caddyfile_adapt/expression_quotes.caddyfiletest.
    await compareGeneratedCaddyfile({
      name: "Caddy expression quote forms fixture",
      files: {},
      site: `
  @a expression {http.request.method} == "POST"
  respond @a "double quoted string"

  @c expression "{http.request.method} == \\"DELETE\\""
  respond @c "double quoted expression"

  @d expression \`{http.request.method} == "PATCH"\`
  respond @d "backtick quoted expression"

  @e \`{http.request.method} == "OPTIONS"\`
  respond @e "shorthand backtick expression"

  respond "fallback" 404
`,
      probes: [
        {
          path: "/quotes",
          method: "POST",
        },
        {
          path: "/quotes",
          method: "DELETE",
        },
        {
          path: "/quotes",
          method: "PATCH",
        },
        {
          path: "/quotes",
          method: "OPTIONS",
        },
        {
          path: "/quotes",
          method: "GET",
        },
      ],
    });

    // Ported from Caddy's caddytest/integration/caddyfile_adapt/matcher_syntax.caddyfiletest.
    await compareGeneratedCaddyfile({
      name: "Caddy matcher syntax vars and expressions fixture",
      files: {},
      site: `
  @matcher4 vars "{http.request.uri}" "/vars-matcher"
  respond @matcher4 "from vars matcher"

  @matcher5 vars_regexp static "{http.request.uri}" \`\\.([a-f0-9]{6})\\.(css|js)$\`
  respond @matcher5 "from vars_regexp matcher with name"

  @matcher6 vars_regexp "{http.request.uri}" \`\\.([a-f0-9]{6})\\.(css|js)$\`
  respond @matcher6 "from vars_regexp matcher without name"

  @matcher7 \`path('/foo*') && method('GET')\`
  respond @matcher7 "inline expression matcher shortcut"

  respond "fallback" 404
`,
      probes: [
        {
          path: "/vars-matcher",
          method: "PUT",
        },
        {
          path: "/app.abcdef.css",
          method: "PUT",
        },
        {
          path: "/app.123456.js",
          method: "POST",
        },
        {
          path: "/foo-item",
        },
        {
          path: "/foo-item",
          method: "POST",
        },
      ],
    });

    // Ported from Caddy's caddytest/integration/caddyfile_adapt/matcher_syntax.caddyfiletest.
    await compareGeneratedCaddyfile({
      name: "Caddy matcher syntax merged fields fixture",
      files: {},
      site: `
  @matcher8 {
    header Foo bar
    header Foo foobar
    header Bar foo
  }
  respond @matcher8 "header matcher merging values of the same field"

  @matcher9 {
    query foo=bar foo=baz bar=foo
    query bar=baz
  }
  respond @matcher9 "query matcher merging pairs with the same keys"

  @matcher10 {
    header !Foo
    header Bar foo
  }
  respond @matcher10 "header matcher with null field matcher"

  respond "fallback" 404
`,
      probes: [
        {
          path: "/headers",
          headers: { Foo: "bar", Bar: "foo" },
        },
        {
          path: "/headers",
          headers: { Foo: "foobar", Bar: "foo" },
        },
        {
          path: "/headers",
          headers: { Foo: "nope", Bar: "foo" },
        },
        {
          path: "/query?foo=bar&bar=baz",
        },
        {
          path: "/query?foo=baz&bar=foo",
        },
        {
          path: "/query?foo=nope&bar=foo",
        },
        {
          path: "/null-header",
          headers: { Bar: "foo" },
        },
        {
          path: "/null-header",
          headers: { Foo: "bar", Bar: "foo" },
        },
      ],
    });

    await compareGeneratedCaddyfile({
      name: "deferred response headers inspect file responses",
      files: {
        "asset.txt": "asset bytes\n",
      },
      site: `
  root * .
  header {
    match {
      status 2xx
      header Content-Type text/plain*
    }
    X-Text-File yes
  }
  header {
    match status 404
    X-Not-Found yes
  }
  file_server
`,
      probes: [
        {
          path: "/asset.txt",
          compareHeaders: ["content-type", "x-text-file", "x-not-found"],
        },
        {
          path: "/missing.txt",
          compareHeaders: ["content-type", "x-text-file", "x-not-found"],
        },
      ],
    });

    await compareGeneratedCaddyfile({
      name: "file server misses run handle_errors routes",
      files: {
        "asset.txt": "asset bytes\n",
      },
      site: `
  root * .
  header {
    match status 404
    X-Outer-404 outer
  }
  file_server
  handle_errors {
    header X-Error-Status {err.status_code}
    respond "handled {err.status_code} {err.status_text}" {err.status_code}
  }
`,
      probes: [
        {
          path: "/asset.txt",
          compareHeaders: ["content-type", "x-error-status", "x-outer-404"],
        },
        {
          path: "/missing.txt",
          compareHeaders: ["content-type", "x-error-status", "x-outer-404"],
        },
      ],
    });

    // Ported from Caddy's caddytest/integration/caddyfile_test.go::TestHandleErrorSimpleCodes.
    await compareGeneratedCaddyfile({
      name: "Caddy integration TestHandleErrorSimpleCodes",
      files: {},
      site: `
  error /private* "Unauthorized" 410
  error /hidden* "Not found" 404

  handle_errors 404 410 {
    respond "404 or 410 error"
  }
`,
      probes: [
        {
          path: "/private",
        },
        {
          path: "/hidden",
        },
      ],
    });

    // Ported from Caddy's caddytest/integration/caddyfile_test.go::TestHandleErrorRange.
    await compareGeneratedCaddyfile({
      name: "Caddy integration TestHandleErrorRange",
      files: {},
      site: `
  error /private* "Unauthorized" 410
  error /hidden* "Not found" 404

  handle_errors 4xx {
    respond "Error in the [400 .. 499] range"
  }
`,
      probes: [
        {
          path: "/private",
        },
        {
          path: "/hidden",
        },
      ],
    });

    // Ported from Caddy's caddytest/integration/caddyfile_test.go::TestHandleErrorSort.
    await compareGeneratedCaddyfile({
      name: "Caddy integration TestHandleErrorSort",
      files: {},
      site: `
  error /private* "Unauthorized" 410
  error /hidden* "Not found" 404
  error /internalerr* "Internal Server Error" 500

  handle_errors {
    respond "Fallback route: code outside the [400..499] range"
  }
  handle_errors 4xx {
    respond "Error in the [400 .. 499] range"
  }
`,
      probes: [
        {
          path: "/internalerr",
        },
        {
          path: "/hidden",
        },
      ],
    });

    // Ported from Caddy's caddytest/integration/caddyfile_test.go::TestHandleErrorRangeAndCodes.
    await compareGeneratedCaddyfile({
      name: "Caddy integration TestHandleErrorRangeAndCodes",
      files: {},
      site: `
  error /private* "Unauthorized" 410
  error /threehundred* "Moved Permanently" 301
  error /internalerr* "Internal Server Error" 500

  handle_errors 500 3xx {
    respond "Error code is equal to 500 or in the [300..399] range"
  }
  handle_errors 4xx {
    respond "Error in the [400 .. 499] range"
  }
`,
      probes: [
        {
          path: "/internalerr",
        },
        {
          path: "/threehundred",
        },
        {
          path: "/private",
        },
      ],
    });

    // Ported from Caddy's caddytest/integration/caddyfile_test.go::TestHandleErrorSubHandlers.
    await compareGeneratedCaddyfile({
      name: "Caddy integration TestHandleErrorSubHandlers",
      files: {},
      site: `
  error /*/internalerr* "Internal Server Error" 500

  handle_errors 404 {
    handle /en/* {
      respond "not found" 404
    }
    handle /es/* {
      respond "no encontrado" 404
    }
    handle {
      respond "default not found"
    }
  }
  handle_errors {
    handle {
      respond "Default error"
    }
    handle /en/* {
      respond "English error"
    }
  }
`,
      probes: [
        {
          path: "/en/notfound",
        },
        {
          path: "/es/notfound",
        },
        {
          path: "/notfound",
        },
        {
          path: "/es/internalerr",
        },
        {
          path: "/en/internalerr",
        },
      ],
    });

    // Ported from Caddy's caddytest/integration/caddyfile_adapt/error_multi_site_blocks.caddyfiletest.
    await compareGeneratedCaddyfile({
      name: "Caddy error routes across multiple site blocks fixture",
      files: {},
      fullCaddyfile: ({ caddyPort }) =>
        `{
  admin off
  auto_https off
}

http://foo.localhost:${caddyPort} {
  error /private* "Unauthorized" 410
  error /fivehundred* "Internal Server Error" 500

  handle_errors 5xx {
    respond "Error In range [500 .. 599]"
  }
  handle_errors 410 {
    respond "404 or 410 error"
  }
}

http://bar.localhost:${caddyPort} {
  error /private* "Unauthorized" 410
  error /fivehundred* "Internal Server Error" 500

  handle_errors 5xx {
    respond "Error In range [500 .. 599] from second site"
  }
  handle_errors 410 {
    respond "404 or 410 error from second site"
  }
}
`,
      probes: [
        {
          path: "/private",
          headers: { Host: "foo.localhost" },
        },
        {
          path: "/fivehundred",
          headers: { Host: "foo.localhost" },
        },
        {
          path: "/private",
          headers: { Host: "bar.localhost" },
        },
        {
          path: "/fivehundred",
          headers: { Host: "bar.localhost" },
        },
      ],
    });

    // Single byte-range and 416 semantics, matched against Go's
    // net/http.ServeContent (which Caddy's file server delegates to). The ETag
    // value itself is intentionally not compared: zeroserve derives tarball
    // ETags from content, while Caddy derives them from mtime+size.
    {
      const rangeHeaders = [
        "content-range",
        "content-length",
        "content-type",
        "accept-ranges",
        "x-content-type-options",
      ];
      await compareGeneratedCaddyfile({
        name: "Caddy file_server single byte-range semantics",
        files: {
          "asset.txt": "0123456789abcdefghijKLMNOPQRST", // 30 bytes
          "empty.txt": "",
        },
        site: `
  root * .
  file_server
`,
        probes: [
          { path: "/asset.txt", headers: { Range: "bytes=0-9" }, compareHeaders: rangeHeaders },
          { path: "/asset.txt", headers: { Range: "bytes=5-" }, compareHeaders: rangeHeaders },
          { path: "/asset.txt", headers: { Range: "bytes=-5" }, compareHeaders: rangeHeaders },
          { path: "/asset.txt", headers: { Range: "bytes=-0" }, compareHeaders: rangeHeaders },
          { path: "/asset.txt", headers: { Range: "bytes=-100" }, compareHeaders: rangeHeaders },
          { path: "/asset.txt", headers: { Range: "bytes=20-100" }, compareHeaders: rangeHeaders },
          { path: "/asset.txt", headers: { Range: "bytes=0-0" }, compareHeaders: rangeHeaders },
          { path: "/asset.txt", headers: { Range: "bytes=0-29" }, compareHeaders: rangeHeaders },
          // Unsatisfiable: start at/after EOF -> 416 with "bytes */N".
          { path: "/asset.txt", headers: { Range: "bytes=30-" }, compareHeaders: rangeHeaders },
          { path: "/asset.txt", headers: { Range: "bytes=40-50" }, compareHeaders: rangeHeaders },
          // Malformed: 416 "invalid range" with no Content-Range.
          { path: "/asset.txt", headers: { Range: "bytes=5-3" }, compareHeaders: rangeHeaders },
          { path: "/asset.txt", headers: { Range: "bytes=abc" }, compareHeaders: rangeHeaders },
          { path: "/asset.txt", headers: { Range: "items=0-4" }, compareHeaders: rangeHeaders },
          { path: "/asset.txt", headers: { Range: "bytes=-" }, compareHeaders: rangeHeaders },
          // Empty spec is ignored -> full 200.
          { path: "/asset.txt", headers: { Range: "bytes=" }, compareHeaders: rangeHeaders },
          // Comma lists that reduce to a single satisfiable range.
          { path: "/asset.txt", headers: { Range: "bytes=0-4," }, compareHeaders: rangeHeaders },
          { path: "/asset.txt", headers: { Range: "bytes=,0-4" }, compareHeaders: rangeHeaders },
          { path: "/asset.txt", headers: { Range: "bytes=0-4,40-50" }, compareHeaders: rangeHeaders },
          // Empty file: explicit range ignored (200), suffix yields empty 206.
          { path: "/empty.txt", headers: { Range: "bytes=0-9" }, compareHeaders: rangeHeaders },
          { path: "/empty.txt", headers: { Range: "bytes=-5" }, compareHeaders: rangeHeaders },
          {
            path: "/asset.txt",
            method: "HEAD",
            headers: { Range: "bytes=0-9" },
            compareHeaders: rangeHeaders,
            compareBody: false,
          },
        ],
      });

      // Conditional request semantics (If-Match / If-None-Match /
      // If-Modified-Since / If-Unmodified-Since / If-Range). Probes avoid
      // depending on the ETag value (only `*` and a deliberately-wrong tag are
      // used); date probes deliberately carry an incorrect weekday to confirm
      // zeroserve, like Go, ignores the weekday rather than rejecting the date.
      await compareGeneratedCaddyfile({
        name: "Caddy file_server conditional request semantics",
        files: {
          "asset.txt": "0123456789abcdefghijKLMNOPQRST",
        },
        site: `
  root * .
  file_server
`,
        probes: [
          // 304: no Content-Type/Content-Length, and no Last-Modified (ETag wins).
          {
            path: "/asset.txt",
            headers: { "If-None-Match": "*" },
            compareHeaders: ["content-type", "content-length", "last-modified"],
          },
          { path: "/asset.txt", headers: { "If-None-Match": `"nope"` } },
          {
            path: "/asset.txt",
            headers: { "If-Modified-Since": "Mon, 21 Oct 2099 07:28:00 GMT" },
            compareHeaders: ["content-type", "content-length", "last-modified"],
          },
          { path: "/asset.txt", headers: { "If-Modified-Since": "Mon, 21 Oct 1995 07:28:00 GMT" } },
          // 412 keeps Content-Type and Last-Modified (Go reaches it via a bare
          // WriteHeader). The 1995 date carries a wrong weekday on purpose.
          {
            path: "/asset.txt",
            headers: { "If-Unmodified-Since": "Mon, 21 Oct 1995 07:28:00 GMT" },
            compareHeaders: ["content-type", "last-modified"],
          },
          { path: "/asset.txt", headers: { "If-Unmodified-Since": "Mon, 21 Oct 2099 07:28:00 GMT" } },
          { path: "/asset.txt", headers: { "If-Match": "*" } },
          {
            path: "/asset.txt",
            headers: { "If-Match": `"nope"` },
            compareHeaders: ["content-type", "last-modified"],
          },
          // If-Range mismatch (tag or non-matching date) drops the range -> 200.
          {
            path: "/asset.txt",
            headers: { Range: "bytes=0-9", "If-Range": `"nope"` },
            compareHeaders: ["content-range", "content-length", "accept-ranges"],
          },
          {
            path: "/asset.txt",
            headers: {
              Range: "bytes=0-9",
              "If-Range": "Mon, 21 Oct 2099 07:28:00 GMT",
            },
            compareHeaders: ["content-range", "content-length", "accept-ranges"],
          },
        ],
      });
    }
  },
});

async function compareGeneratedCaddyfile(
  caseDef: GeneratedCase,
): Promise<void> {
  const siteDir = await Deno.makeTempDir();
  let tarPath: string | null = null;
  let upstream: { port: number; stop: () => Promise<void> } | null = null;
  try {
    await Deno.mkdir(join(siteDir, ".zeroserve", "scripts"), {
      recursive: true,
    });
    for (const [path, contents] of Object.entries(caseDef.files)) {
      const filePath = join(siteDir, path);
      await Deno.mkdir(dirname(filePath), { recursive: true });
      if (typeof contents === "string") {
        await Deno.writeTextFile(filePath, contents);
      } else {
        await Deno.writeFile(filePath, contents);
      }
    }

    const caddyPort = await getFreePort();
    if (caseDef.upstream) {
      upstream = await withUpstream();
    }
    const caddyfile = buildGeneratedCaddyfile(caseDef, {
      caddyPort,
      upstreamPort: upstream?.port ?? 0,
    });
    const caddyfilePath = join(siteDir, "Caddyfile");
    await Deno.writeTextFile(caddyfilePath, caddyfile);
    await writeCompiledCaddyMiddleware(siteDir, caddyfilePath);

    tarPath = await packSite(siteDir);
    const caddyBaseUrl = await withCaddy(siteDir, caddyfilePath, caddyPort);
    try {
      await withZeroserve(tarPath, async (zeroserveBaseUrl) => {
        const probes = typeof caseDef.probes === "function"
          ? caseDef.probes({ upstreamPort: upstream?.port ?? 0 })
          : caseDef.probes;
        for (const probe of probes) {
          const caddy = await fetchObserved(caddyBaseUrl, probe);
          const zeroserve = await fetchObserved(zeroserveBaseUrl, probe);
          assertEquals(
            zeroserve,
            caddy,
            `${caseDef.name}: ${probe.method ?? "GET"} ${probe.path}`,
          );
        }
      });
    } finally {
      await caddyBaseUrl.stop();
    }
  } finally {
    if (tarPath !== null) {
      await Deno.remove(tarPath).catch(() => {});
    }
    if (upstream !== null) {
      await upstream.stop();
    }
    await Deno.remove(siteDir, { recursive: true }).catch(() => {});
  }
}

function buildGeneratedCaddyfile(
  caseDef: GeneratedCase,
  ctx: { caddyPort: number; upstreamPort: number },
): string {
  if (caseDef.fullCaddyfile !== undefined) {
    return typeof caseDef.fullCaddyfile === "function"
      ? caseDef.fullCaddyfile(ctx)
      : caseDef.fullCaddyfile;
  }
  if (caseDef.site === undefined) {
    throw new Error(`${caseDef.name}: generated case requires site`);
  }
  const site = typeof caseDef.site === "function"
    ? caseDef.site({ upstreamPort: ctx.upstreamPort })
    : caseDef.site;
  return `{
  admin off
  auto_https off
}

${caseDef.prelude ?? ""}
:${ctx.caddyPort} {
${site}}
`;
}

async function writeCompiledCaddyMiddleware(
  siteDir: string,
  caddyfilePath: string,
): Promise<void> {
  const zeroservePath = await getZeroservePath();
  const compiled = await new Deno.Command(zeroservePath, {
    args: ["--caddy-compile", caddyfilePath],
    cwd: repoRoot,
    stdout: "piped",
    stderr: "piped",
  }).output();
  if (!compiled.success) {
    throw new Error(decoder.decode(compiled.stderr));
  }
  await Deno.writeFile(
    join(siteDir, ".zeroserve", "scripts", "caddy.c"),
    compiled.stdout,
  );
}

async function withCaddy(
  siteDir: string,
  caddyfilePath: string,
  port: number,
): Promise<{ origin: string; stop: () => Promise<void> }> {
  const child = new Deno.Command(caddyBin, {
    args: ["run", "--config", caddyfilePath, "--adapter", "caddyfile"],
    cwd: siteDir,
    stdin: "null",
    stdout: "null",
    stderr: "inherit",
  }).spawn();
  const statusPromise = child.status;
  await waitForServer("127.0.0.1", port, statusPromise);
  return {
    origin: `http://127.0.0.1:${port}`,
    stop: () => stopProcess(child, statusPromise),
  };
}

async function fetchObserved(
  server: { origin: string } | string,
  probe: Probe,
): Promise<ObservedResponse> {
  const origin = typeof server === "string" ? server : server.origin;
  const res = await fetch(`${origin}${probe.path}`, {
    method: probe.method ?? "GET",
    headers: probe.headers,
    body: probe.body,
    redirect: probe.redirect ?? "manual",
  });
  const headers: Record<string, string | null> = {};
  for (const name of probe.compareHeaders ?? []) {
    headers[name] = res.headers.get(name);
  }
  return {
    status: res.status,
    body: probe.compareBody === false
      ? ""
      : normalizeBody(await res.text(), probe),
    headers,
  };
}

function normalizeBody(body: string, probe: Probe): string {
  if (probe.normalizeBrowseCount) {
    const listing = JSON.parse(body) as unknown[];
    return `entries:${listing.length}`;
  }
  if (!probe.normalizeBrowseJson) {
    return body;
  }
  const listing = JSON.parse(body) as Array<{ name: string; size: number }>;
  return JSON.stringify(listing.map((item) => `${item.name}:${item.size}`));
}

async function withUpstream(): Promise<{
  port: number;
  stop: () => Promise<void>;
}> {
  const port = await getFreePort();
  const server = Deno.serve({
    hostname: "127.0.0.1",
    port,
    onListen: () => {},
  }, (req) => {
    const url = new URL(req.url);
    if (url.pathname === "/auth") {
      const originalUri = req.headers.get("x-forwarded-uri") ?? "";
      if (originalUri.includes("denied")) {
        return new Response("denied", { status: 401 });
      }
      return new Response(null, {
        status: 204,
        headers: {
          "X-User-Id": "alice",
          "X-Role": "admin",
          "X-Empty-Auth": "",
        },
      });
    }
    const headers = new Headers({
      "X-Backend-Token": "backend",
      "X-Seen-User": req.headers.get("x-user-id") ?? "",
      "X-Seen-Auth-User": req.headers.get("x-auth-user") ?? "",
      "X-Seen-Role": req.headers.get("x-role") ?? "",
    });
    const status = url.pathname === "/proxy-created" ? 201 : 200;
    return new Response(
      `${url.pathname}:${req.headers.get("x-upstream-token") ?? ""}`,
      { status, headers },
    );
  });
  return {
    port,
    stop: async () => {
      await server.shutdown();
    },
  };
}

async function hasCommand(command: string): Promise<boolean> {
  try {
    const output = await new Deno.Command(command, {
      args: ["version"],
      stdout: "null",
      stderr: "null",
    }).output();
    return output.success;
  } catch (err) {
    if (err instanceof Deno.errors.NotFound) {
      return false;
    }
    throw err;
  }
}
