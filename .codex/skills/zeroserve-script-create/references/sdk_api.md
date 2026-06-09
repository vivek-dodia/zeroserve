# Zeroserve SDK API (summary)

## Entry point and macros

- Include the SDK: `#include <zeroserve.h>`.
- Mark the entry function with `ZS_ENTRY` (section `zeroserve.request`).
- `ZS_STR("literal")` expands to `(ptr, len)` for NUL-terminated literals.

## Request inspection

- `zs_req_method(out, out_len)`
- `zs_req_path(out, out_len)`
- `zs_req_normalized_path(out, out_len)` returns the cleaned decoded request
  path used by zeroserve static-file lookup.
- `zs_caddy_path_regexp_subject(out, out_len)` returns the decoded, cleaned
  request path used by Caddy `path_regexp` matching.
- `zs_req_uri(out, out_len)`
- `zs_req_query(out, out_len)`
- `zs_req_scheme(out, out_len)`
- `zs_req_proto_major()` / `zs_req_proto_minor()` return the HTTP protocol
  version numbers.
- `zs_req_peer(out, out_len)`
- `zs_req_is_tls()` returns `1` for TLS requests.
- `zs_req_tls_handshake_complete()` returns `1` once TLS is complete for the
  current request; zeroserve currently runs middleware after TCP TLS handshakes.
- `zs_req_header(name, name_len, out, out_len)`
- `zs_req_query_param(name, name_len, out, out_len)`
- `zs_req_query_param_matches(name, name_len, value, value_len)` returns `1`
  when any decoded query value for `name` equals `value`, or when `value` is
  `*` and the key is present.
- `zs_req_remote_ip_matches(ranges_json, ranges_json_len)` returns `1` when the
  current direct peer IP matches any IP or CIDR range in the JSON string array.
- `zs_caddy_client_ip_matches(config_json, config_json_len)` resolves the Caddy
  client IP using static `trusted_proxies`, `client_ip_headers`, and
  `trusted_proxies_strict`, then matches it against configured IP/CIDR ranges.
- `zs_caddy_vars_match(vars_json, vars_json_len)` returns `1` when any Caddy
  `vars` matcher entry matches. Single-placeholder keys are resolved as
  placeholders, literal keys read values from `zs_caddy_vars_set`, and expected
  values are placeholder-expanded.
- `zs_caddy_vars_regexp_match(vars_json, vars_json_len)` evaluates Caddy
  `vars_regexp` matcher entries against values set by `zs_caddy_vars_set` and
  stores regex captures in metadata.
- `zs_caddy_path_match(pattern, pattern_len)` returns `1` when the current
  request path matches a Caddy path matcher pattern, including cleaned-path,
  glob, and escaped `%` matching behavior.
- `zs_caddy_query_match(name_template, name_template_len, value_template,
  value_template_len)` expands both templates as Caddy placeholders, then
  returns `1` when the decoded query key is present with the decoded value, or
  when the expanded value is `*` and the key is present.
- `zs_caddy_query_present(name_template, name_template_len)` expands the key
  template as Caddy placeholders and returns `1` when the decoded query key is
  present.
- `zs_caddy_query_empty()` returns `1` when Caddy's parsed query map is empty,
  matching an empty Caddy query matcher. Malformed query pairs are dropped for
  this check, like Go's `URL.Query()`.
- `zs_caddy_header_match(name, name_len, value_template, value_template_len)`
  expands the allowed value template and evaluates Caddy request-header matcher
  semantics against every repeated value for `name`.
- `zs_caddy_header_present(name, name_len)` returns `1` when the request header
  exists, supporting Caddy header matcher `[]` and `null` presence semantics.
- `zs_caddy_header_regexp_match(name, name_len, config_json, config_json_len)`
  evaluates a Caddy regex matcher config (`pattern`, optional `name`) against
  every repeated request-header value for `name` and stores captures on success.
- `zs_caddy_regex_match(input, input_len, config_json, config_json_len)`
  evaluates a Caddy regex matcher config (`pattern`, optional `name`) and stores
  numbered/named captures in metadata under `http.regexp...` keys.
- `zs_caddy_file_match(config_json, config_json_len)` evaluates a supported
  Caddy `file` matcher against the packed site or an absolute host filesystem
  root and stores `http.matchers.file.relative`, `.absolute`, `.type`, and
  `.remainder` placeholders on success. If `root` is omitted, it uses
  `http.vars.root` and falls back to the packed site root when unset, matching
  Caddy's default. Glob expansion and `=status` error fallbacks are
  intentionally rejected by the compiler.
- `zs_caddy_expand(input, input_len, out, out_len)` expands supported Caddy
  placeholders from the current request, response hook headers, shared
  metadata, regex captures, and Caddy vars. Supported request placeholders
  include method, scheme, host/port/hostport, host labels, remote address
  host/port, URI/path/query with escaped variants, prefixed query, path
  file/dir/base/ext and indexed path segments, original method/URI/path/query
  state from before request mutation, protocol/protocol name, request UUID,
  available TLS ALPN/SNI/ECH state, and more. Supported response placeholders
  include `http.response.header.*` while a response hook is running. Unknown
  placeholders expand to the empty string, like Caddy `ReplaceAll`.
- `zs_caddy_expand_known(input, input_len, out, out_len)` is the same expansion
  surface, but leaves unknown placeholders intact, like Caddy `ReplaceKnown`.
- `zs_caddy_rewrite_uri(uri_template, uri_template_len)` expands and applies a
  Caddy `rewrite.uri` template to the current request path, query, and fragment
  using Caddy's preservation rules.
- `zs_caddy_respond(status_template, status_template_len, body_template,
  body_template_len)` expands Caddy placeholders in a static response status and
  body, applies Caddy's static-response content-type inference, and sets a
  terminal response. It is intended for generated Caddy middleware.
- `zs_caddy_respond_static(status_template, status_template_len, config_json,
  config_json_len)` is the generated Caddy `static_response` helper. The config
  contains the body, headers, and close flag; headers are expanded before
  Caddy's implicit `Content-Type` decision.
- `zs_caddy_map(config_json, config_json_len)` registers a lazy Caddy map
  provider for the current request. The config is Caddy's `map` handler JSON
  without the `handler` field; mapped placeholders are evaluated when later
  placeholder expansion asks for them.
- `zs_caddy_response_headers(ops_json, ops_json_len)` applies non-deferred
  Caddy `headers.response` operations to the current request's early response
  header map before a downstream handler creates the response.
- `zs_caddy_reverse_proxy_url(url_template, url_template_len, out, out_len)`
  expands a generated reverse-proxy backend URL template, stores
  `http.reverse_proxy.upstream.*` placeholders in metadata for later header
  operations, and writes the expanded URL to `out`.
- `zs_caddy_reverse_proxy_forwarded(config_json, config_json_len)` applies
  Caddy reverse-proxy `X-Forwarded-*` preparation, including server-level static
  trusted proxies and handler `trusted_proxies` preservation rules. It is
  intended for generated Caddy middleware.
- `zs_caddy_reverse_proxy_rewrite(config_json, config_json_len)` applies a
  supported Caddy reverse-proxy `rewrite` object to the upstream request only,
  without mutating the live request seen by later response hooks.
- During `zs_reverse_proxy`, zeroserve stores
  `http.reverse_proxy.status_code`, `http.reverse_proxy.status_text`, and
  `http.reverse_proxy.header.*` placeholders from the upstream response before
  response hooks run.
- `zs_req_body_limit(max_size)` lowers the per-request buffered body read limit
  and returns `1` if `Content-Length` is already larger than `max_size`.
- `zs_req_body_json()` parses the request body as JSON and returns a handle (-1 on failure,
  empty body, body > 256KB, or invalid JSON). The body is read lazily on first call and cached.
- `zs_connection_info()` returns a JSON object handle describing the
  underlying connection, including `tls`, `tls_handshake_complete`, `alpn`,
  `sni`, `ech`, and TLS fingerprint fields.

## Request mutation

- `zs_req_set_method(method, method_len)`
- `zs_caddy_rewrite_method(method_template, method_template_len)` expands a
  Caddy `rewrite.method` template, uppercases it, and applies it to the current
  request.
- `zs_req_set_uri(uri, uri_len)`
- `zs_req_rewrite_query(ops_json, ops_json_len)` applies supported Caddy
  `rewrite.query` operations (`rename`, `set`, `add`, string `replace`, and
  `delete`) to the current request query string.
- `zs_caddy_rewrite_uri(uri_template, uri_template_len)` applies a placeholder
  aware Caddy `rewrite.uri` template to the current request.
- `zs_req_rewrite_uri(ops_json, ops_json_len)` applies supported Caddy URI
  rewrite operations (`strip_path_prefix`, `strip_path_suffix`, and string
  `uri_substring`, and `path_regexp`) to the current request URI.
- `zs_caddy_vars_set(vars_json, vars_json_len)` stores supported Caddy `vars`
  handler values in the per-request metadata map, expanding placeholders in
  variable names and string values.
- `zs_req_set_header(name, name_len, value, value_len)`
    - Pass `value_len = 0` to remove a header.
- `zs_req_append_header(name, name_len, value, value_len)`
- `zs_req_delete_header(pattern, pattern_len)` deletes exact, prefix (`Foo*`),
  suffix (`*Foo`), contains (`*Foo*`), or all (`*`) request headers.
- `zs_req_replace_header(op_json, op_json_len)` applies a supported Caddy
  header replacement object (`name`, `search` or `search_regexp`, `replace`) to
  request headers.

## Metadata (per-request string map)

- `zs_meta_get(key, key_len, out, out_len)`
- `zs_meta_set(key, key_len, value, value_len)`
    - Keys prefixed with `zs.response.header.` become response headers.

## Response hooks

- `zs_res_hook(script, script_len, func, func_len, json_handle)` registers a
  `ZS_CALL_ENTRY` function to run after response headers exist and before they
  are written. Pass an empty script name to target the current script.
- In a response hook: `zs_res_status()`, `zs_res_set_status(status)`,
  `zs_res_header(name, name_len, out, out_len)`,
  `zs_res_set_header(name, name_len, value, value_len)`,
  `zs_res_append_header(name, name_len, value, value_len)`, and
  `zs_res_delete_header(pattern, pattern_len)`.
- In a response hook: `zs_caddy_res_header_match(name, name_len, value,
  value_len)` and `zs_caddy_res_header_present(name, name_len)` implement Caddy
  response-header matcher value and presence semantics across repeated headers.
  The allowed value is expanded as a Caddy placeholder template before wildcard
  matching.
- In a response hook:
  `zs_caddy_copy_response_headers(config_json, config_json_len)` copies headers
  from the original response header set using a Caddy `copy_response_headers`
  style object with optional `include` or `exclude` arrays.
- In a response hook, `zs_res_replace_header(op_json, op_json_len)` applies a
  supported Caddy header replacement object (`name`, `search` or
  `search_regexp`, `replace`) to response headers.
- Response hooks share the request metadata map, so `zs_meta_set` updates,
  including `zs.response.header.<name>`, are visible when final headers are
  emitted.

## Response / proxy

- `zs_respond(status, body, body_len)`
- `zs_reverse_proxy(backend_url, backend_url_len)` proxies to an HTTP/HTTPS
  backend and fills missing `X-Forwarded-For`, `X-Forwarded-Proto`, and
  `X-Forwarded-Host` headers. Generated Caddy middleware uses
  `zs_caddy_reverse_proxy_forwarded` first for Caddy-compatible trusted-proxy
  handling.
- `zs_file_server(config_json, config_json_len)` serves a static file response
  using supported Caddy file-server config JSON. Relative roots resolve inside
  the packed site tar; absolute roots resolve against the host filesystem.
  Omitted roots use `http.vars.root` with a packed-site-root fallback.
  Caddy placeholders are expanded in `fs`, `root`, `hide`, `index_names`, and `status_code`
  before selecting a file. `hide` entries use Caddy-style case-sensitive
  component/path glob matching. With `{"pass_thru": true}`, it returns `1` and
  leaves the request runnable when no file would be served; otherwise it returns
  `0` after selecting the file-server response. Browse responses include
  `Last-Modified` and honor `If-Modified-Since`.

## Logging, time, and environment

- `zs_log(msg, len)`
- `zs_now_ms()`
- `zs_env_get(name, name_len, out, out_len)` reads an environment variable.

## Crypto and encoding

- `zs_getrandom(out, out_len)`
- `zs_sha256(data, data_len, out, out_len)` writes a 32-byte SHA-256 digest (requires `out_len == 32`).
- `zs_hmac_sha256(key, key_len, msg, msg_len, out)`
- `zs_base64_encode(data, data_len, out, out_len, encoding)`
- `zs_base64_decode_in_place(buf, buf_len, encoding)`
- `zs_hex_encode(data, data_len, out, out_len, case)` encodes binary data to hexadecimal.
- `zs_hex_decode_in_place(buf, buf_len)` decodes hexadecimal to binary in place.

## JSON parsing (handle table)

- `zs_json_parse(data, data_len)` parses JSON and returns a handle (-1 on failure).
- `zs_load_static_json(path, path_len)` reads the static file at `path` in the tarball and
  parses JSON, returning a handle (-1 if missing or invalid JSON). The path is used verbatim
  (no normalization, index fallback, or `.html` try).
- `zs_load_file_metadata(path, path_len)` returns a JSON handle for a tarball entry with
  `{"size":...,"etag":...,"mtime":...}` (-1 if missing). The path is used verbatim.
- `zs_json_reset(handle)` resets a handle back to the document root.
- `zs_json_get(handle, key, key_len)` reads an object key and returns a handle
  (-1 if missing, non-object, or invalid UTF-8 key).
- `zs_json_array_get(handle, array_index)` takes an array index and returns a handle
  (-1 if missing, non-array).
- `zs_json_read_string(handle, out, out_len)` writes a JSON string into `out`
  (use `out_len = 0` to query required length; -1 if not a string).
- `zs_json_read_i64(handle, out, out_len)` writes a native-endian `i64` into `out`
  (requires `out_len == sizeof(i64)`; -1 if not a number or out of range).
- `zs_json_read_bool(handle, out, out_len)` writes `0` or `1` into `out`
  (requires `out_len == 1`; -1 if not a boolean).
- `zs_object_free(handle)` releases a JSON handle when you're done with it.
- The handle table is limited (32 entries); free handles to avoid exhaustion.

## JSON creation and modification

- `zs_json_new_object()` creates an empty JSON object `{}`; returns a handle (-1 on failure).
- `zs_json_new_array()` creates an empty JSON array `[]`; returns a handle (-1 on failure).
- `zs_json_clone(handle)` deep-clones a JSON value into a new independent tree; returns a handle.
- `zs_json_len(handle)` returns the length of an array, object, or string (-1 for other types).
- `zs_json_type(handle)` returns the type code: `ZS_JSON_NULL` (0), `ZS_JSON_BOOL` (1),
  `ZS_JSON_NUMBER` (2), `ZS_JSON_STRING` (3), `ZS_JSON_ARRAY` (4), `ZS_JSON_OBJECT` (5).
- `zs_json_set(handle, key, key_len, value_handle)` sets a field on an object; the value is
  cloned from `value_handle`. Returns 0 on success, -1 if not an object.
- `zs_json_remove(handle, key, key_len)` removes a field from an object. Returns 0 on success,
  -1 if not an object or key not found.
- `zs_json_array_push(handle, value_handle)` appends a cloned value to an array; returns new
  length on success, -1 if not an array.
- `zs_json_array_set(handle, index, value_handle)` sets an element at an array index; returns
  0 on success, -1 if out of bounds or not an array.
- `zs_json_set_string(handle, value, value_len)` replaces the node with a string value.
- `zs_json_set_i64(handle, value)` replaces the node with an i64 value.
- `zs_json_set_bool(handle, value)` replaces the node with a boolean (0 = false, non-zero = true).
- `zs_json_set_null(handle)` replaces the node with null.

## JSON response

- `zs_json_respond(status, handle)` serializes the JSON handle to a response body, sets
  `Content-Type: application/json`, and sends the response. Returns 0 on success.

## Helper notes

- String helpers write C strings into the output buffer.
- Passing `out_len = 0` returns the required length.
- Binary helpers return the number of bytes written and do not NUL-terminate.
- `zs_sha256` requires `out_len` to be exactly 32 bytes.
- `zs_hmac_sha256` writes 32 bytes to the output buffer.
- `zs_base64_encode` requires the output buffer to fit the encoded length.
- Base64 `encoding` values: `ZS_BASE64_STANDARD`, `ZS_BASE64_STANDARD_NO_PAD`,
  `ZS_BASE64_URL`, `ZS_BASE64_URL_NO_PAD`.
- `zs_hex_encode` outputs 2 hex characters per input byte; use `out_len = 0` to query the required length.
- `zs_hex_decode_in_place` requires an even `buf_len`; returns the decoded length or -1 on error.
- Hex `case` values: `ZS_HEX_LOWERCASE`, `ZS_HEX_UPPERCASE`.
- Header names are matched case-insensitively.
- The SDK also provides small string/memory helpers like `zs_strlen`, `zs_strcmp`,
  `zs_memcpy`, `zs_memset`, and `zs_utoa10`.
- `zs_req_body_json` reads the body lazily (only when called) and caches the result.
  Subsequent calls return the cached handle. The body is limited to 256KB.

## AWS SigV4 signing

- `zs_aws_v4_authorization_header(params, params_len)` generates an AWS Signature Version 4
  Authorization header value. Takes a pointer to `zs_aws_v4_sign_params` and the struct size.
  Returns the number of characters written (excluding null terminator), or -1/-2 on error.
  If `params->out_len` is 0, returns the required buffer size without writing.

  The `zs_aws_v4_sign_params` struct fields:
  - `access_key`, `access_key_len`: AWS access key ID
  - `secret_key`, `secret_key_len`: AWS secret access key
  - `region`, `region_len`: AWS region (e.g., "us-east-1")
  - `service`, `service_len`: Service name (e.g., "s3", "execute-api")
  - `method`, `method_len`: HTTP method (e.g., "GET", "POST")
  - `uri`, `uri_len`: Request URI including path and optional query string
  - `headers_json`: JSON object handle with headers to sign (e.g., `{"host": "s3.amazonaws.com"}`)
  - `body_hash`, `body_hash_len`: Hex-encoded SHA256 of body, or "UNSIGNED-PAYLOAD"
  - `timestamp_ms`: Unix timestamp in milliseconds for the request
  - `out`, `out_len`: Output buffer for the Authorization header value

  Example usage:

  ```c
  char auth[512];
  zs_json headers = zs_json_new_object();
  zs_json_set_string(headers, "host", 4, "s3.amazonaws.com", 16);

  zs_aws_v4_sign_params p = {
      .access_key = "AKIA...", .access_key_len = 20,
      .secret_key = "wJalr...", .secret_key_len = 40,
      .region = "us-east-1", .region_len = 9,
      .service = "s3", .service_len = 2,
      .method = "GET", .method_len = 3,
      .uri = "/bucket/object", .uri_len = 14,
      .headers_json = headers,
      .body_hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
      .body_hash_len = 64,
      .timestamp_ms = zs_now_ms(),
      .out = auth, .out_len = sizeof(auth)
  };

  zs_s64 n = zs_aws_v4_authorization_header(&p, sizeof(p));
  if (n > 0) {
      zs_req_set_header("Authorization", 13, auth, n);
  }
  zs_object_free(headers);
  ```

- `zs_aws_v4_presigned_url(params, params_len, expires_secs)` generates an AWS Signature
  Version 4 pre-signed URL. Takes a pointer to `zs_aws_v4_sign_params`, the struct size,
  and the expiration time in seconds. Returns the number of characters written (excluding
  null terminator), or -1/-2 on error. If `params->out_len` is 0, returns the required
  buffer size without writing.

  The output is a URL path with query string containing the signature parameters
  (`X-Amz-Algorithm`, `X-Amz-Credential`, `X-Amz-Date`, `X-Amz-Expires`,
  `X-Amz-SignedHeaders`, `X-Amz-Signature`). The body is always treated as
  `UNSIGNED-PAYLOAD`.

  Example usage:

  ```c
  char url[1024];
  zs_json headers = zs_json_new_object();
  zs_s64 host_val = zs_json_parse(ZS_STR("\"s3.amazonaws.com\""));
  zs_json_set(headers, ZS_STR("host"), host_val);
  zs_object_free(host_val);

  zs_aws_v4_sign_params p = {
      .access_key = "AKIA...", .access_key_len = 20,
      .secret_key = "wJalr...", .secret_key_len = 40,
      .region = "us-east-1", .region_len = 9,
      .service = "s3", .service_len = 2,
      .method = "GET", .method_len = 3,
      .uri = "/bucket/object?prefix=docs/", .uri_len = 25,
      .headers_json = headers,
      .timestamp_ms = zs_now_ms(),
      .out = url, .out_len = sizeof(url)
  };

  zs_s64 n = zs_aws_v4_presigned_url(&p, sizeof(p), 3600);
  if (n > 0) {
      // url now contains "/bucket/object?prefix=docs/&X-Amz-Algorithm=..."
  }
  zs_object_free(headers);
  ```

## Rate limiting

- `zs_rate_limit(key, key_len, per_second, per_minute, per_hour)` checks whether a request
  should be allowed based on rate limits for the given key. Returns:
  - `ZS_RATE_LIMIT_ALLOWED` (0) if allowed
  - `ZS_RATE_LIMIT_EXCEEDED_SECOND` (1) if per-second limit exceeded
  - `ZS_RATE_LIMIT_EXCEEDED_MINUTE` (2) if per-minute limit exceeded
  - `ZS_RATE_LIMIT_EXCEEDED_HOUR` (3) if per-hour limit exceeded
  - `ZS_RATE_LIMIT_EXCEEDED_BUCKET_LIMIT` (4) if too many unique keys are being tracked
  - `-1` on error (invalid parameters or key too long, max 256 bytes)

  A limit of 0 means unlimited for that window. The key can be any arbitrary bytes,
  such as an IP address (`zs_req_peer`), API key, or user ID. Rate limit state is
  shared across all requests and persists across hot reloads.

  Example (rate limit by API key):

  ```c
  ZS_ENTRY
  zs_u64 entry(void) {
      char api_key[128];
      if (zs_req_header("X-API-Key", 9, api_key, sizeof(api_key)) <= 0) {
          zs_respond(401, ZS_STR("{\"error\":\"missing api key\"}"));
          return 0;
      }

      // Allow 5 req/s, 60 req/min per API key
      zs_s64 result = zs_rate_limit(ZS_STR(api_key), 5, 60, 0);
      if (result != ZS_RATE_LIMIT_ALLOWED) {
          zs_respond(429, ZS_STR("{\"error\":\"rate limit exceeded\"}"));
          return 0;
      }
      return 0;
  }
  ```

## OIDC login (Authorization Code + PKCE)

zeroserve is the OAuth2 client (Relying Party). Config is passed as a JSON object
handle (keys: `issuer` or `authorization_endpoint`+`token_endpoint`, `client_id`,
`client_secret`, `redirect_uri`, optional `scope`, `cookie_secret`,
`session_ttl_secs`). Login state and the session live in sealed cookies (no
server-side store). `cookie_secret` must be >= 16 bytes and stable across
restarts. The id_token claims are validated (`iss`/`aud`/`exp`/`nonce`) but its
signature is not separately checked (it is fetched over TLS from the token
endpoint; OIDC Core 3.1.3.7).

- `zs_oidc_begin_login(cfg, return_to, return_to_len)` — set state cookie, 302 to
  the IdP, return to `return_to` afterward. Terminal.
- `zs_oidc_handle_callback(cfg)` — on the `redirect_uri` path: validate state,
  exchange the code, set the session cookie, 302 to `return_to`. Terminal.
- `zs_oidc_session_verify(cfg)` — JSON claims handle if logged in, `0` if not,
  `<0` on error. Not terminal; free the handle with `zs_object_free`.
- `zs_oidc_logout(cfg, end_session_url, end_session_url_len)` — clear the session
  cookie and optionally 302 to the IdP end-session URL. Terminal.

  Example (gate the site, with /callback and /logout routes):
  ```c
  zs_s64 cfg = zs_json_parse(ZS_STR(
      "{\"issuer\":\"https://idp.example\","
       "\"client_id\":\"cid\",\"client_secret\":\"csecret\","
       "\"redirect_uri\":\"https://app.example/callback\","
       "\"cookie_secret\":\"stable-16+byte-secret\"}"));
  if (cfg < 0) { zs_respond(500, ZS_STR("config error")); return 0; }

  char path[256];
  zs_req_path(path, sizeof(path));
  if (zs_memcmp(path, "/callback", 9) == 0) { zs_oidc_handle_callback(cfg); return 0; }
  if (zs_memcmp(path, "/logout", 7) == 0)  { zs_oidc_logout(cfg, ZS_STR("")); return 0; }

  zs_s64 session = zs_oidc_session_verify(cfg);
  if (session <= 0) {
      char uri[512]; zs_req_uri(uri, sizeof(uri));
      zs_oidc_begin_login(cfg, ZS_STR(uri));
      return 0;
  }
  zs_object_free(session);
  return 0;  // authenticated
  ```
