//! Request matcher parsing, ported from `httpcaddyfile` (`parseMatcherDefinitions`,
//! `matcherSetFromMatcherToken`) and the per-matcher `UnmarshalCaddyfile`
//! methods in `modules/caddyhttp`. A matcher set is a JSON object mapping
//! matcher names to their JSON (AND semantics); named matchers (`@name`) are
//! collected up front per site block.

use std::collections::HashMap;
use std::sync::OnceLock;

use anyhow::{Result, bail};
use regex::Regex;
use serde_json::{Map, Value, json};

use crate::caddyfile::dispenser::{Dispenser, MATCHER_NAME_CTX_KEY};
use crate::caddyfile::token::Token;

const MATCHER_PREFIX: &str = "@";

/// Private CIDR ranges, matching `internal.PrivateRangesCIDR`.
const PRIVATE_RANGES: &[&str] = &[
    "192.168.0.0/16",
    "172.16.0.0/12",
    "10.0.0.0/8",
    "127.0.0.1/8",
    "fd00::/8",
    "::1",
];

/// Parses a named matcher definition (a `@name ...` segment) into `defs`.
/// Faithful port of `parseMatcherDefinitions`.
pub fn parse_matcher_definitions(
    d: &mut Dispenser,
    defs: &mut HashMap<String, Value>,
) -> Result<()> {
    d.next(); // advance to the first token (@name)
    let def_name = d.val();
    if defs.contains_key(&def_name) {
        bail!("matcher is defined more than once: {def_name}");
    }
    let ctx_name = def_name.trim_start_matches('@').to_string();
    let mut set: Map<String, Value> = Map::new();

    // A quoted first argument is shorthand for an expression matcher.
    if d.next_arg() {
        if d.token().quoted() {
            let mut name_tok = d.token();
            name_tok.text = "expression".to_string();
            let expr_tok = d.token();
            let v = make_matcher("expression", vec![name_tok, expr_tok], &ctx_name)?;
            set.insert("expression".to_string(), v);
            defs.insert(def_name, Value::Object(set));
            return Ok(());
        }
        d.prev();
    }

    // Concatenate tokens per matcher name (a matcher may appear more than once).
    let mut by_name: HashMap<String, Vec<Token>> = HashMap::new();
    let mut order: Vec<String> = Vec::new();
    let nesting = d.nesting();
    while d.next_arg() || d.next_block(nesting) {
        let name = d.val();
        by_name.entry(name.clone()).or_insert_with(|| {
            order.push(name.clone());
            Vec::new()
        });
        let seg = d.next_segment();
        by_name.get_mut(&name).unwrap().extend(seg);
    }
    for name in order {
        let tokens = by_name.remove(&name).unwrap();
        let v = make_matcher(&name, tokens, &ctx_name)?;
        set.insert(name, v);
    }

    defs.insert(def_name, Value::Object(set));
    Ok(())
}

/// Resolves a matcher token to a matcher set. Faithful port of
/// `matcherSetFromMatcherToken`: `*` is the catch-all (no matchers); a `/`
/// prefix is a single path matcher; a `@name` references a defined matcher.
/// Returns `(matcher_set, recognized)`.
pub fn matcher_set_from_matcher_token(
    text: &str,
    defs: &HashMap<String, Value>,
) -> Result<(Option<Value>, bool)> {
    if text == "*" {
        return Ok((None, true));
    }
    if text.starts_with('/') {
        return Ok((Some(json!({ "path": [text] })), true));
    }
    if text.starts_with(MATCHER_PREFIX) {
        match defs.get(text) {
            Some(m) => return Ok((Some(m.clone()), true)),
            None => bail!("unrecognized matcher name: {text}"),
        }
    }
    Ok((None, false))
}

/// Builds the JSON for a single matcher from its tokens (the first token is the
/// matcher name). `ctx_name` is the enclosing named-matcher name, used to fill
/// regexp/expression matcher names by default.
pub fn make_matcher(name: &str, tokens: Vec<Token>, ctx_name: &str) -> Result<Value> {
    let mut d = Dispenser::new(tokens);
    d.set_context(MATCHER_NAME_CTX_KEY, ctx_name);
    match name {
        "path" | "host" | "method" => string_list_matcher(&mut d, name),
        "path_regexp" => regexp_matcher(&mut d, name),
        "query" => query_matcher(&mut d),
        "header" => header_matcher(&mut d),
        "header_regexp" => header_regexp_matcher(&mut d, "header_regexp"),
        "expression" => expression_matcher(&mut d),
        "not" => not_matcher(&mut d),
        "remote_ip" | "client_ip" => ip_matcher(&mut d, name),
        "protocol" => protocol_matcher(&mut d),
        "tls" => tls_matcher(&mut d),
        "file" => file_matcher(&mut d),
        "vars" => vars_matcher(&mut d),
        "vars_regexp" => header_regexp_matcher(&mut d, "vars_regexp"),
        other => bail!("unsupported matcher '{other}'"),
    }
}

fn string_list_matcher(d: &mut Dispenser, name: &str) -> Result<Value> {
    let mut out: Vec<String> = Vec::new();
    while d.next() {
        out.extend(d.remaining_args());
        if d.next_block(0) {
            bail!("malformed {name} matcher: blocks are not supported");
        }
    }
    Ok(json!(out))
}

fn regexp_matcher(d: &mut Dispenser, _name: &str) -> Result<Value> {
    let mut pattern = String::new();
    let mut mname = String::new();
    while d.next() {
        if !pattern.is_empty() {
            bail!("regular expression can only be used once per named matcher");
        }
        let args = d.remaining_args();
        match args.len() {
            1 => pattern = args[0].clone(),
            2 => {
                mname = args[0].clone();
                pattern = args[1].clone();
            }
            _ => return Err(d.arg_err()),
        }
        if mname.is_empty() {
            mname = d.get_context_string(MATCHER_NAME_CTX_KEY);
        }
        if d.next_block(0) {
            bail!("malformed path_regexp matcher: blocks are not supported");
        }
    }
    Ok(regexp_value(&pattern, &mname))
}

fn regexp_value(pattern: &str, name: &str) -> Value {
    let mut m = Map::new();
    if !name.is_empty() {
        m.insert("name".to_string(), json!(name));
    }
    if !pattern.is_empty() {
        m.insert("pattern".to_string(), json!(pattern));
    }
    Value::Object(m)
}

fn query_matcher(d: &mut Dispenser) -> Result<Value> {
    let mut m: Map<String, Value> = Map::new();
    while d.next() {
        for query in d.remaining_args() {
            if query.is_empty() {
                continue;
            }
            let Some((before, after)) = query.split_once('=') else {
                bail!("malformed query matcher token: {query}; must be in param=val format");
            };
            m.entry(before.to_string())
                .or_insert_with(|| Value::Array(Vec::new()))
                .as_array_mut()
                .unwrap()
                .push(json!(after));
        }
        if d.next_block(0) {
            bail!("malformed query matcher: blocks are not supported");
        }
    }
    Ok(Value::Object(m))
}

fn header_matcher(d: &mut Dispenser) -> Result<Value> {
    let mut m: Map<String, Value> = Map::new();
    while d.next() {
        let mut field = String::new();
        if !d.args(&mut [&mut field]) {
            bail!("malformed header matcher: expected field");
        }
        if let Some(stripped) = field.strip_prefix('!') {
            if stripped.is_empty() {
                bail!("malformed header matcher: must have field name following ! character");
            }
            m.insert(stripped.to_string(), Value::Null);
            if d.next_arg() {
                bail!("malformed header matcher: null matching headers cannot have a field value");
            }
        } else {
            if !d.next_arg() {
                bail!("malformed header matcher: expected both field and value");
            }
            let val = d.val();
            // http.Header.Add canonicalizes the field name (the null `!` form
            // above uses a direct map assignment and does not).
            let field = super::handlers::canonical_header_key(&field);
            let entry = m.entry(field).or_insert_with(|| Value::Array(Vec::new()));
            if entry.is_null() {
                *entry = Value::Array(Vec::new());
            }
            entry
                .as_array_mut()
                .expect("request header matcher values are arrays after null promotion")
                .push(json!(val));
        }
        if d.next_block(0) {
            bail!("malformed header matcher: blocks are not supported");
        }
    }
    Ok(Value::Object(m))
}

fn header_regexp_matcher(d: &mut Dispenser, kind: &str) -> Result<Value> {
    let mut m: Map<String, Value> = Map::new();
    while d.next() {
        let (mut first, mut second, mut third) = (String::new(), String::new(), String::new());
        if !d.args(&mut [&mut first, &mut second]) {
            return Err(d.arg_err());
        }
        let (name, field, val) = if d.args(&mut [&mut third]) {
            (first.clone(), second.clone(), third.clone())
        } else {
            (String::new(), first.clone(), second.clone())
        };
        let name = if name.is_empty() {
            d.get_context_string(MATCHER_NAME_CTX_KEY)
        } else {
            name
        };
        if kind == "header_regexp" && m.contains_key(&field) {
            bail!(
                "header_regexp matcher can only be used once per named matcher, per header field: {field}"
            );
        }
        m.insert(field, regexp_value(&val, &name));
        if d.next_block(0) {
            bail!("malformed {kind} matcher: blocks are not supported");
        }
    }
    Ok(Value::Object(m))
}

fn expression_matcher(d: &mut Dispenser) -> Result<Value> {
    d.next(); // consume matcher name
    let expr;
    if d.count_remaining_args() > 1 {
        expr = d.remaining_args_raw().join(" ");
        return Ok(json!(expr));
    }
    if !d.next_arg() {
        return Err(d.arg_err());
    }
    expr = d.val();
    let name = d.get_context_string(MATCHER_NAME_CTX_KEY);
    if name.is_empty() {
        Ok(json!(expr))
    } else {
        Ok(json!({ "expr": expr, "name": name }))
    }
}

fn not_matcher(d: &mut Dispenser) -> Result<Value> {
    let mut sets: Vec<Value> = Vec::new();
    while d.next() {
        let set = parse_nested_matcher_set(d)?;
        sets.push(set);
    }
    Ok(json!(sets))
}

/// Port of `ParseCaddyfileNestedMatcherSet` (used by `not`). The dispenser is
/// positioned at the `not` token; nested matchers may be inline or in a block.
pub fn parse_nested_matcher_set(d: &mut Dispenser) -> Result<Value> {
    let mut by_name: HashMap<String, Vec<Token>> = HashMap::new();
    let mut order: Vec<String> = Vec::new();
    let nesting = d.nesting();
    while d.next_arg() || d.next_block(nesting) {
        if d.token().quoted() {
            let mut name_tok = d.token();
            name_tok.text = "expression".to_string();
            let expr_tok = d.token();
            let e = by_name.entry("expression".to_string()).or_insert_with(|| {
                order.push("expression".to_string());
                Vec::new()
            });
            e.push(name_tok);
            e.push(expr_tok);
            continue;
        }
        let name = d.val();
        by_name.entry(name.clone()).or_insert_with(|| {
            order.push(name.clone());
            Vec::new()
        });
        let seg = d.next_segment();
        by_name.get_mut(&name).unwrap().extend(seg);
    }
    let mut set: Map<String, Value> = Map::new();
    for name in order {
        let tokens = by_name.remove(&name).unwrap();
        set.insert(name.clone(), make_matcher(&name, tokens, "")?);
    }
    Ok(Value::Object(set))
}

fn ip_matcher(d: &mut Dispenser, name: &str) -> Result<Value> {
    let mut ranges: Vec<String> = Vec::new();
    while d.next() {
        while d.next_arg() {
            let v = d.val();
            if v == "forwarded" {
                bail!(
                    "the 'forwarded' option is no longer supported; use the 'client_ip' matcher instead"
                );
            }
            if v == "private_ranges" {
                ranges.extend(PRIVATE_RANGES.iter().map(|s| s.to_string()));
                continue;
            }
            ranges.push(v);
        }
        if d.next_block(0) {
            bail!("malformed {name} matcher: blocks are not supported");
        }
    }
    Ok(json!({ "ranges": ranges }))
}

fn protocol_matcher(d: &mut Dispenser) -> Result<Value> {
    let mut proto = String::new();
    while d.next() {
        if !d.args(&mut [&mut proto]) {
            bail!("expected exactly one protocol");
        }
    }
    Ok(json!(proto))
}

fn tls_matcher(d: &mut Dispenser) -> Result<Value> {
    let mut m = Map::new();
    while d.next() {
        if d.next_arg() {
            match d.val().as_str() {
                "early_data" => {
                    m.insert("handshake_complete".into(), json!(false));
                }
                other => bail!("unrecognized option '{other}'"),
            }
            if d.next_arg() {
                return Err(d.arg_err());
            }
        }
        if d.next_block(0) {
            bail!("malformed tls matcher: blocks are not supported");
        }
    }
    Ok(Value::Object(m))
}

fn file_matcher(d: &mut Dispenser) -> Result<Value> {
    let mut m = Map::new();
    let mut try_files = Vec::new();
    let mut root = String::new();
    let mut try_policy = String::new();
    let mut split_path = Vec::new();

    while d.next() {
        try_files.extend(d.remaining_args());
        while d.next_block(0) {
            match d.val().as_str() {
                "root" => {
                    if !d.next_arg() {
                        return Err(d.arg_err());
                    }
                    root = d.val();
                }
                "try_files" => {
                    let args = d.remaining_args();
                    if args.is_empty() && try_files.is_empty() {
                        return Err(d.arg_err());
                    }
                    try_files.extend(args);
                }
                "try_policy" => {
                    if !d.next_arg() {
                        return Err(d.arg_err());
                    }
                    try_policy = d.val();
                }
                "split_path" => {
                    split_path = d.remaining_args();
                    if split_path.is_empty() {
                        return Err(d.arg_err());
                    }
                }
                other => bail!("unrecognized subdirective: {other}"),
            }
        }
    }

    if !root.is_empty() {
        m.insert("root".to_string(), json!(root));
    }
    if !try_files.is_empty() {
        m.insert("try_files".to_string(), json!(try_files));
    }
    if !try_policy.is_empty() {
        m.insert("try_policy".to_string(), json!(try_policy));
    }
    if !split_path.is_empty() {
        m.insert("split_path".to_string(), json!(split_path));
    }

    Ok(Value::Object(m))
}

fn vars_matcher(d: &mut Dispenser) -> Result<Value> {
    let mut m: Map<String, Value> = Map::new();
    while d.next() {
        let mut field = String::new();
        if !d.args(&mut [&mut field]) {
            bail!("malformed vars matcher: expected field name");
        }
        let vals = d.remaining_args();
        if vals.is_empty() {
            bail!("malformed vars matcher: expected at least one value to match against");
        }
        let entry = m
            .entry(field)
            .or_insert_with(|| Value::Array(Vec::new()))
            .as_array_mut()
            .unwrap();
        for v in vals {
            entry.push(json!(v));
        }
        if d.next_block(0) {
            bail!("malformed vars matcher: blocks are not supported");
        }
    }
    Ok(Value::Object(m))
}

// --- shorthand placeholder replacement (NewShorthandReplacer) ---

/// Replaces Caddyfile placeholder shorthands (e.g. `{path}`) with their full
/// identifiers (`{http.request.uri.path}`) in `text`. Port of
/// `ShorthandReplacer.ApplyToSegment`.
pub fn apply_shorthands(text: &str) -> String {
    let mut out = text.to_string();
    for pair in SIMPLE_SHORTHANDS.chunks(2) {
        out = out.replace(pair[0], pair[1]);
    }
    for (re, replacement) in complex_shorthands() {
        out = re.replace_all(&out, *replacement).into_owned();
    }
    out
}

pub fn was_replaced_placeholder_shorthand(token: &str) -> Option<&'static str> {
    for pair in SIMPLE_SHORTHANDS.chunks(2) {
        if token.trim_matches(['{', '}']) == pair[1].trim_matches(['{', '}']) {
            return Some(pair[0]);
        }
    }
    None
}

#[rustfmt::skip]
const SIMPLE_SHORTHANDS: &[&str] = &[
    "{host}", "{http.request.host}",
    "{hostport}", "{http.request.hostport}",
    "{port}", "{http.request.port}",
    "{orig_method}", "{http.request.orig_method}",
    "{orig_uri}", "{http.request.orig_uri}",
    "{orig_path}", "{http.request.orig_uri.path}",
    "{orig_dir}", "{http.request.orig_uri.path.dir}",
    "{orig_file}", "{http.request.orig_uri.path.file}",
    "{orig_query}", "{http.request.orig_uri.query}",
    "{orig_?query}", "{http.request.orig_uri.prefixed_query}",
    "{method}", "{http.request.method}",
    "{uri}", "{http.request.uri}",
    "{%uri}", "{http.request.uri_escaped}",
    "{path}", "{http.request.uri.path}",
    "{%path}", "{http.request.uri.path_escaped}",
    "{dir}", "{http.request.uri.path.dir}",
    "{file}", "{http.request.uri.path.file}",
    "{query}", "{http.request.uri.query}",
    "{%query}", "{http.request.uri.query_escaped}",
    "{?query}", "{http.request.uri.prefixed_query}",
    "{remote}", "{http.request.remote}",
    "{remote_host}", "{http.request.remote.host}",
    "{remote_port}", "{http.request.remote.port}",
    "{scheme}", "{http.request.scheme}",
    "{uuid}", "{http.request.uuid}",
    "{tls_cipher}", "{http.request.tls.cipher_suite}",
    "{tls_version}", "{http.request.tls.version}",
    "{tls_client_fingerprint}", "{http.request.tls.client.fingerprint}",
    "{tls_client_issuer}", "{http.request.tls.client.issuer}",
    "{tls_client_serial}", "{http.request.tls.client.serial}",
    "{tls_client_subject}", "{http.request.tls.client.subject}",
    "{tls_client_certificate_pem}", "{http.request.tls.client.certificate_pem}",
    "{tls_client_certificate_der_base64}", "{http.request.tls.client.certificate_der_base64}",
    "{upstream_hostport}", "{http.reverse_proxy.upstream.hostport}",
    "{client_ip}", "{http.vars.client_ip}",
];

fn complex_shorthands() -> &'static [(Regex, &'static str)] {
    static CELL: OnceLock<Vec<(Regex, &'static str)>> = OnceLock::new();
    CELL.get_or_init(|| {
        let pairs: &[(&str, &str)] = &[
            (r"\{header\.([\w-]*)\}", "{http.request.header.$1}"),
            (r"\{cookie\.([\w-]*)\}", "{http.request.cookie.$1}"),
            (r"\{labels\.([\w-]*)\}", "{http.request.host.labels.$1}"),
            (r"\{path\.([\w-]*)\}", "{http.request.uri.path.$1}"),
            (r"\{file\.([\w-]*)\}", "{http.request.uri.path.file.$1}"),
            (r"\{query\.([\w-]*)\}", "{http.request.uri.query.$1}"),
            (r"\{re\.([\w\-.]*)\}", "{http.regexp.$1}"),
            (r"\{vars\.([\w-]*)\}", "{http.vars.$1}"),
            (r"\{rp\.([\w\-.]*)\}", "{http.reverse_proxy.$1}"),
            (r"\{resp\.([\w\-.]*)\}", "{http.intercept.$1}"),
            (r"\{err\.([\w\-.]*)\}", "{http.error.$1}"),
            (r"\{file_match\.([\w-]*)\}", "{http.matchers.file.$1}"),
        ];
        pairs
            .iter()
            .map(|(p, r)| (Regex::new(p).unwrap(), *r))
            .collect()
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::caddyfile::lexer::tokenize;

    fn defs(input: &str) -> HashMap<String, Value> {
        let mut d = Dispenser::new(tokenize(input, "Caddyfile").unwrap());
        let mut defs = HashMap::new();
        parse_matcher_definitions(&mut d, &mut defs).unwrap();
        defs
    }

    #[test]
    fn single_line_path_matcher() {
        let d = defs("@api path /api/*");
        assert_eq!(d["@api"], json!({"path": ["/api/*"]}));
    }

    #[test]
    fn block_and_semantics() {
        let d = defs("@api {\n  path /api/*\n  method GET POST\n}");
        assert_eq!(
            d["@api"],
            json!({"path": ["/api/*"], "method": ["GET", "POST"]})
        );
    }

    #[test]
    fn header_null_and_value() {
        let d = defs("@h {\n  header X-Foo bar\n  header !X-Bar\n}");
        assert_eq!(
            d["@h"],
            json!({"header": {"X-Foo": ["bar"], "X-Bar": null}})
        );
    }

    #[test]
    fn repeated_header_matchers_overwrite_and_append_like_caddy() {
        let d = defs("@h {\n  header !X-Foo\n  header X-Foo yes\n  header X-Foo no\n}");
        assert_eq!(d["@h"], json!({"header": {"X-Foo": ["yes", "no"]}}));

        let d = defs("@h {\n  header X-Foo yes\n  header !X-Foo\n}");
        assert_eq!(d["@h"], json!({"header": {"X-Foo": null}}));
    }

    #[test]
    fn expression_shorthand_quoted() {
        let d = defs("@e `{http.request.method} == 'GET'`");
        assert_eq!(
            d["@e"],
            json!({"expression": {"expr": "{http.request.method} == 'GET'", "name": "e"}})
        );
    }

    #[test]
    fn not_matcher_nests() {
        let d = defs("@n not path /admin/*");
        assert_eq!(d["@n"], json!({"not": [{"path": ["/admin/*"]}]}));
    }

    #[test]
    fn remote_ip_private_ranges() {
        let d = defs("@p remote_ip private_ranges 1.2.3.4");
        let ranges = d["@p"]["remote_ip"]["ranges"].as_array().unwrap();
        assert!(ranges.contains(&json!("10.0.0.0/8")));
        assert!(ranges.contains(&json!("1.2.3.4")));
    }

    #[test]
    fn inline_path_token() {
        let empty = HashMap::new();
        let (m, ok) = matcher_set_from_matcher_token("/foo*", &empty).unwrap();
        assert!(ok);
        assert_eq!(m.unwrap(), json!({"path": ["/foo*"]}));
    }

    #[test]
    fn wildcard_token() {
        let empty = HashMap::new();
        let (m, ok) = matcher_set_from_matcher_token("*", &empty).unwrap();
        assert!(ok);
        assert!(m.is_none());
    }

    #[test]
    fn shorthand_replacement() {
        assert_eq!(apply_shorthands("{path}"), "{http.request.uri.path}");
        assert_eq!(
            apply_shorthands("{header.X-Foo}"),
            "{http.request.header.X-Foo}"
        );
        assert_eq!(apply_shorthands("{vars.x}"), "{http.vars.x}");
    }
}
