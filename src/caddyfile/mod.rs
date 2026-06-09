//! Caddyfile front-end: parses a native Caddyfile and adapts it to Caddy JSON,
//! faithfully reproducing the output of Caddy's own `caddyfile` +
//! `httpcaddyfile` adapters. The resulting JSON feeds the existing
//! `caddy_compile` back-end (Caddy JSON -> eBPF C).
//!
//! Layering mirrors Caddy:
//!   - [`lexer`]  : bytes -> flat `Vec<Token>` (port of lexer.go)
//!   - [`grammar`]: block interior -> segments (lalrpop; the recursive part)
//!   - [`parser`] : top-level server-block splitting (port of parse.go)
//!   - [`dispenser`] + [`adapter`]: segments -> apps.http JSON (port of
//!     httpcaddyfile)
//!
//! These modules are faithful ports of Caddy's Go packages and intentionally
//! carry the full Dispenser/Helper API surface even where a given method is not
//! yet exercised by the supported directive set, so `dead_code` is allowed for
//! the module tree.
#![allow(dead_code)]

pub mod adapter;
pub mod address;
pub mod dispenser;
pub mod import;
pub mod lexer;
pub mod parser;
pub mod token;
pub mod toks;

use anyhow::Result;
use serde_json::Value;

lalrpop_util::lalrpop_mod!(
    #[allow(clippy::all, clippy::pedantic, dead_code)]
    pub grammar,
    "/caddyfile/grammar.rs"
);

use token::Token;

/// Parses a flat token slice (a block interior, or a bare directive run) into
/// segments using the lalrpop grammar. Each segment is a flat `Vec<Token>`
/// beginning with a directive name.
pub fn parse_segments(tokens: &[Token]) -> Result<Vec<Vec<Token>>> {
    let spanned = toks::to_spanned(tokens);
    grammar::DirectivesParser::new()
        .parse(spanned)
        .map_err(|e| anyhow::anyhow!("caddyfile parse error: {e:?}"))
}

/// Adapts a Caddyfile source string into Caddy JSON, returning the JSON value
/// alongside any warnings (for config that falls outside the supported surface).
pub fn adapt(input: &str, filename: &str) -> Result<(Value, Vec<String>)> {
    let server_blocks = parser::parse(filename, input)?;
    adapter::adapt(server_blocks)
}

/// Adapts a Caddyfile source string into a pretty-printed Caddy JSON string.
pub fn adapt_to_string(input: &str, filename: &str) -> Result<(String, Vec<String>)> {
    let (value, warnings) = adapt(input, filename)?;
    Ok((serde_json::to_string_pretty(&value)?, warnings))
}

#[cfg(test)]
mod grammar_tests {
    use super::*;

    fn segs(input: &str) -> Vec<Vec<String>> {
        let tokens = lexer::tokenize(input, "Caddyfile").unwrap();
        parse_segments(&tokens)
            .unwrap()
            .into_iter()
            .map(|seg| seg.into_iter().map(|t| t.text).collect())
            .collect()
    }

    #[test]
    fn groups_directive_lines() {
        let out = segs("respond hi\nheader X Y");
        assert_eq!(out, vec![vec!["respond", "hi"], vec!["header", "X", "Y"]]);
    }

    #[test]
    fn keeps_block_tokens_flat_in_segment() {
        let out = segs("reverse_proxy localhost:8080 {\n  header_up X Y\n}");
        assert_eq!(
            out,
            vec![vec![
                "reverse_proxy",
                "localhost:8080",
                "{",
                "header_up",
                "X",
                "Y",
                "}"
            ]]
        );
    }

    #[test]
    fn nested_blocks_stay_in_one_segment() {
        let out = segs("handle {\n  respond hi\n  header {\n    X Y\n  }\n}");
        assert_eq!(out.len(), 1);
        assert_eq!(out[0][0], "handle");
        assert_eq!(out[0].last().unwrap(), "}");
    }

    #[test]
    fn blank_lines_ignored() {
        let out = segs("\n\nrespond hi\n\n\nheader X Y\n\n");
        assert_eq!(out.len(), 2);
    }
}
