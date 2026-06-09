//! Top-level Caddyfile parsing, ported from `caddyconfig/caddyfile/parse.go`
//! (`parseAll`/`begin`/`addresses`/`blockContents`/snippet & named-route
//! handling). This is the part of Caddy that is procedural and not
//! context-free: the per-block braced-vs-bare decision and the multi-line
//! address handling. Each block's interior token run is handed to the lalrpop
//! grammar (via [`super::parse_segments`]) to be grouped into segments.

use std::collections::HashMap;

use anyhow::{Result, bail};

use super::dispenser::Dispenser;
use super::import;
use super::lexer::tokenize;
use super::token::Token;

/// A server block: a set of address keys plus the directive segments parsed
/// from its body. Mirrors `caddyfile.ServerBlock`.
#[derive(Debug, Clone, Default)]
pub struct ServerBlock {
    pub keys: Vec<Token>,
    pub segments: Vec<Vec<Token>>,
    pub has_braces: bool,
    pub is_named_route: bool,
}

impl ServerBlock {
    /// The text of each key.
    pub fn keys_text(&self) -> Vec<String> {
        self.keys.iter().map(|k| k.text.clone()).collect()
    }
}

/// Parses a Caddyfile into server blocks (in source order). Environment
/// variables are expanded and `import`/snippets are resolved first.
pub fn parse(filename: &str, input: &str) -> Result<Vec<ServerBlock>> {
    let tokens = tokenize(input, filename)?;
    // Resolve snippet definitions and `import` directives at the token level,
    // exactly the layer Caddy operates `import` on.
    let tokens = import::expand(tokens, filename)?;

    let mut parser = Parser {
        d: Dispenser::new(tokens),
    };
    parser.parse_all()
}

struct Parser {
    d: Dispenser,
}

impl Parser {
    fn parse_all(&mut self) -> Result<Vec<ServerBlock>> {
        let mut blocks = Vec::new();
        while self.d.next() {
            if let Some(block) = self.parse_one()? {
                if !block.keys.is_empty() || !block.segments.is_empty() {
                    blocks.push(block);
                }
            }
        }
        Ok(blocks)
    }

    fn parse_one(&mut self) -> Result<Option<ServerBlock>> {
        self.begin()
    }

    fn begin(&mut self) -> Result<Option<ServerBlock>> {
        let mut block = ServerBlock::default();

        // Collect the address keys.
        let eof = self.addresses(&mut block)?;
        if eof {
            // A line of addresses and nothing else.
            return Ok(Some(block));
        }

        // Named route: a single `&(name)` key.
        if let Some(name) = is_named_route(&block.keys) {
            let mut name_token = self.d.token();
            name_token.text = name;
            block.keys = vec![name_token];
            block.is_named_route = true;
            let interior = self.block_tokens(false)?;
            block.segments = super::parse_segments(&interior)?;
            return Ok(Some(block));
        }

        // Snippet: a single `(name)` key. Snippets are resolved during import
        // expansion, so any that survive here are unused definitions — skip them.
        if is_snippet(&block.keys).is_some() {
            self.block_tokens(false)?; // consume the block
            return Ok(None);
        }

        // Otherwise this is a site block (or the global options block, which is
        // simply a block with empty keys).
        self.block_contents(&mut block)?;
        Ok(Some(block))
    }

    /// Collects address keys. Returns true if EOF was reached during/just after
    /// the addresses (a bare line of addresses). Faithful port of `addresses`.
    fn addresses(&mut self, block: &mut ServerBlock) -> Result<bool> {
        let mut expecting_another = false;
        loop {
            let mut value = self.d.val();
            let token = self.d.token();

            if value.starts_with('@') {
                bail!(
                    "request matchers may not be defined globally, they must be in a site block; found {value}"
                );
            }

            if value == "{" {
                if expecting_another {
                    bail!("Expected another address but had '{value}' - check for extra comma");
                }
                block.has_braces = true;
                break;
            }

            if value.ends_with('{') && value != "{" {
                bail!(
                    "Site addresses cannot end with a curly brace: '{value}' - put a space between the token and the brace"
                );
            }

            if !value.is_empty() {
                if value.ends_with(',') {
                    value.pop();
                    expecting_another = true;
                } else {
                    expecting_another = false;
                }

                if value.contains(',') {
                    bail!(
                        "Site addresses cannot contain a comma ',': '{value}' - put a space after the comma to separate site addresses"
                    );
                }

                if !value.is_empty() {
                    let mut key = token;
                    key.text = value;
                    block.keys.push(key);
                }
            }

            let has_next = self.d.next();
            if expecting_another && !has_next {
                return Err(self.d.eof_err());
            }
            if !has_next {
                return Ok(true); // EOF
            }
            if !expecting_another && self.d.is_new_line() {
                break;
            }
        }
        Ok(false)
    }

    /// Parses the body of a site block, handling the with-braces and the
    /// brace-less single-server forms. Faithful port of `blockContents`.
    fn block_contents(&mut self, block: &mut ServerBlock) -> Result<()> {
        let has_open = self.d.val() == "{";
        let interior = if has_open {
            self.block_tokens(false)?
        } else {
            // Single-server config without braces: the rest of the input is this
            // block's directives. Rewind one (`cursor--`) so the current token is
            // included, then take everything to EOF.
            self.collect_to_eof_including_current()
        };
        block.segments = super::parse_segments(&interior)?;
        Ok(())
    }

    /// Reads and returns all tokens within a brace block (interior only, nested
    /// braces retained). Assumes the current token is `{`. Faithful port of
    /// `blockTokens(false)`.
    fn block_tokens(&mut self, retain_curlies: bool) -> Result<Vec<Token>> {
        if self.d.val() != "{" {
            return Err(self.d.syntax_err("{"));
        }
        let mut nesting = 1;
        let mut tokens: Vec<Token> = Vec::new();
        if retain_curlies {
            tokens.push(self.d.token());
        }
        while self.d.next() {
            if self.d.val() == "}" {
                nesting -= 1;
                if nesting == 0 {
                    if retain_curlies {
                        tokens.push(self.d.token());
                    }
                    break;
                }
            }
            if self.d.val() == "{" {
                nesting += 1;
            }
            tokens.push(self.d.token());
        }
        if nesting != 0 {
            return Err(self.d.syntax_err("}"));
        }
        Ok(tokens)
    }

    /// Collects the current token and all subsequent tokens to EOF (used for the
    /// brace-less single-server form).
    fn collect_to_eof_including_current(&mut self) -> Vec<Token> {
        let mut tokens = vec![self.d.token()];
        while self.d.next() {
            tokens.push(self.d.token());
        }
        tokens
    }
}

/// Returns the snippet name if `keys` is a single `(name)` key.
pub fn is_snippet(keys: &[Token]) -> Option<String> {
    if keys.len() == 1 {
        let t = &keys[0].text;
        if t.starts_with('(') && t.ends_with(')') {
            return Some(t[1..t.len() - 1].to_string());
        }
    }
    None
}

/// Returns the named-route name if `keys` is a single `&(name)` key.
pub fn is_named_route(keys: &[Token]) -> Option<String> {
    if keys.len() == 1 {
        let t = &keys[0].text;
        if t.starts_with("&(") && t.ends_with(')') {
            return Some(t[2..t.len() - 1].to_string());
        }
    }
    None
}

/// Snippet definitions found at the top level, keyed by name. Used by import
/// expansion. Mirrors the `definedSnippets` map.
pub type SnippetTable = HashMap<String, Vec<Token>>;

#[cfg(test)]
mod tests {
    use super::*;

    fn block_summary(input: &str) -> Vec<(Vec<String>, usize)> {
        parse("Caddyfile", input)
            .unwrap()
            .into_iter()
            .map(|b| (b.keys_text(), b.segments.len()))
            .collect()
    }

    #[test]
    fn single_braced_site() {
        let out = block_summary("example.com {\n  respond hi\n}");
        assert_eq!(out, vec![(vec!["example.com".to_string()], 1)]);
    }

    #[test]
    fn multiple_keys() {
        let out = block_summary("example.com, www.example.com {\n  respond hi\n}");
        assert_eq!(out[0].0, vec!["example.com", "www.example.com"]);
    }

    #[test]
    fn bare_single_site() {
        let out = block_summary("localhost\nrespond hi\nheader X Y");
        // One block: keys=[localhost], segments=[respond hi],[header X Y]
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].0, vec!["localhost"]);
        assert_eq!(out[0].1, 2);
    }

    #[test]
    fn global_options_block_has_empty_keys() {
        let out = block_summary("{\n  http_port 8080\n}\nexample.com {\n  respond hi\n}");
        assert_eq!(out.len(), 2);
        assert!(out[0].0.is_empty()); // global options
        assert_eq!(out[1].0, vec!["example.com"]);
    }

    #[test]
    fn address_only_block() {
        let out = block_summary("localhost");
        assert_eq!(out, vec![(vec!["localhost".to_string()], 0)]);
    }

    #[test]
    fn multiline_addresses_with_trailing_comma() {
        let out = block_summary("example.com,\nwww.example.com {\n respond hi\n}");
        assert_eq!(out[0].0, vec!["example.com", "www.example.com"]);
    }
}
