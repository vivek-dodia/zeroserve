//! Token cursor for walking a segment's tokens, a faithful port of
//! `caddyconfig/caddyfile/dispenser.go`. Directive handlers use this to consume
//! their arguments and sub-blocks, exactly as Caddy's `UnmarshalCaddyfile`
//! methods do.

use std::collections::HashMap;

use anyhow::anyhow;

use super::token::{Quote, Token, is_next_on_new_line};

/// Walks a slice of tokens, tracking a cursor and brace nesting level.
#[derive(Clone)]
pub struct Dispenser {
    tokens: Vec<Token>,
    cursor: isize,
    nesting: i32,
    context: HashMap<String, String>,
}

/// Context key used by regexp matchers to name their capture groups (the
/// matcher's name without the leading `@`). Mirrors `MatcherNameCtxKey`.
pub const MATCHER_NAME_CTX_KEY: &str = "matcher_name";

impl Dispenser {
    /// Creates a new dispenser positioned before the first token.
    pub fn new(tokens: Vec<Token>) -> Dispenser {
        Dispenser {
            tokens,
            cursor: -1,
            nesting: 0,
            context: HashMap::new(),
        }
    }

    fn len(&self) -> isize {
        self.tokens.len() as isize
    }

    /// Loads the next token. Returns true if a token was loaded.
    pub fn next(&mut self) -> bool {
        if self.cursor < self.len() - 1 {
            self.cursor += 1;
            return true;
        }
        false
    }

    /// Moves to the previous token (may go to -1 to "start over").
    pub fn prev(&mut self) -> bool {
        if self.cursor > -1 {
            self.cursor -= 1;
            return self.cursor > -1;
        }
        false
    }

    /// Loads the next token if it's on the same line and not a block opening.
    pub fn next_arg(&mut self) -> bool {
        if !self.next_on_same_line() {
            return false;
        }
        if self.val() == "{" {
            self.cursor -= 1;
            return false;
        }
        true
    }

    fn next_on_same_line(&mut self) -> bool {
        if self.cursor < 0 {
            self.cursor += 1;
            return true;
        }
        if self.cursor >= self.len() - 1 {
            return false;
        }
        let curr = &self.tokens[self.cursor as usize];
        let next = &self.tokens[(self.cursor + 1) as usize];
        if !is_next_on_new_line(curr, next) {
            self.cursor += 1;
            return true;
        }
        false
    }

    /// Loads the next token only if it is on a new line.
    pub fn next_line(&mut self) -> bool {
        if self.cursor < 0 {
            self.cursor += 1;
            return true;
        }
        if self.cursor >= self.len() - 1 {
            return false;
        }
        let curr = &self.tokens[self.cursor as usize];
        let next = &self.tokens[(self.cursor + 1) as usize];
        if is_next_on_new_line(curr, next) {
            self.cursor += 1;
            return true;
        }
        false
    }

    /// Iterates the tokens of a block. Use as a loop condition with the nesting
    /// level captured before the loop:
    /// `let nesting = d.nesting(); while d.next_block(nesting) { ... }`.
    pub fn next_block(&mut self, initial_nesting_level: i32) -> bool {
        if self.nesting > initial_nesting_level {
            if !self.next() {
                return false;
            }
            if self.val() == "}" && !self.next_on_same_line() {
                self.nesting -= 1;
            } else if self.val() == "{" && !self.next_on_same_line() {
                self.nesting += 1;
            }
            return self.nesting > initial_nesting_level;
        }
        if !self.next_on_same_line() {
            return false;
        }
        if self.val() != "{" {
            self.cursor -= 1;
            return false;
        }
        self.next(); // consume open curly brace
        if self.val() == "}" {
            return false; // opened and closed right away
        }
        self.nesting += 1;
        true
    }

    /// Returns the current nesting level.
    pub fn nesting(&self) -> i32 {
        self.nesting
    }

    /// Text of the current token (empty if none loaded).
    pub fn val(&self) -> String {
        if self.cursor < 0 || self.cursor >= self.len() {
            return String::new();
        }
        self.tokens[self.cursor as usize].text.clone()
    }

    /// Raw text of the current token, including quotes (but not heredoc marker).
    pub fn val_raw(&self) -> String {
        if self.cursor < 0 || self.cursor >= self.len() {
            return String::new();
        }
        let tok = &self.tokens[self.cursor as usize];
        match tok.quote {
            Quote::Double => format!("\"{}\"", tok.text),
            Quote::Backtick => format!("`{}`", tok.text),
            _ => tok.text.clone(),
        }
    }

    /// Line number of the current token (0 if none).
    pub fn line(&self) -> usize {
        if self.cursor < 0 || self.cursor >= self.len() {
            return 0;
        }
        self.tokens[self.cursor as usize].line
    }

    /// Filename of the current token.
    pub fn file(&self) -> String {
        if self.cursor < 0 || self.cursor >= self.len() {
            return String::new();
        }
        self.tokens[self.cursor as usize].file.clone()
    }

    /// Loads the next arguments into `targets`. Returns false (leaving the
    /// remaining targets unchanged) if there aren't enough argument tokens.
    pub fn args(&mut self, targets: &mut [&mut String]) -> bool {
        for target in targets.iter_mut() {
            if !self.next_arg() {
                return false;
            }
            **target = self.val();
        }
        true
    }

    /// Like [`Dispenser::args`], but requires the argument count to match
    /// exactly.
    pub fn all_args(&mut self, targets: &mut [&mut String]) -> bool {
        if !self.args(targets) {
            return false;
        }
        if self.next_arg() {
            self.prev();
            return false;
        }
        true
    }

    /// Counts remaining arguments on the line without consuming them.
    pub fn count_remaining_args(&mut self) -> usize {
        let mut count = 0;
        while self.next_arg() {
            count += 1;
        }
        for _ in 0..count {
            self.prev();
        }
        count
    }

    /// Loads any remaining arguments (tokens on the same line) into a vec.
    pub fn remaining_args(&mut self) -> Vec<String> {
        let mut args = Vec::new();
        while self.next_arg() {
            args.push(self.val());
        }
        args
    }

    /// Like [`Dispenser::remaining_args`] but retaining quotes.
    pub fn remaining_args_raw(&mut self) -> Vec<String> {
        let mut args = Vec::new();
        while self.next_arg() {
            args.push(self.val_raw());
        }
        args
    }

    /// Loads any remaining arguments as tokens.
    pub fn remaining_args_as_tokens(&mut self) -> Vec<Token> {
        let mut args = Vec::new();
        while self.next_arg() {
            args.push(self.token());
        }
        args
    }

    /// Returns a copy of the tokens from the current token to the end of the
    /// segment (end of line, or end of a block opened at the end of the line).
    pub fn next_segment(&mut self) -> Vec<Token> {
        let mut tkns = vec![self.token()];
        while self.next_arg() {
            tkns.push(self.token());
        }
        let mut opened_block = false;
        let nesting = self.nesting();
        while self.next_block(nesting) {
            if !opened_block {
                // next_block consumed the opening brace; rewind to include it.
                self.prev();
                tkns.push(self.token());
                self.next();
                opened_block = true;
            }
            tkns.push(self.token());
        }
        if opened_block {
            // include the closing brace (without consuming it)
            tkns.push(self.token());
        }
        tkns
    }

    /// A new dispenser over [`Dispenser::next_segment`].
    pub fn new_from_next_segment(&mut self) -> Dispenser {
        Dispenser::new(self.next_segment())
    }

    /// Returns the current token (or an empty token if none).
    pub fn token(&self) -> Token {
        if self.cursor < 0 || self.cursor >= self.len() {
            return Token::new("", 0);
        }
        self.tokens[self.cursor as usize].clone()
    }

    /// Resets the cursor to before the first token.
    pub fn reset(&mut self) {
        self.cursor = -1;
        self.nesting = 0;
    }

    /// Deletes the current token; the cursor is not advanced.
    pub fn delete(&mut self) {
        if self.cursor >= 0 && self.cursor <= self.len() - 1 {
            self.tokens.remove(self.cursor as usize);
            self.cursor -= 1;
        }
    }

    /// True if the current token is on a different (later) line than the
    /// previous token. Returns true if there is no previous token.
    pub fn is_new_line(&self) -> bool {
        if self.cursor < 1 {
            return true;
        }
        if self.cursor > self.len() - 1 {
            return false;
        }
        let prev = &self.tokens[(self.cursor - 1) as usize];
        let curr = &self.tokens[self.cursor as usize];
        is_next_on_new_line(prev, curr)
    }

    /// True if the next token is on a different (later) line than the current.
    pub fn is_next_on_new_line(&self) -> bool {
        if self.cursor < 0 {
            return false;
        }
        if self.cursor >= self.len() - 1 {
            return true;
        }
        let curr = &self.tokens[self.cursor as usize];
        let next = &self.tokens[(self.cursor + 1) as usize];
        is_next_on_new_line(curr, next)
    }

    /// Sets a context key (used by regexp matchers for capture-group naming).
    pub fn set_context(&mut self, key: &str, value: &str) {
        self.context.insert(key.to_string(), value.to_string());
    }

    /// Gets a context string value, or empty string if missing.
    pub fn get_context_string(&self, key: &str) -> String {
        self.context.get(key).cloned().unwrap_or_default()
    }

    // --- error helpers (mirroring the Dispenser error constructors) ---

    /// An "expected another argument" error.
    pub fn arg_err(&self) -> anyhow::Error {
        if self.val() == "{" {
            return self.err("unexpected token '{', expecting argument");
        }
        self.errf(format!(
            "wrong argument count or unexpected line ending after '{}'",
            self.val()
        ))
    }

    /// A syntax error: found the current token, expected `expected`.
    pub fn syntax_err(&self, expected: &str) -> anyhow::Error {
        anyhow!(
            "syntax error: unexpected token '{}', expecting '{}', at {}:{}",
            self.val(),
            expected,
            self.file(),
            self.line()
        )
    }

    /// An unexpected-EOF error.
    pub fn eof_err(&self) -> anyhow::Error {
        self.errf("unexpected EOF")
    }

    /// A custom error annotated with the current file and line.
    pub fn err(&self, msg: &str) -> anyhow::Error {
        anyhow!("{}, at {}:{}", msg, self.file(), self.line())
    }

    /// Like [`Dispenser::err`] but for an owned/formatted message.
    pub fn errf(&self, msg: impl Into<String>) -> anyhow::Error {
        anyhow!("{}, at {}:{}", msg.into(), self.file(), self.line())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::caddyfile::lexer::tokenize;

    fn disp(input: &str) -> Dispenser {
        Dispenser::new(tokenize(input, "Caddyfile").unwrap())
    }

    #[test]
    fn walks_args_on_one_line() {
        let mut d = disp("respond hi 200");
        assert!(d.next());
        assert_eq!(d.val(), "respond");
        assert_eq!(d.remaining_args(), vec!["hi", "200"]);
    }

    #[test]
    fn next_arg_stops_at_block() {
        let mut d = disp("reverse_proxy a b {\n c d\n}");
        assert!(d.next());
        assert_eq!(d.val(), "reverse_proxy");
        assert_eq!(d.remaining_args(), vec!["a", "b"]);
        // The '{' is not an arg; block iteration picks up c, d.
        let nesting = d.nesting();
        let mut inner = Vec::new();
        while d.next_block(nesting) {
            inner.push(d.val());
        }
        assert_eq!(inner, vec!["c", "d"]);
    }

    #[test]
    fn next_segment_includes_braces() {
        let mut d = disp("handle /a* {\n respond hi\n}");
        assert!(d.next());
        let seg: Vec<String> = d.next_segment().into_iter().map(|t| t.text).collect();
        assert_eq!(seg, vec!["handle", "/a*", "{", "respond", "hi", "}"]);
    }
}
