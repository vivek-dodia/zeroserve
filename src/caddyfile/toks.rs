//! Bridges the hand-written lexer to the lalrpop grammar. lalrpop uses an
//! external token stream (our [`Tok`]); this module maps a flat `[Token]` slice
//! into that stream, inserting an explicit [`Tok::Nl`] terminal wherever two
//! adjacent tokens are on different logical lines. This converts Caddy's
//! line-number-based segment grouping into something an LR grammar can consume.

use super::token::{Token, is_next_on_new_line};

/// External terminal type consumed by the lalrpop grammar. Block delimiters
/// `{`/`}` become [`Tok::Open`]/[`Tok::Close`]; every other token is a
/// [`Tok::Word`]; line breaks (at any nesting) become [`Tok::Nl`].
#[derive(Debug, Clone)]
pub enum Tok {
    Word(Token),
    Open(Token),
    Close(Token),
    Nl,
}

/// A located token, as lalrpop's external-lexer interface expects:
/// `Result<(start, token, end), error>`.
pub type Spanned = Result<(usize, Tok, usize), String>;

/// Converts a flat token slice (a block interior, or a bare directive run) into
/// the located stream the grammar parses. An [`Tok::Nl`] is inserted between any
/// two tokens on different lines per [`is_next_on_new_line`]. The Nl stream is
/// normalized for the grammar: runs of Nl are collapsed to one, and leading and
/// trailing Nls are dropped, so segments are separated by exactly one Nl.
pub fn to_spanned(tokens: &[Token]) -> Vec<Spanned> {
    let mut out: Vec<Spanned> = Vec::with_capacity(tokens.len() * 2);
    let mut pending_nl = false;
    for (i, tok) in tokens.iter().enumerate() {
        if i > 0 && is_next_on_new_line(&tokens[i - 1], tok) {
            pending_nl = true;
        }
        // Emit a single separator Nl only between real tokens (never leading).
        if pending_nl && !out.is_empty() {
            out.push(Ok((i, Tok::Nl, i)));
        }
        pending_nl = false;
        let mapped = match tok.text.as_str() {
            "{" => Tok::Open(tok.clone()),
            "}" => Tok::Close(tok.clone()),
            _ => Tok::Word(tok.clone()),
        };
        out.push(Ok((i, mapped, i + 1)));
    }
    out
}
