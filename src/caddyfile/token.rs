//! Caddyfile tokens, ported from `caddyconfig/caddyfile/lexer.go` (the `Token`
//! type) and the `isNextOnNewLine` helper in the same file. A token is a single
//! "word" of a Caddyfile; tokens are separated by whitespace unless quoted.

/// The kind of quoting that enclosed a token, if any. Mirrors the `wasQuoted`
/// rune in Caddy: `0` (none), `"` (double quote), `` ` `` (backtick), or `<`
/// (heredoc).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Quote {
    None,
    Double,
    Backtick,
    Heredoc,
}

impl Quote {
    /// True if the token was enclosed in quotes (double, backtick or heredoc).
    pub fn quoted(self) -> bool {
        !matches!(self, Quote::None)
    }
}

/// A single parsable unit of a Caddyfile.
#[derive(Debug, Clone)]
pub struct Token {
    /// Source file the token came from (used for `import` relative paths and
    /// for `is_next_on_new_line` boundary detection).
    pub file: String,
    /// Import chain, namespacing tokens spliced in via `import`. Each entry is a
    /// human-readable "file:line (import ...)" string, matching Caddy.
    pub imports: Vec<String>,
    /// 1-based line number where the token starts.
    pub line: usize,
    /// The token's text (with quotes/heredoc markers stripped).
    pub text: String,
    /// How the token was quoted, if at all.
    pub quote: Quote,
    /// The heredoc marker, if this token was a heredoc.
    pub heredoc_marker: String,
    /// Snippet the token was defined in, if any (for import cycle detection).
    pub snippet_name: String,
}

impl Token {
    /// Construct a bare token with the given text and line; other fields default.
    pub fn new(text: impl Into<String>, line: usize) -> Token {
        Token {
            file: String::new(),
            imports: Vec::new(),
            line,
            text: text.into(),
            quote: Quote::None,
            heredoc_marker: String::new(),
            snippet_name: String::new(),
        }
    }

    /// True if the token was enclosed in quotes (double, backtick or heredoc).
    pub fn quoted(&self) -> bool {
        self.quote.quoted()
    }

    /// Counts how many line breaks are in the token text. Heredocs have an extra
    /// two line breaks because the opening delimiter is on its own line and is
    /// not included in the token text, and the trailing newline is removed.
    /// Faithful port of `Token.NumLineBreaks`.
    pub fn num_line_breaks(&self) -> usize {
        let mut breaks = self.text.matches('\n').count();
        if self.quote == Quote::Heredoc {
            breaks += 2;
        }
        breaks
    }
}

/// Tests whether `t2` is on a different line from `t1`. Faithful port of
/// `isNextOnNewLine` in `lexer.go`: a token from a different file or a different
/// import chain is always considered to be on a new line.
pub fn is_next_on_new_line(t1: &Token, t2: &Token) -> bool {
    if t1.file != t2.file {
        return true;
    }
    if t1.imports.len() != t2.imports.len() {
        return true;
    }
    for (a, b) in t1.imports.iter().zip(t2.imports.iter()) {
        if a != b {
            return true;
        }
    }
    t1.line + t1.num_line_breaks() < t2.line
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn num_line_breaks_counts_newlines() {
        let t = Token::new("a\nb\nc", 1);
        assert_eq!(t.num_line_breaks(), 2);
    }

    #[test]
    fn heredoc_adds_two_line_breaks() {
        let mut t = Token::new("line1\nline2", 1);
        t.quote = Quote::Heredoc;
        // 1 newline in text + 2 for heredoc framing.
        assert_eq!(t.num_line_breaks(), 3);
    }

    #[test]
    fn next_on_new_line_uses_line_and_breaks() {
        let a = Token::new("a", 1);
        let same = Token::new("b", 1);
        let next = Token::new("c", 2);
        assert!(!is_next_on_new_line(&a, &same));
        assert!(is_next_on_new_line(&a, &next));
    }

    #[test]
    fn different_file_is_new_line() {
        let mut a = Token::new("a", 5);
        a.file = "A".into();
        let mut b = Token::new("b", 1);
        b.file = "B".into();
        assert!(is_next_on_new_line(&a, &b));
    }
}
