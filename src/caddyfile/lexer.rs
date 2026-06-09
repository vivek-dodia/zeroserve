//! Caddyfile lexer, a faithful port of `caddyconfig/caddyfile/lexer.go`
//! (`lexer.next`, `finalizeHeredoc`) plus the `{$ENV:default}` substitution
//! from `parse.go` (`replaceEnvVars`). Turns input bytes into a flat list of
//! [`Token`]s with accurate line numbers, which downstream parsing relies on to
//! group tokens into segments.

use anyhow::{Result, bail};

use super::token::{Quote, Token};

/// Lexes `input` into Caddyfile tokens, attributing them to `filename`.
/// Environment variables in `{$VAR}` / `{$VAR:default}` notation are expanded
/// first, exactly as Caddy does before parsing.
pub fn tokenize(input: &str, filename: &str) -> Result<Vec<Token>> {
    let expanded = replace_env_vars(input);
    let mut lexer = Lexer::new(&expanded);
    let mut tokens = Vec::new();
    while let Some(mut token) = lexer.next_token()? {
        token.file = filename.to_string();
        tokens.push(token);
    }
    Ok(tokens)
}

struct Lexer {
    chars: Vec<char>,
    pos: usize,
    line: usize,
    skipped_lines: usize,
}

impl Lexer {
    fn new(input: &str) -> Lexer {
        let mut chars: Vec<char> = input.chars().collect();
        // Discard byte order mark, if present.
        if chars.first() == Some(&'\u{FEFF}') {
            chars.remove(0);
        }
        Lexer {
            chars,
            pos: 0,
            line: 1,
            skipped_lines: 0,
        }
    }

    fn read(&mut self) -> Option<char> {
        let ch = self.chars.get(self.pos).copied();
        if ch.is_some() {
            self.pos += 1;
        }
        ch
    }

    /// Loads the next token. Returns `Ok(None)` when all tokens are consumed.
    /// Faithful port of `lexer.next`.
    fn next_token(&mut self) -> Result<Option<Token>> {
        let mut val: Vec<char> = Vec::new();
        let mut comment = false;
        let mut quoted = false;
        let mut bt_quoted = false;
        let mut in_heredoc = false;
        let mut heredoc_escaped = false;
        let mut escaped = false;
        let mut heredoc_marker = String::new();
        // Line where the current token began; set when the first char lands.
        let mut token_line = self.line;

        loop {
            let Some(ch) = self.read() else {
                // EOF (the only read failure for an in-memory buffer).
                if !val.is_empty() {
                    if in_heredoc {
                        bail!(
                            "incomplete heredoc <<{} on line #{}, expected ending marker {}",
                            heredoc_marker,
                            self.line + self.skipped_lines,
                            heredoc_marker
                        );
                    }
                    return Ok(Some(self.make_token(
                        &val,
                        Quote::None,
                        &heredoc_marker,
                        token_line,
                    )));
                }
                return Ok(None);
            };

            // Detect whether we have the start of a heredoc.
            if (!quoted && !bt_quoted)
                && (!in_heredoc && !heredoc_escaped)
                && val.len() > 1
                && val[0] == '<'
                && val[1] == '<'
            {
                // A space means it's just a regular token and not a heredoc.
                if ch == ' ' {
                    return Ok(Some(self.make_token(
                        &val,
                        Quote::None,
                        &heredoc_marker,
                        token_line,
                    )));
                }
                // Skip CR, we only care about LF.
                if ch == '\r' {
                    continue;
                }
                if ch == '\n' {
                    if val.len() == 2 {
                        bail!(
                            "missing opening heredoc marker on line #{}; must contain only alphanumeric characters, dashes and underscores; got empty string",
                            self.line
                        );
                    }
                    if val.len() >= 3 && val[2] == '<' {
                        bail!(
                            "too many '<' for heredoc on line #{}; only use two, for example <<END",
                            self.line
                        );
                    }
                    heredoc_marker = val[2..].iter().collect();
                    if !is_valid_heredoc_marker(&heredoc_marker) {
                        bail!(
                            "heredoc marker on line #{} must contain only alphanumeric characters, dashes and underscores; got '{}'",
                            self.line,
                            heredoc_marker
                        );
                    }
                    in_heredoc = true;
                    self.skipped_lines += 1;
                    val.clear();
                    continue;
                }
                val.push(ch);
                continue;
            }

            // If we're in a heredoc, all characters are read as-is.
            if in_heredoc {
                val.push(ch);
                if ch == '\n' {
                    self.skipped_lines += 1;
                }
                // Check if we're done, i.e. the last chars are the marker.
                let marker_len = heredoc_marker.chars().count();
                if val.len() >= marker_len
                    && val[val.len() - marker_len..].iter().collect::<String>() == heredoc_marker
                {
                    let finalized = self.finalize_heredoc(&val, &heredoc_marker, token_line)?;
                    self.line += self.skipped_lines;
                    self.skipped_lines = 0;
                    return Ok(Some(self.make_token(
                        &finalized,
                        Quote::Heredoc,
                        &heredoc_marker,
                        token_line,
                    )));
                }
                continue;
            }

            // Track whether we found an escape '\' for the next iteration.
            if !escaped && !bt_quoted && ch == '\\' {
                escaped = true;
                continue;
            }

            if quoted || bt_quoted {
                if quoted && escaped {
                    // All is literal in a quoted area, so only escape quotes.
                    if ch != '"' {
                        val.push('\\');
                    }
                    escaped = false;
                } else if (quoted && ch == '"') || (bt_quoted && ch == '`') {
                    let q = if quoted {
                        Quote::Double
                    } else {
                        Quote::Backtick
                    };
                    return Ok(Some(self.make_token(&val, q, &heredoc_marker, token_line)));
                }
                // Allow quoted text to wrap and continue on multiple lines.
                if ch == '\n' {
                    self.line += 1 + self.skipped_lines;
                    self.skipped_lines = 0;
                }
                val.push(ch);
                continue;
            }

            if ch.is_whitespace() {
                // Ignore CR altogether, we only care about LF.
                if ch == '\r' {
                    continue;
                }
                if ch == '\n' {
                    // Newlines can be escaped to chain arguments onto multiple
                    // lines; else, increment the line count.
                    if escaped {
                        self.skipped_lines += 1;
                        escaped = false;
                    } else {
                        self.line += 1 + self.skipped_lines;
                        self.skipped_lines = 0;
                    }
                    // Comments (#) are single-line only.
                    comment = false;
                }
                // Any kind of space means we're at the end of this token.
                if !val.is_empty() {
                    return Ok(Some(self.make_token(
                        &val,
                        Quote::None,
                        &heredoc_marker,
                        token_line,
                    )));
                }
                continue;
            }

            // Comments must be at the start of a token, in other words,
            // preceded by space or newline.
            if ch == '#' && val.is_empty() {
                comment = true;
            }
            if comment {
                continue;
            }

            if val.is_empty() {
                token_line = self.line;
                if ch == '"' {
                    quoted = true;
                    continue;
                }
                if ch == '`' {
                    bt_quoted = true;
                    continue;
                }
            }

            if escaped {
                // Allow escaping the first < to skip the heredoc syntax.
                if ch == '<' {
                    heredoc_escaped = true;
                } else {
                    val.push('\\');
                }
                escaped = false;
            }

            val.push(ch);
        }
    }

    fn make_token(&self, val: &[char], quote: Quote, marker: &str, line: usize) -> Token {
        Token {
            file: String::new(),
            imports: Vec::new(),
            line,
            text: val.iter().collect(),
            quote,
            heredoc_marker: marker.to_string(),
            snippet_name: String::new(),
        }
    }

    /// Strips the leading whitespace (matching the closing marker's indentation)
    /// from each line of a heredoc. Faithful port of `lexer.finalizeHeredoc`.
    fn finalize_heredoc(&self, val: &[char], marker: &str, start_line: usize) -> Result<Vec<char>> {
        let marker_len = marker.chars().count();
        // Find the last newline of the heredoc, where the contents end.
        let last_newline = val.iter().rposition(|&c| c == '\n').unwrap_or(0);

        // Lines preceding the marker line (split keeps a trailing empty entry,
        // matching Go's strings.Split on a string ending in '\n').
        let head: &[char] = &val[..last_newline + 1];
        let mut lines: Vec<Vec<char>> = Vec::new();
        let mut cur: Vec<char> = Vec::new();
        for &c in head {
            if c == '\n' {
                lines.push(std::mem::take(&mut cur));
            } else {
                cur.push(c);
            }
        }
        lines.push(cur); // trailing empty segment after the last '\n'

        // The padding to strip is the indentation before the marker.
        let padding: Vec<char> = val[last_newline + 1..val.len() - marker_len].to_vec();

        let mut out: Vec<char> = Vec::new();
        for (idx, line_text) in lines[..lines.len() - 1].iter().enumerate() {
            if line_text.is_empty() || (line_text.len() == 1 && line_text[0] == '\r') {
                out.push('\n');
                continue;
            }
            // The padding must match exactly at the start.
            if !line_text.starts_with(&padding[..]) {
                let clean: String = line_text
                    .iter()
                    .collect::<String>()
                    .trim_end_matches(['\r', '\n'])
                    .to_string();
                bail!(
                    "mismatched leading whitespace in heredoc <<{} on line #{} [{}], expected whitespace [{}] to match the closing marker",
                    marker,
                    start_line + idx + 1,
                    clean,
                    padding.iter().collect::<String>()
                );
            }
            for &c in &line_text[padding.len()..] {
                if c != '\r' {
                    out.push(c);
                }
            }
            out.push('\n');
        }

        // Remove the trailing newline from the loop.
        if out.last() == Some(&'\n') {
            out.pop();
        }
        Ok(out)
    }
}

fn is_valid_heredoc_marker(marker: &str) -> bool {
    !marker.is_empty()
        && marker
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
}

/// Replaces all occurrences of `{$ENV}` / `{$ENV:default}` with the environment
/// variable's value (or default). Faithful port of `parse.go`'s
/// `replaceEnvVars`. Substitution is single-pass (no recursive expansion).
pub fn replace_env_vars(input: &str) -> String {
    const SPAN_OPEN: &str = "{$";
    const SPAN_CLOSE: &str = "}";
    let mut input = input.to_string();
    let mut offset = 0usize;
    loop {
        let Some(begin_rel) = input[offset..].find(SPAN_OPEN) else {
            break;
        };
        let begin = begin_rel + offset;
        let search_from = begin + SPAN_OPEN.len();
        let Some(end_rel) = input[search_from..].find(SPAN_CLOSE) else {
            break;
        };
        let end = end_rel + search_from;

        let env_string = &input[search_from..end];
        if env_string.is_empty() {
            offset = end + SPAN_CLOSE.len();
            continue;
        }

        let mut parts = env_string.splitn(2, ':');
        let key = parts.next().unwrap_or("");
        let default = parts.next();
        let value = match std::env::var(key) {
            Ok(v) => v,
            Err(_) => default.unwrap_or("").to_string(),
        };

        let mut new = String::with_capacity(input.len());
        new.push_str(&input[..begin]);
        new.push_str(&value);
        new.push_str(&input[end + SPAN_CLOSE.len()..]);
        offset = begin + value.len();
        input = new;
    }
    input
}

#[cfg(test)]
mod tests {
    use super::*;

    fn texts(input: &str) -> Vec<String> {
        tokenize(input, "Caddyfile")
            .unwrap()
            .into_iter()
            .map(|t| t.text)
            .collect()
    }

    #[test]
    fn splits_words_and_braces() {
        assert_eq!(
            texts("example.com {\n  respond hi\n}"),
            vec!["example.com", "{", "respond", "hi", "}"]
        );
    }

    #[test]
    fn placeholder_is_one_token() {
        assert_eq!(
            texts("respond {http.request.uri}"),
            vec!["respond", "{http.request.uri}"]
        );
    }

    #[test]
    fn empty_object_placeholder_is_one_token() {
        assert_eq!(texts("respond {}"), vec!["respond", "{}"]);
    }

    #[test]
    fn double_quotes_keep_spaces() {
        let toks = tokenize("respond \"hello world\"", "Caddyfile").unwrap();
        assert_eq!(toks[1].text, "hello world");
        assert_eq!(toks[1].quote, Quote::Double);
    }

    #[test]
    fn backticks_keep_spaces() {
        let toks = tokenize("respond `a b`", "Caddyfile").unwrap();
        assert_eq!(toks[1].text, "a b");
        assert_eq!(toks[1].quote, Quote::Backtick);
    }

    #[test]
    fn comments_are_skipped() {
        assert_eq!(
            texts("respond hi # trailing\n# whole line\nfoo"),
            vec!["respond", "hi", "foo"]
        );
    }

    #[test]
    fn line_continuation_keeps_same_line() {
        let toks = tokenize("respond a \\\n  b", "Caddyfile").unwrap();
        assert_eq!(
            toks.iter().map(|t| t.text.clone()).collect::<Vec<_>>(),
            vec!["respond", "a", "b"]
        );
        // All on the same logical line thanks to the backslash continuation.
        assert_eq!(toks[0].line, 1);
        assert_eq!(toks[2].line, 1);
    }

    #[test]
    fn line_numbers_advance() {
        let toks = tokenize("a\nb\nc", "Caddyfile").unwrap();
        assert_eq!(toks[0].line, 1);
        assert_eq!(toks[1].line, 2);
        assert_eq!(toks[2].line, 3);
    }

    #[test]
    fn heredoc_strips_indentation() {
        let input = "respond <<EOF\n    line one\n    line two\n    EOF 200";
        let toks = tokenize(input, "Caddyfile").unwrap();
        assert_eq!(toks[0].text, "respond");
        assert_eq!(toks[1].text, "line one\nline two");
        assert_eq!(toks[1].quote, Quote::Heredoc);
        assert_eq!(toks[2].text, "200");
    }

    #[test]
    fn heredoc_num_line_breaks() {
        let input = "respond <<EOF\na\nb\nEOF";
        let toks = tokenize(input, "Caddyfile").unwrap();
        // "a\nb" => 1 newline + 2 heredoc framing = 3.
        assert_eq!(toks[1].num_line_breaks(), 3);
    }

    #[test]
    fn heredoc_mismatched_whitespace_reports_content_line_like_caddy() {
        let err = tokenize(
            "handle {\n\trespond <<END\n\tline1\n\tline2\n  END\n}",
            "Caddyfile",
        )
        .unwrap_err()
        .to_string();
        assert!(
            err.contains(
                "mismatched leading whitespace in heredoc <<END on line #3 [\tline1], expected whitespace [  ] to match the closing marker"
            ),
            "{err}"
        );
    }

    #[test]
    fn heredoc_invalid_marker_reports_line_like_caddy() {
        let err = tokenize(
            "handle {\n    respond <<END!\n    Hello\n    END!\n}",
            "Caddyfile",
        )
        .unwrap_err()
        .to_string();
        assert!(
            err.contains(
                "heredoc marker on line #2 must contain only alphanumeric characters, dashes and underscores; got 'END!'"
            ),
            "{err}"
        );
    }

    #[test]
    fn env_var_default_used_when_unset() {
        let out = replace_env_vars("http_port {$ZS_TEST_NOPE:8081}");
        assert_eq!(out, "http_port 8081");
    }

    #[test]
    fn env_var_value_used_when_set() {
        // SAFETY: single-threaded test setting a process-unique var.
        unsafe { std::env::set_var("ZS_TEST_PORT_X", "9090") };
        let out = replace_env_vars("http_port {$ZS_TEST_PORT_X:8081}");
        assert_eq!(out, "http_port 9090");
    }
}
