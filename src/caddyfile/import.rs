//! `import` directive and snippet handling, a pragmatic port of the relevant
//! parts of `parse.go` (`doImport`) and `importargs.go`. Operates at the token
//! level before structural parsing: snippet definitions `(name) { ... }` are
//! collected and stripped, then `import <snippet|file> [args...]` occurrences
//! are spliced in with positional/variadic argument and block substitution.

use std::{
    collections::HashMap,
    path::{Path, PathBuf},
};

use anyhow::{Result, bail};

use super::lexer::tokenize;
use super::token::{Token, is_next_on_new_line};

/// Expands snippets and `import` directives in `tokens`. `filename` is the
/// source path, used to resolve relative file imports.
pub fn expand(tokens: Vec<Token>, filename: &str) -> Result<Vec<Token>> {
    let mut snippets = HashMap::new();
    let tokens = collect_snippets(tokens, &mut snippets)?;
    expand_imports(tokens, &mut snippets, filename)
}

type Snippets = HashMap<String, Snippet>;

#[derive(Clone)]
struct Snippet {
    node: String,
    tokens: Vec<Token>,
}

struct Imported {
    nodes: Vec<String>,
    tokens: Vec<Token>,
}

#[derive(Default)]
struct ImportGraph {
    edges: HashMap<String, Vec<String>>,
}

impl ImportGraph {
    fn add_edges(&mut self, from: &str, to: &[String]) -> Result<()> {
        for node in to {
            if self.reaches(node, from) {
                bail!("a cycle of imports exists between {from} and {node}");
            }
            let edges = self.edges.entry(from.to_string()).or_default();
            if !edges.contains(node) {
                edges.push(node.clone());
            }
        }
        Ok(())
    }

    fn reaches(&self, from: &str, to: &str) -> bool {
        let mut seen = HashMap::new();
        self.reaches_inner(from, to, &mut seen)
    }

    fn reaches_inner(&self, from: &str, to: &str, seen: &mut HashMap<String, bool>) -> bool {
        if from == to {
            return true;
        }
        if seen.insert(from.to_string(), true).is_some() {
            return false;
        }
        self.edges
            .get(from)
            .into_iter()
            .flatten()
            .any(|next| self.reaches_inner(next, to, seen))
    }
}

fn is_paren_name(text: &str) -> bool {
    text.len() >= 2 && text.starts_with('(') && text.ends_with(')')
}

fn at_line_start(tokens: &[Token], i: usize) -> bool {
    i == 0 || is_next_on_new_line(&tokens[i - 1], &tokens[i])
}

/// Collects top-level `(name) { ... }` snippet definitions, removing them from
/// the returned token stream.
fn collect_snippets(tokens: Vec<Token>, snippets: &mut Snippets) -> Result<Vec<Token>> {
    let mut out = Vec::with_capacity(tokens.len());
    let mut i = 0;
    let mut nesting = 0i32;
    while i < tokens.len() {
        let t = &tokens[i];
        if nesting == 0
            && at_line_start(&tokens, i)
            && is_paren_name(&t.text)
            && i + 1 < tokens.len()
            && tokens[i + 1].text == "{"
        {
            let name = t.text[1..t.text.len() - 1].to_string();
            let (interior, close_idx) = capture_block(&tokens, i + 1)?;
            let interior: Vec<Token> = interior
                .into_iter()
                .map(|mut tk| {
                    tk.snippet_name = name.clone();
                    tk
                })
                .collect();
            let node = format!("{}:{name}", t.file);
            snippets.insert(
                name,
                Snippet {
                    node,
                    tokens: interior,
                },
            );
            i = close_idx + 1;
            continue;
        }
        match t.text.as_str() {
            "{" => nesting += 1,
            "}" => nesting -= 1,
            _ => {}
        }
        out.push(t.clone());
        i += 1;
    }
    Ok(out)
}

/// Returns the interior tokens of a brace block (nested braces retained) and the
/// index of the matching closing brace. `open_idx` must point at the `{`.
fn capture_block(tokens: &[Token], open_idx: usize) -> Result<(Vec<Token>, usize)> {
    let mut nesting = 1i32;
    let mut interior = Vec::new();
    let mut j = open_idx + 1;
    while j < tokens.len() {
        let text = tokens[j].text.as_str();
        if text == "}" {
            nesting -= 1;
            if nesting == 0 {
                return Ok((interior, j));
            }
            interior.push(tokens[j].clone());
        } else {
            if text == "{" {
                nesting += 1;
            }
            interior.push(tokens[j].clone());
        }
        j += 1;
    }
    bail!("unclosed block starting at line {}", tokens[open_idx].line);
}

fn expand_imports(
    mut tokens: Vec<Token>,
    snippets: &mut Snippets,
    filename: &str,
) -> Result<Vec<Token>> {
    // Re-scan from the start after each expansion so nested imports resolve.
    // The iteration cap guards against import cycles.
    const MAX_ITERS: usize = 10_000;
    let mut graph = ImportGraph::default();
    for _ in 0..MAX_ITERS {
        let Some(idx) = find_import(&tokens) else {
            return Ok(tokens);
        };
        if idx + 1 >= tokens.len() || is_next_on_new_line(&tokens[idx], &tokens[idx + 1]) {
            bail!(
                "import requires a non-empty filepath, at line {}",
                tokens[idx].line
            );
        }
        let target = tokens[idx + 1].text.clone();
        let mut end = idx + 1;
        let mut args = Vec::new();
        let mut import_block = None;
        let mut k = idx + 2;
        while k < tokens.len() && !is_next_on_new_line(&tokens[k - 1], &tokens[k]) {
            if tokens[k].text == "{" {
                let (interior, close_idx) = capture_block(&tokens, k)?;
                import_block = Some(interior);
                end = close_idx;
                break;
            }
            args.push(tokens[k].text.clone());
            end = k;
            k += 1;
        }

        let imported = resolve(
            &target,
            &args,
            import_block.as_deref(),
            snippets,
            filename,
            &tokens[idx],
        )?;
        let node = import_node(&tokens[idx]);
        graph.add_edges(&node, &imported.nodes)?;

        let mut new = Vec::with_capacity(tokens.len() + imported.tokens.len());
        new.extend_from_slice(&tokens[..idx]);
        new.extend(imported.tokens);
        new.extend_from_slice(&tokens[end + 1..]);
        tokens = new;
    }
    bail!("too many import expansions (possible import cycle)");
}

/// Finds the first `import` directive (a token "import" at the start of a line).
fn find_import(tokens: &[Token]) -> Option<usize> {
    (0..tokens.len()).find(|&i| tokens[i].text == "import" && at_line_start(tokens, i))
}

fn resolve(
    target: &str,
    args: &[String],
    import_block: Option<&[Token]>,
    snippets: &mut Snippets,
    filename: &str,
    import_tok: &Token,
) -> Result<Imported> {
    let Imported { nodes, tokens } = if let Some(snippet) = snippets.get(target) {
        Imported {
            nodes: vec![snippet.node.clone()],
            tokens: snippet.tokens.clone(),
        }
    } else {
        let Imported { nodes, tokens } = import_files(target, filename, import_tok)?;
        let tokens = collect_snippets(tokens, snippets)?;
        Imported { nodes, tokens }
    };
    Ok(Imported {
        nodes,
        tokens: apply_import_placeholders(tokens, args, import_block, import_tok)?,
    })
}

fn import_node(tok: &Token) -> String {
    if tok.snippet_name.is_empty() {
        tok.file.clone()
    } else {
        format!("{}:{}", tok.file, tok.snippet_name)
    }
}

fn import_files(pattern: &str, filename: &str, import_tok: &Token) -> Result<Imported> {
    let dir = Path::new(filename)
        .parent()
        .unwrap_or_else(|| Path::new("."));
    let glob_pattern: PathBuf = if Path::new(pattern).is_absolute() {
        PathBuf::from(pattern)
    } else {
        dir.join(pattern)
    };
    let pattern_str = glob_pattern.to_string_lossy().to_string();
    let has_glob = pattern_str.contains(['*', '?', '[', ']']);
    if pattern_str.matches('*').count() > 1
        || pattern_str.matches('?').count() > 1
        || (pattern_str.contains('[') && pattern_str.contains(']'))
    {
        bail!("glob pattern may only contain one wildcard (*), but has others: {pattern_str}");
    }

    let mut out = Vec::new();
    let mut nodes = Vec::new();
    let mut matched = false;
    // Support a literal path, or a single trailing-component glob via std read_dir.
    if has_glob {
        let parent = glob_pattern.parent().unwrap_or_else(|| Path::new("."));
        let needle = glob_pattern
            .file_name()
            .map(|s| s.to_string_lossy().to_string())
            .unwrap_or_default();
        let skip_dotfiles = needle.starts_with('*');
        if let Ok(entries) = std::fs::read_dir(parent) {
            let mut paths: Vec<PathBuf> = entries
                .flatten()
                .map(|e| e.path())
                .filter(|p| {
                    let name = p
                        .file_name()
                        .map(|s| s.to_string_lossy().to_string())
                        .unwrap_or_default();
                    !(skip_dotfiles && name.starts_with('.')) && glob_match(&needle, &name)
                })
                .collect();
            paths.sort();
            for p in paths {
                matched = true;
                nodes.push(import_file_node(&p));
                out.extend(read_and_tokenize(&p)?);
            }
        }
    } else if glob_pattern.is_file() {
        matched = true;
        nodes.push(import_file_node(&glob_pattern));
        out.extend(read_and_tokenize(&glob_pattern)?);
    }

    if !matched && !has_glob {
        bail!(
            "file to import not found: {} (resolved from {}:{})",
            pattern,
            import_tok.file,
            import_tok.line
        );
    }
    Ok(Imported { nodes, tokens: out })
}

fn import_file_node(path: &Path) -> String {
    std::fs::canonicalize(path)
        .unwrap_or_else(|_| path.to_path_buf())
        .to_string_lossy()
        .to_string()
}

fn read_and_tokenize(path: &Path) -> Result<Vec<Token>> {
    let content = std::fs::read_to_string(path)
        .map_err(|e| anyhow::anyhow!("could not import {}: {e}", path.display()))?;
    let abs = std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    tokenize(&content, &abs.to_string_lossy())
}

/// Minimal glob supporting a single `*` (any run) and `?` (any one char), which
/// matches Caddy's restriction to a single wildcard in import patterns.
fn glob_match(pattern: &str, name: &str) -> bool {
    if let Some(star) = pattern.find('*') {
        let (pre, post) = (&pattern[..star], &pattern[star + 1..]);
        return name.len() >= pre.len() + post.len()
            && name.starts_with(pre)
            && name.ends_with(post);
    }
    if pattern.contains('?') {
        return pattern.len() == name.len()
            && pattern
                .chars()
                .zip(name.chars())
                .all(|(p, c)| p == '?' || p == c);
    }
    pattern == name
}

/// Applies positional/variadic argument and block substitution to imported
/// tokens. Imported snippet/file tokens receive an import chain, but tokens
/// substituted from the caller's import block keep their original provenance so
/// Caddy's line-boundary rules continue to separate them from the snippet's
/// surrounding braces.
fn apply_import_placeholders(
    tokens: Vec<Token>,
    args: &[String],
    import_block: Option<&[Token]>,
    import_tok: &Token,
) -> Result<Vec<Token>> {
    let chain = if import_tok.snippet_name.is_empty() {
        format!("{}:{} (import)", import_tok.file, import_tok.line)
    } else {
        format!(
            "{}:{} (import {})",
            import_tok.file, import_tok.line, import_tok.snippet_name
        )
    };
    let empty = [];
    let import_block = import_block.unwrap_or(&empty);
    let named_blocks = named_import_blocks(import_block)?;
    let mut out = Vec::with_capacity(tokens.len());
    for tok in tokens {
        let mut tok = tok;
        tok.imports.push(chain.clone());
        if let Some((start, end)) = parse_variadic(&tok.text, args.len()) {
            for a in &args[start..end] {
                let mut t2 = tok.clone();
                t2.text = a.clone();
                out.push(t2);
            }
        } else if tok.text == "{block}" {
            out.extend(import_block.iter().cloned());
        } else if let Some(name) = tok
            .text
            .strip_prefix("{blocks.")
            .and_then(|s| s.strip_suffix('}'))
        {
            if let Some(block) = named_blocks.get(name) {
                out.extend(block.iter().cloned());
            }
        } else {
            tok.text = replace_args(&tok.text, args);
            out.push(tok);
        }
    }
    Ok(out)
}

fn named_import_blocks(tokens: &[Token]) -> Result<std::collections::HashMap<String, Vec<Token>>> {
    let mut blocks = std::collections::HashMap::new();
    let mut i = 0;
    while i < tokens.len() {
        if !at_line_start(tokens, i) {
            i += 1;
            continue;
        }
        if tokens[i].text == "{" {
            bail!("anonymous blocks are not supported");
        }

        let key = tokens[i].text.clone();
        let mut mapping = Vec::new();
        let mut j = i + 1;
        while j < tokens.len() && !is_next_on_new_line(&tokens[j - 1], &tokens[j]) {
            if tokens[j].text == "{" {
                let (interior, close_idx) = capture_block(tokens, j)?;
                mapping.extend(interior);
                j = close_idx + 1;
                break;
            }
            mapping.push(tokens[j].clone());
            j += 1;
        }
        blocks.insert(key, mapping);
        i = j;
    }
    Ok(blocks)
}

/// Port of `parseVariadic`: detects a `{args[start:end]}` placeholder that is a
/// token on its own and returns the index range into `args`.
fn parse_variadic(text: &str, arg_count: usize) -> Option<(usize, usize)> {
    let inner = text.strip_prefix("{args[")?.strip_suffix("]}")?;
    if inner.is_empty() {
        return None;
    }
    let (start, end) = inner.split_once(':')?;
    if start.contains('}') || end.contains('{') {
        return None;
    }
    let start_index = if start.is_empty() {
        0
    } else {
        start.parse::<usize>().ok()?
    };
    let end_index = if end.is_empty() {
        arg_count
    } else {
        end.parse::<usize>().ok()?
    };
    if start_index > end_index || end_index > arg_count {
        return None;
    }
    Some((start_index, end_index))
}

/// Replaces `{args[N]}` and the deprecated `{args.N}` placeholders within a
/// token's text with the corresponding positional argument.
fn replace_args(text: &str, args: &[String]) -> String {
    let mut result = text.to_string();
    for (i, arg) in args.iter().enumerate() {
        result = result.replace(&format!("{{args[{i}]}}"), arg);
        result = result.replace(&format!("{{args.{i}}}"), arg);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn expanded_texts(input: &str) -> Vec<String> {
        let tokens = tokenize(input, "Caddyfile").unwrap();
        expand(tokens, "Caddyfile")
            .unwrap()
            .into_iter()
            .map(|t| t.text)
            .collect()
    }

    fn expand_error(input: &str) -> String {
        let tokens = tokenize(input, "Caddyfile").unwrap();
        expand(tokens, "Caddyfile").unwrap_err().to_string()
    }

    fn temp_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "zeroserve-caddy-import-{name}-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn snippet_definition_is_stripped() {
        let out = expanded_texts("(snip) {\n  respond hi\n}\nexample.com {\n  respond yo\n}");
        assert!(!out.contains(&"(snip)".to_string()));
        assert!(out.contains(&"example.com".to_string()));
    }

    #[test]
    fn import_inlines_snippet() {
        let out = expanded_texts("(snip) {\n  respond hi\n}\nexample.com {\n  import snip\n}");
        // import is replaced by snippet body tokens.
        assert!(out.iter().any(|t| t == "respond"));
        assert!(!out.iter().any(|t| t == "import"));
    }

    #[test]
    fn file_import_registers_snippets_like_caddy() {
        let dir = temp_dir("file-snippet");
        let snippet_file = dir.join("snippets.conf");
        fs::write(&snippet_file, "(snip) {\n  respond from-file\n}\n").unwrap();
        let caddyfile = dir.join("Caddyfile");
        let input = "import snippets.conf\nexample.com {\n  import snip\n}";
        let tokens = tokenize(input, &caddyfile.to_string_lossy()).unwrap();
        let out: Vec<String> = expand(tokens, &caddyfile.to_string_lossy())
            .unwrap()
            .into_iter()
            .map(|t| t.text)
            .collect();

        assert!(out.iter().any(|t| t == "respond"));
        assert!(out.iter().any(|t| t == "from-file"));
        assert!(!out.iter().any(|t| t == "import"));
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn import_substitutes_positional_args() {
        let out = expanded_texts(
            "(greet) {\n  respond {args[0]}\n}\nexample.com {\n  import greet hello\n}",
        );
        assert!(out.iter().any(|t| t == "hello"));
        assert!(!out.iter().any(|t| t.contains("args[0]")));
    }

    #[test]
    fn import_substitutes_anonymous_block() {
        let out = expanded_texts(
            "(snip) {\n  header {\n    {block}\n  }\n}\nexample.com {\n  import snip {\n    foo bar\n  }\n}",
        );
        assert!(out.iter().any(|t| t == "foo"));
        assert!(out.iter().any(|t| t == "bar"));
        assert!(!out.iter().any(|t| t == "{block}"));
    }

    #[test]
    fn import_substitutes_named_blocks() {
        let out = expanded_texts(
            "(snip) {\n  header {\n    {blocks.foo}\n  }\n  header {\n    {blocks.bar}\n  }\n}\nexample.com {\n  import snip {\n    foo {\n      X-Foo a\n    }\n    bar {\n      X-Bar b\n    }\n  }\n}",
        );
        assert!(out.iter().any(|t| t == "X-Foo"));
        assert!(out.iter().any(|t| t == "X-Bar"));
        assert!(!out.iter().any(|t| t.contains("blocks.")));
    }

    #[test]
    fn import_rejects_anonymous_blocks_like_caddy() {
        let err = expand_error(
            "(snip) {\n  {block}\n}\nexample.com {\n  import snip {\n    {\n      header foo bar\n    }\n  }\n}",
        );
        assert!(err.contains("anonymous blocks are not supported"));
    }

    #[test]
    fn import_named_blocks_keep_same_line_args_like_caddy() {
        let out = expanded_texts(
            "(snip) {\n  header {\n    {blocks.foo}\n  }\n}\nexample.com {\n  import snip {\n    foo X-Foo a\n  }\n}",
        );
        assert!(out.iter().any(|t| t == "X-Foo"));
        assert!(out.iter().any(|t| t == "a"));
    }

    #[test]
    fn import_reports_snippet_cycles_like_caddy() {
        let err = expand_error("(a) {\n  import b\n}\n(b) {\n  import a\n}\nimport a\n");
        assert!(err.contains("a cycle of imports exists between Caddyfile:b and Caddyfile:a"));
    }

    #[test]
    fn import_allows_unmatched_globs_like_caddy() {
        let dir = temp_dir("unmatched-glob");
        let caddyfile = dir.join("Caddyfile");
        let input = "example.com {\n  import missing/*\n  respond ok\n}";
        let tokens = tokenize(input, &caddyfile.to_string_lossy()).unwrap();
        let out: Vec<String> = expand(tokens, &caddyfile.to_string_lossy())
            .unwrap()
            .into_iter()
            .map(|t| t.text)
            .collect();
        assert!(out.iter().any(|t| t == "respond"));
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn import_globs_skip_dotfiles_only_for_star_prefix_like_caddy() {
        let dir = temp_dir("dotfiles");
        fs::write(dir.join("visible.caddy"), "respond visible\n").unwrap();
        fs::write(dir.join(".hidden.caddy"), "respond hidden\n").unwrap();
        let caddyfile = dir.join("Caddyfile");

        let star = format!("example.com {{\n  import {}/*.caddy\n}}", dir.display());
        let star_tokens = tokenize(&star, &caddyfile.to_string_lossy()).unwrap();
        let star_out: Vec<String> = expand(star_tokens, &caddyfile.to_string_lossy())
            .unwrap()
            .into_iter()
            .map(|t| t.text)
            .collect();
        assert!(star_out.iter().any(|t| t == "visible"));
        assert!(!star_out.iter().any(|t| t == "hidden"));

        let dot = format!("example.com {{\n  import {}/.*\n}}", dir.display());
        let dot_tokens = tokenize(&dot, &caddyfile.to_string_lossy()).unwrap();
        let dot_out: Vec<String> = expand(dot_tokens, &caddyfile.to_string_lossy())
            .unwrap()
            .into_iter()
            .map(|t| t.text)
            .collect();
        assert!(dot_out.iter().any(|t| t == "hidden"));
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn import_rejects_broad_globs_like_caddy() {
        let err = expand_error("import /*/*.txt\n");
        assert!(err.contains("glob pattern may only contain one wildcard"));
    }
}
