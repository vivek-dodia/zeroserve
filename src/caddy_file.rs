use std::collections::HashMap;
use std::path::Path;

pub fn display_path(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}

pub fn join_file_path(root: &str, rel: &str) -> Option<String> {
    let joined = match (root.is_empty(), rel.is_empty()) {
        (true, true) => String::new(),
        (true, false) => rel.trim_start_matches('/').to_string(),
        (false, true) => root.to_string(),
        (false, false) => format!(
            "{}/{}",
            root.trim_end_matches('/'),
            rel.trim_start_matches('/')
        ),
    };
    if joined
        .split('/')
        .any(|component| component == "." || component == "..")
    {
        return None;
    }
    Some(joined)
}

pub fn file_hidden(path: &str, hide: &[String]) -> bool {
    if path.is_empty() {
        return false;
    }
    let components = path.split('/').collect::<Vec<_>>();
    for pattern in hide {
        let pattern = pattern.trim();
        if pattern.is_empty() || pattern.contains('{') || pattern.contains('}') {
            continue;
        }
        if pattern.contains('/') {
            if path_hidden(pattern, path) {
                return true;
            }
        } else if components
            .iter()
            .any(|component| glob_match(pattern, component))
        {
            return true;
        }
    }
    false
}

pub fn fs_file_hidden(logical: &str, full_path: &Path, hide: &[String]) -> bool {
    if hide.is_empty() {
        return false;
    }
    let full_path = display_path(full_path);
    let full_components = full_path.split('/').collect::<Vec<_>>();
    let logical_components = logical.split('/').collect::<Vec<_>>();
    for pattern in hide {
        let pattern = pattern.trim();
        if pattern.is_empty() || pattern.contains('{') || pattern.contains('}') {
            continue;
        }
        if pattern.contains('/') {
            let pattern = hide_path_with_cwd(pattern);
            if path_hidden(&pattern, &full_path) {
                return true;
            }
        } else if logical_components
            .iter()
            .chain(full_components.iter())
            .any(|component| glob_match(pattern, component))
        {
            return true;
        }
    }
    false
}

fn hide_path_with_cwd(pattern: &str) -> String {
    let path = Path::new(pattern);
    if path.is_absolute() {
        return display_path(path);
    }
    std::env::current_dir()
        .map(|cwd| display_path(&cwd.join(path)))
        .unwrap_or_else(|_| pattern.replace('\\', "/"))
}

pub fn path_hidden(pattern: &str, path: &str) -> bool {
    if let Some(after) = path.strip_prefix(pattern)
        && (after.is_empty() || after.starts_with('/'))
    {
        return true;
    }
    path_glob_match(pattern, path)
}

pub fn path_glob_match(pattern: &str, value: &str) -> bool {
    let pattern_parts = pattern.split('/').collect::<Vec<_>>();
    let value_parts = value.split('/').collect::<Vec<_>>();
    pattern_parts.len() == value_parts.len()
        && pattern_parts
            .iter()
            .zip(value_parts.iter())
            .all(|(pattern, value)| glob_match(pattern, value))
}

pub fn glob_match(pattern: &str, value: &str) -> bool {
    let pattern = pattern.as_bytes();
    let value = value.as_bytes();
    let mut memo = HashMap::new();
    glob_match_inner(pattern, value, 0, 0, &mut memo)
}

fn glob_match_inner(
    pattern: &[u8],
    value: &[u8],
    pi: usize,
    vi: usize,
    memo: &mut HashMap<(usize, usize), bool>,
) -> bool {
    if let Some(result) = memo.get(&(pi, vi)) {
        return *result;
    }
    let result = if pi == pattern.len() {
        vi == value.len()
    } else {
        match pattern[pi] {
            b'*' => {
                glob_match_inner(pattern, value, pi + 1, vi, memo)
                    || (vi < value.len() && glob_match_inner(pattern, value, pi, vi + 1, memo))
            }
            b'?' => vi < value.len() && glob_match_inner(pattern, value, pi + 1, vi + 1, memo),
            b'[' => {
                if vi >= value.len() {
                    false
                } else if let Some((matched, next_pi)) =
                    glob_class_match(pattern, pi + 1, value[vi])
                {
                    matched && glob_match_inner(pattern, value, next_pi, vi + 1, memo)
                } else {
                    false
                }
            }
            b'\\' => {
                if pi + 1 >= pattern.len() {
                    false
                } else {
                    vi < value.len()
                        && value[vi] == pattern[pi + 1]
                        && glob_match_inner(pattern, value, pi + 2, vi + 1, memo)
                }
            }
            byte => {
                vi < value.len()
                    && value[vi] == byte
                    && glob_match_inner(pattern, value, pi + 1, vi + 1, memo)
            }
        }
    };
    memo.insert((pi, vi), result);
    result
}

fn glob_class_match(pattern: &[u8], mut pi: usize, value: u8) -> Option<(bool, usize)> {
    let negated = matches!(pattern.get(pi), Some(b'^'));
    if negated {
        pi += 1;
    }
    let mut matched = false;
    let mut has_term = false;
    while pi < pattern.len() {
        if pattern[pi] == b']' && has_term {
            return Some((if negated { !matched } else { matched }, pi + 1));
        }
        if pattern[pi] == b'-' {
            return None;
        }
        let (start, next_pi) = glob_class_byte(pattern, pi)?;
        pi = next_pi;
        has_term = true;
        if pi < pattern.len() && pattern[pi] == b'-' {
            if pi + 1 >= pattern.len() || pattern[pi + 1] == b']' {
                return None;
            }
            let (end, after_end) = glob_class_byte(pattern, pi + 1)?;
            pi = after_end;
            if start <= value && value <= end {
                matched = true;
            }
        } else if value == start {
            matched = true;
        }
    }
    None
}

fn glob_class_byte(pattern: &[u8], pi: usize) -> Option<(u8, usize)> {
    if pi >= pattern.len() {
        return None;
    }
    if pattern[pi] == b'\\' && pi + 1 < pattern.len() {
        Some((pattern[pi + 1], pi + 2))
    } else {
        Some((pattern[pi], pi + 1))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn file_hide_path_prefix_hides_descendants() {
        let hide = vec!["public/assets/private".to_string()];
        assert!(file_hidden("public/assets/private", &hide));
        assert!(file_hidden("public/assets/private/nested.txt", &hide));
        assert!(!file_hidden("public/assets/private-ish.txt", &hide));

        let hide = vec!["/public/assets/private".to_string()];
        assert!(!file_hidden("public/assets/private", &hide));
    }

    #[test]
    fn glob_matches_bracket_classes_like_filepath_match() {
        assert!(glob_match("[A-Z][0-9][!@#][[]end[]]", "A5![end]"));
        assert!(!glob_match("[A-Z][0-9][!@#][[]end[]]", "a5![end]"));
    }
}
