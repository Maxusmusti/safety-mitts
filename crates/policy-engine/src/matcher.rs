use globset::Glob;
use regex::Regex;

/// Check whether `command` matches a command-matcher pattern.
///
/// * If `is_regex` is true the pattern is compiled as a regular expression and
///   tested against the full command string.
/// * Otherwise the pattern is treated as a simplified glob: `*` matches any
///   sequence of characters, and the pattern can contain `|` to express
///   alternatives (OR).  Each alternative is tested as an anchored match
///   against the full command string.
pub fn matches_command(matcher_pattern: &str, is_regex: bool, command: &str) -> bool {
    if is_regex {
        match Regex::new(matcher_pattern) {
            Ok(re) => re.is_match(command),
            Err(e) => {
                tracing::warn!(
                    pattern = matcher_pattern,
                    error = %e,
                    "failed to compile command regex; treating as non-match"
                );
                false
            }
        }
    } else {
        // Glob-style: split on `|` for OR alternatives.
        matcher_pattern.split('|').any(|alt| {
            let alt = alt.trim();
            glob_matches(alt, command)
        })
    }
}

/// Check whether `path` matches a file-path glob pattern.
///
/// Uses the `globset` crate for full glob semantics including `**`, `?`, and
/// character classes.
pub fn matches_file_path(pattern: &str, path: &str) -> bool {
    match Glob::new(pattern) {
        Ok(glob) => {
            let matcher = glob.compile_matcher();
            matcher.is_match(path)
        }
        Err(e) => {
            tracing::warn!(
                pattern,
                error = %e,
                "failed to compile file-path glob; treating as non-match"
            );
            false
        }
    }
}

/// Check whether `method` matches a method-matcher pattern.
///
/// The pattern can contain `|`-separated alternatives.  Each alternative is
/// compared to `method` as an exact (case-sensitive) match.
pub fn matches_method(pattern: &str, method: &str) -> bool {
    pattern.split('|').any(|alt| alt.trim() == method)
}

/// Simple glob matching: convert a pattern with `*` wildcards into a regex and
/// test it anchored against the full input string.
fn glob_matches(pattern: &str, input: &str) -> bool {
    // Build an anchored regex from the glob pattern.
    let mut regex_str = String::with_capacity(pattern.len() + 4);
    regex_str.push('^');
    for ch in pattern.chars() {
        match ch {
            '*' => regex_str.push_str(".*"),
            '?' => regex_str.push('.'),
            // Escape regex-special characters.
            '.' | '+' | '(' | ')' | '[' | ']' | '{' | '}' | '^' | '$' | '\\' | '|' => {
                regex_str.push('\\');
                regex_str.push(ch);
            }
            _ => regex_str.push(ch),
        }
    }
    regex_str.push('$');

    match Regex::new(&regex_str) {
        Ok(re) => re.is_match(input),
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- command matching (glob) ----

    #[test]
    fn glob_exact_match() {
        assert!(matches_command("ls", false, "ls"));
        assert!(!matches_command("ls", false, "ls -la"));
    }

    #[test]
    fn glob_wildcard() {
        assert!(matches_command("ls *", false, "ls -la"));
        assert!(matches_command("ls*", false, "ls"));
        assert!(matches_command("ls*", false, "ls -la"));
        // "ls *" requires the space, so bare "ls" does not match.
        assert!(!matches_command("ls *", false, "ls"));
        // Wildcard matches any trailing content.
        assert!(matches_command("rm *", false, "rm -rf /"));
    }

    #[test]
    fn glob_or_alternatives() {
        assert!(matches_command("ls|pwd|whoami", false, "pwd"));
        assert!(matches_command("ls|pwd|whoami", false, "ls"));
        assert!(!matches_command("ls|pwd|whoami", false, "id"));
    }

    #[test]
    fn glob_or_with_wildcards() {
        assert!(matches_command("cat *|head *|tail *", false, "head -n 10 foo.txt"));
        assert!(!matches_command("cat *|head *|tail *", false, "grep foo bar"));
    }

    #[test]
    fn glob_special_chars_escaped() {
        // Dots and parens in the pattern should be treated literally.
        assert!(matches_command("foo.bar", false, "foo.bar"));
        assert!(!matches_command("foo.bar", false, "fooXbar"));
    }

    // ---- command matching (regex) ----

    #[test]
    fn regex_basic() {
        assert!(matches_command(r"rm\s+-rf\s+/", true, "rm -rf /"));
        assert!(matches_command(r"rm\s+-rf\s+/", true, "rm  -rf  /home"));
        assert!(!matches_command(r"rm\s+-rf\s+/", true, "ls -la"));
    }

    #[test]
    fn regex_anchored() {
        // Regex is not anchored by default, so partial matches work.
        assert!(matches_command(r"sudo", true, "sudo rm -rf /"));
    }

    #[test]
    fn regex_invalid_pattern_returns_false() {
        assert!(!matches_command(r"[invalid", true, "anything"));
    }

    // ---- file path matching ----

    #[test]
    fn file_path_exact() {
        assert!(matches_file_path("/etc/passwd", "/etc/passwd"));
        assert!(!matches_file_path("/etc/passwd", "/etc/shadow"));
    }

    #[test]
    fn file_path_double_star() {
        assert!(matches_file_path("/etc/**", "/etc/nginx/nginx.conf"));
        assert!(matches_file_path("/etc/**", "/etc/passwd"));
        assert!(!matches_file_path("/etc/**", "/var/log/syslog"));
    }

    #[test]
    fn file_path_single_star() {
        assert!(matches_file_path("/tmp/*.log", "/tmp/app.log"));
        // globset's `*` matches across directory separators by default,
        // which is the safer behavior for security rules (blocks more).
        assert!(matches_file_path("/tmp/*.log", "/tmp/sub/app.log"));
    }

    #[test]
    fn file_path_invalid_glob_returns_false() {
        assert!(!matches_file_path("[invalid", "/anything"));
    }

    // ---- method matching ----

    #[test]
    fn method_exact() {
        assert!(matches_method("textDocument/hover", "textDocument/hover"));
        assert!(!matches_method("textDocument/hover", "textDocument/completion"));
    }

    #[test]
    fn method_or_alternatives() {
        let pattern = "textDocument/hover|textDocument/completion|textDocument/definition";
        assert!(matches_method(pattern, "textDocument/hover"));
        assert!(matches_method(pattern, "textDocument/completion"));
        assert!(matches_method(pattern, "textDocument/definition"));
        assert!(!matches_method(pattern, "textDocument/references"));
    }

    #[test]
    fn method_with_spaces_around_pipe() {
        assert!(matches_method("a | b | c", "b"));
        assert!(!matches_method("a | b | c", "d"));
    }
}
