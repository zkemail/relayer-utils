use crate::regex::types::{
    DecomposedRegexConfig, ExtractionError, ExtractionResult, NFAGraph, RegexPart,
};
use fancy_regex::Regex;

/// Converts capturing groups to non-capturing groups `(?:...)` in a regex pattern.
/// Matches zk-regex-compiler's behavior: https://github.com/zkemail/zk-regex/blob/3d37c3110fbd1baa96d048ab658bcb47acd8731b/compiler/src/utils.rs#L37
///
/// This function converts:
/// - Bare capturing groups `(...)` to `(?:...)`
/// - Named captures `(?<name>...)` (PCRE style) to `(?:...)`
/// - Named captures `(?P<name>...)` (Rust style) to `(?:...)`
///
/// This function properly handles:
/// - Escaped parentheses like `\(` and `\)` (preserved as-is)
/// - Parentheses within character classes like `[()]` (preserved as-is)
/// - Special groups like `(?:...)`, `(?=...)`, `(?!...)`, etc. (preserved as-is)
///
/// # Arguments
///
/// * `pattern` - The regex pattern string to process
///
/// # Returns
///
/// A new string with all capturing groups converted to non-capturing groups
///
/// # Examples
///
/// ```text
/// convert_bare_groups_to_non_capturing("(a|b)")         → "(?:a|b)"
/// convert_bare_groups_to_non_capturing("(?<name>abc)")  → "(?:abc)"
/// convert_bare_groups_to_non_capturing("(?P<name>abc)") → "(?:abc)"
/// convert_bare_groups_to_non_capturing("(?:a|b)")       → "(?:a|b)" // unchanged
/// convert_bare_groups_to_non_capturing(r"\(a\)")        → r"\(a\)"  // escaped parens preserved
/// convert_bare_groups_to_non_capturing("[()]")          → "[()]"    // char class preserved
/// ```
fn convert_bare_groups_to_non_capturing(pattern: &str) -> String {
    let mut result = String::with_capacity(pattern.len() + pattern.len() / 4);
    let chars: Vec<char> = pattern.chars().collect();
    let mut i = 0;
    let mut in_char_class = false;
    let mut escaped = false;

    while i < chars.len() {
        let ch = chars[i];

        if escaped {
            // Previous char was backslash, this char is escaped
            result.push(ch);
            escaped = false;
        } else if ch == '\\' {
            // Start escape sequence
            result.push(ch);
            escaped = true;
        } else if ch == '[' && !in_char_class {
            // Entering character class
            result.push(ch);
            in_char_class = true;
        } else if ch == ']' && in_char_class {
            // Exiting character class
            result.push(ch);
            in_char_class = false;
        } else if ch == '(' && !in_char_class {
            // Check if this is a capturing group that needs conversion
            if i + 1 >= chars.len() || chars[i + 1] != '?' {
                // Bare capturing group: (...)
                result.push_str("(?:");
            } else if i + 2 < chars.len() && chars[i + 2] == '<' {
                // Could be: (?<=...) positive lookbehind, or (?<!...) negative lookbehind, or (?<name>...) PCRE named capture
                if i + 3 < chars.len() && (chars[i + 3] == '=' || chars[i + 3] == '!') {
                    // Lookbehind assertion: (?<=...) or (?<!...)
                    // These are special groups, preserve as-is
                    result.push(ch);
                } else {
                    // PCRE named capture: (?<name>...)
                    // Convert to non-capturing and skip the name
                    result.push_str("(?:");
                    i += 2; // Skip '?' and '<'
                    // Skip until we find the closing '>'
                    while i + 1 < chars.len() && chars[i + 1] != '>' {
                        i += 1;
                    }
                    if i + 1 < chars.len() && chars[i + 1] == '>' {
                        i += 1; // Skip the '>'
                    }
                }
            } else if i + 3 < chars.len() && chars[i + 2] == 'P' && chars[i + 3] == '<' {
                // Rust named capture: (?P<name>...)
                // Convert to non-capturing and skip the name
                result.push_str("(?:");
                i += 3; // Skip '?', 'P', and '<'
                // Skip until we find the closing '>'
                while i + 1 < chars.len() && chars[i + 1] != '>' {
                    i += 1;
                }
                if i + 1 < chars.len() && chars[i + 1] == '>' {
                    i += 1; // Skip the '>'
                }
            } else {
                // Other special group like (?:...), (?=...), etc.
                result.push(ch);
            }
        } else {
            result.push(ch);
        }

        i += 1;
    }

    result
}

/// Extracts substring indices matching a decomposed regex pattern
///
/// This function supports two modes:
///
/// 1. **With NFAGraph** (`nfa_graph = Some(&nfa)`):
///    - Uses capture groups from the compiler's NFAGraph
///    - Ensures extraction aligns with circuit witness generation
///    - Recommended when used in circuit contexts
///
/// 2. **Without NFAGraph** (`nfa_graph = None`):
///    - Creates capture groups based on PublicPattern parts
///    - Works standalone without compiler dependency
///    - Suitable for simple extraction use cases
///
/// # Capture Group Handling
///
/// To ensure stable and predictable capture group numbering, this function automatically
/// converts bare capturing groups `(...)` to non-capturing groups `(?:...)` within
/// PublicPattern parts before wrapping them in an outer capturing group. This prevents
/// nested capture groups from interfering with the expected group indices.
///
/// For example:
/// - Input pattern: `"(\w+)@(\d+)"`
/// - Converted to: `"((?:\w+)@(?:\d+))"` (only 1 capture group)
///
/// Existing special groups like `(?:...)`, `(?=...)`, `(?!...)`, etc. are preserved as-is.
///
/// # Arguments
/// * `input` - The input string to search
/// * `config` - The decomposed regex configuration
/// * `nfa_graph` - Optional NFAGraph from compiler (use when available)
/// * `reveal_private` - Whether to include private (non-public) pattern matches
///
/// # Returns
/// A vector of (start, end) tuples for each match
///
/// # Examples
///
/// Basic usage without `NFAGraph`:
/// ```
/// use relayer_utils::{DecomposedRegexConfig, RegexPart, extract_substr_idxes};
///
/// let config = DecomposedRegexConfig {
///     parts: vec![
///         RegexPart::Pattern("prefix:".to_string()),
///         RegexPart::PublicPattern(("\\w+".to_string(), 20)),
///     ],
/// };
///
/// let input = "prefix:hello world prefix:test";
/// let indices = extract_substr_idxes(input, &config, None, false).unwrap();
///
/// assert_eq!(&input[indices[0].0..indices[0].1], "hello");
/// assert_eq!(&input[indices[1].0..indices[1].1], "test");
/// ```
///
/// With `NFAGraph` (circuit context):
/// ```ignore
/// use relayer_utils::{NFAGraph, DecomposedRegexConfig, RegexPart, extract_substr_idxes};
///
/// // Pseudocode: obtain a valid regex graph JSON from the compiler
/// let regex_graph_json = "...";
/// let nfa = NFAGraph::from_json(&regex_graph_json)?;
///
/// let config = DecomposedRegexConfig {
///     parts: vec![
///         RegexPart::Pattern("prefix:".to_string()),
///         RegexPart::PublicPattern(("\\w+".to_string(), 20)),
///     ],
/// };
///
/// let input = "prefix:hello";
/// let indices = extract_substr_idxes(input, &config, Some(&nfa), false)?;
/// assert_eq!(&input[indices[0].0..indices[0].1], "hello");
/// ```
pub fn extract_substr_idxes(
    input: &str,
    config: &DecomposedRegexConfig,
    nfa_graph: Option<&NFAGraph>,
    reveal_private: bool,
) -> ExtractionResult<Vec<(usize, usize)>> {
    if let Some(nfa) = nfa_graph {
        // Path 1: Use NFAGraph's capture groups
        extract_with_nfa(input, config, nfa, reveal_private)
    } else {
        // Path 2: Create our own capture groups
        extract_without_nfa(input, config, reveal_private)
    }
}

/// Extract using NFAGraph's capture group structure
fn extract_with_nfa(
    input: &str,
    config: &DecomposedRegexConfig,
    nfa: &NFAGraph,
    reveal_private: bool,
) -> ExtractionResult<Vec<(usize, usize)>> {
    // Parse capture groups from NFAGraph
    let capture_group_count = nfa.num_capture_groups;

    // Compose pattern maintaining NFA's structure
    // The NFAGraph already knows which parts are capture groups
    let pattern = compose_pattern_for_nfa(config, nfa)?;

    // Compile and execute regex
    let regex =
        Regex::new(&pattern).map_err(|e| ExtractionError::CompilationError(e.to_string()))?;

    let mut results = Vec::new();

    for captures in regex.captures_iter(input) {
        let captures = captures.map_err(|e| ExtractionError::MatchFailed(e.to_string()))?;

        if reveal_private {
            // Return full match
            if let Some(m) = captures.get(0) {
                results.push((m.start(), m.end()));
            }
        } else {
            // Return only captures corresponding to PublicPattern parts
            // Capture groups are numbered 1..=capture_group_count
            for group_id in 1..=capture_group_count {
                if let Some(m) = captures.get(group_id) {
                    results.push((m.start(), m.end()));
                }
            }
        }
    }

    if results.is_empty() {
        Err(ExtractionError::NoMatch)
    } else {
        Ok(results)
    }
}

/// Extract creating own capture groups from config
fn extract_without_nfa(
    input: &str,
    config: &DecomposedRegexConfig,
    reveal_private: bool,
) -> ExtractionResult<Vec<(usize, usize)>> {
    // Compose pattern with capture groups around PublicPattern parts
    let (pattern, public_group_indices) = compose_pattern_standalone(config)?;

    // Compile and execute regex
    let regex =
        Regex::new(&pattern).map_err(|e| ExtractionError::CompilationError(e.to_string()))?;

    let mut results = Vec::new();

    for captures in regex.captures_iter(input) {
        let captures = captures.map_err(|e| ExtractionError::MatchFailed(e.to_string()))?;

        if reveal_private {
            // Return full match
            if let Some(m) = captures.get(0) {
                results.push((m.start(), m.end()));
            }
        } else {
            // Return only public capture groups
            for group_idx in &public_group_indices {
                if let Some(m) = captures.get(*group_idx) {
                    results.push((m.start(), m.end()));
                }
            }
        }
    }

    if results.is_empty() {
        Err(ExtractionError::NoMatch)
    } else {
        Ok(results)
    }
}

/// Compose pattern for NFAGraph-based extraction
/// Trust that the NFAGraph knows the correct capture group structure
fn compose_pattern_for_nfa(
    config: &DecomposedRegexConfig,
    nfa: &NFAGraph,
) -> ExtractionResult<String> {
    let mut pattern = String::new();
    let mut public_count = 0;

    for part in &config.parts {
        match part {
            RegexPart::Pattern(p) => {
                let adjusted_pattern = convert_bare_groups_to_non_capturing(p);
                pattern.push_str(&adjusted_pattern);
            }
            RegexPart::PublicPattern((p, _max_bytes)) => {
                public_count += 1;
                // Convert any bare capturing groups to non-capturing groups to prevent
                // nested capture groups from interfering with the expected group numbering
                let adjusted_pattern = convert_bare_groups_to_non_capturing(p);
                // Wrap in capturing group
                pattern.push_str(&format!("({})", adjusted_pattern).as_str());
            }
        };
    }

    // Verify we got the expected number of public parts
    if public_count != nfa.num_capture_groups {
        return Err(ExtractionError::InvalidConfig(format!(
            "Config has {} public parts but NFAGraph has {} capture groups",
            public_count, nfa.num_capture_groups
        )));
    }

    if pattern.is_empty() {
        return Err(ExtractionError::InvalidConfig("Empty pattern".to_string()));
    }

    Ok(pattern)
}

/// Compose pattern for standalone extraction
/// Create capture groups around PublicPattern parts
fn compose_pattern_standalone(
    config: &DecomposedRegexConfig,
) -> ExtractionResult<(String, Vec<usize>)> {
    let mut pattern = String::new();
    let mut public_group_indices = Vec::new();
    let mut current_group = 1; // Group 0 is always the full match

    for part in &config.parts {
        match part {
            RegexPart::Pattern(p) => {
                let adjusted_pattern = convert_bare_groups_to_non_capturing(p);
                pattern.push_str(&adjusted_pattern);
            }
            RegexPart::PublicPattern((p, _max_bytes)) => {
                public_group_indices.push(current_group);
                current_group += 1;
                // Convert any bare capturing groups to non-capturing groups to prevent
                // nested capture groups from interfering with the expected group numbering
                let adjusted_pattern = convert_bare_groups_to_non_capturing(p);
                // Wrap in capturing group
                pattern.push_str(&format!("({})", adjusted_pattern).as_str());
            }
        };
    }

    if pattern.is_empty() {
        return Err(ExtractionError::InvalidConfig("Empty pattern".to_string()));
    }

    Ok((pattern, public_group_indices))
}

/// Extracts actual substrings matching a decomposed regex pattern
///
/// # Arguments
/// * `input` - The input string to search
/// * `config` - The decomposed regex configuration
/// * `nfa_graph` - Optional NFAGraph from compiler
/// * `reveal_private` - Whether to include private (non-public) pattern matches
///
/// # Returns
/// A vector of matched strings
pub fn extract_substr(
    input: &str,
    config: &DecomposedRegexConfig,
    nfa_graph: Option<&NFAGraph>,
    reveal_private: bool,
) -> ExtractionResult<Vec<String>> {
    let indices = extract_substr_idxes(input, config, nfa_graph, reveal_private)?;

    Ok(indices
        .into_iter()
        .map(|(start, end)| input[start..end].to_string())
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_without_nfa() {
        let config = DecomposedRegexConfig {
            parts: vec![
                RegexPart::Pattern("prefix:".to_string()),
                RegexPart::PublicPattern(("\\w+".to_string(), 20)),
            ],
        };

        let input = "prefix:hello world prefix:test";
        let result = extract_substr_idxes(input, &config, None, false).unwrap();

        // Should find "hello" and "test" (public parts only)
        assert_eq!(result.len(), 2);
        assert_eq!(&input[result[0].0..result[0].1], "hello");
        assert_eq!(&input[result[1].0..result[1].1], "test");
    }

    #[test]
    fn test_extract_substr() {
        let config = DecomposedRegexConfig {
            parts: vec![
                RegexPart::Pattern("from:".to_string()),
                RegexPart::PublicPattern(("[a-z]+@[a-z]+\\.com".to_string(), 50)),
            ],
        };

        let input = "from:alice@example.com";
        let result = extract_substr(input, &config, None, false).unwrap();

        assert_eq!(result, vec!["alice@example.com"]);
    }

    #[test]
    fn test_no_match_returns_error() {
        let config = DecomposedRegexConfig {
            parts: vec![RegexPart::Pattern("notfound".to_string())],
        };

        let input = "this does not match";
        let result = extract_substr_idxes(input, &config, None, false);

        assert!(matches!(result, Err(ExtractionError::NoMatch)));
    }

    #[test]
    fn test_reveal_private_returns_full_match() {
        let config = DecomposedRegexConfig {
            parts: vec![
                RegexPart::Pattern("prefix:".to_string()),
                RegexPart::PublicPattern(("\\w+".to_string(), 20)),
            ],
        };

        let input = "prefix:hello";

        // reveal_private = false: only public part
        let public_only = extract_substr_idxes(input, &config, None, false).unwrap();
        assert_eq!(&input[public_only[0].0..public_only[0].1], "hello");

        // reveal_private = true: full match
        let full_match = extract_substr_idxes(input, &config, None, true).unwrap();
        assert_eq!(&input[full_match[0].0..full_match[0].1], "prefix:hello");
    }

    #[test]
    fn test_nested_capturing_groups_converted() {
        // Test that bare capturing groups inside PublicPattern are converted to non-capturing
        // This ensures stable capture group numbering
        let config = DecomposedRegexConfig {
            parts: vec![
                RegexPart::Pattern("data:".to_string()),
                RegexPart::PublicPattern(("(\\w+)-(\\d+)".to_string(), 50)),
            ],
        };

        let input = "data:hello-123";
        let result = extract_substr_idxes(input, &config, None, false).unwrap();

        // Should extract the entire public pattern match, not individual nested groups
        assert_eq!(result.len(), 1, "Should have exactly one capture group");
        assert_eq!(&input[result[0].0..result[0].1], "hello-123");
    }

    #[test]
    fn test_multiple_public_patterns_with_nested_groups() {
        // Test multiple PublicPattern parts each with nested groups
        let config = DecomposedRegexConfig {
            parts: vec![
                RegexPart::Pattern("from:".to_string()),
                RegexPart::PublicPattern(("(\\w+)@(\\w+)".to_string(), 50)),
                RegexPart::Pattern(" to:".to_string()),
                RegexPart::PublicPattern(("(\\w+)@(\\w+)".to_string(), 50)),
            ],
        };

        let input = "from:alice@example to:bob@test";
        let result = extract_substr_idxes(input, &config, None, false).unwrap();

        // Should extract exactly two capture groups (one per PublicPattern)
        assert_eq!(result.len(), 2, "Should have exactly two capture groups");
        assert_eq!(&input[result[0].0..result[0].1], "alice@example");
        assert_eq!(&input[result[1].0..result[1].1], "bob@test");
    }

    #[test]
    fn test_already_non_capturing_groups_preserved() {
        // Test that already non-capturing groups (?:...) work correctly
        let config = DecomposedRegexConfig {
            parts: vec![
                RegexPart::Pattern("prefix:".to_string()),
                RegexPart::PublicPattern(("(?:\\w+)-(?:\\d+)".to_string(), 50)),
            ],
        };

        let input = "prefix:hello-123";
        let result = extract_substr_idxes(input, &config, None, false).unwrap();

        assert_eq!(result.len(), 1);
        assert_eq!(&input[result[0].0..result[0].1], "hello-123");
    }

    #[test]
    fn test_extract_substr_subject_all_patterns() {
        let omit_non_capture_groups = DecomposedRegexConfig {
            parts: vec![
                RegexPart::Pattern("(\r\n|^)subject:".to_string()),
                RegexPart::PublicPattern(("[^\r\n]+".to_string(), 64)),
                RegexPart::Pattern("\r\n".to_string()),
            ],
        };

        let explicit_non_capture_groups = DecomposedRegexConfig {
            parts: vec![
                RegexPart::Pattern("(?:\r\n|^)subject:".to_string()),
                RegexPart::PublicPattern(("([^\r\n]+)".to_string(), 64)),
                RegexPart::Pattern("\r\n".to_string()),
            ],
        };

        let input = "subject:hello world\r\n";

        let expected_output = "hello world";
        
        let result_omit_capture_groups = extract_substr(input, &omit_non_capture_groups, None, false).unwrap();
        let result_explicit_capture_groups = extract_substr(input, &explicit_non_capture_groups, None, false).unwrap();
        
        assert_eq!(result_omit_capture_groups[0], expected_output);
        assert_eq!(result_explicit_capture_groups[0], expected_output);
    }
}
