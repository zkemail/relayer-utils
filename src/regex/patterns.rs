use crate::regex::extract::{extract_substr, extract_substr_idxes};
use crate::regex::types::{DecomposedRegexConfig, ExtractionError, ExtractionResult, RegexPart};
use lazy_static::lazy_static;

// Pre-defined regex patterns for common email components
// These are standalone patterns that don't require NFAGraph
lazy_static! {
    /// Pattern for extracting email addresses (user@domain.com)
    static ref EMAIL_ADDR_CONFIG: DecomposedRegexConfig = DecomposedRegexConfig {
        parts: vec![
            RegexPart::PublicPattern((r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}".to_string(), 256)),
        ],
    };

    /// Pattern for extracting email domain from address
    static ref EMAIL_DOMAIN_CONFIG: DecomposedRegexConfig = DecomposedRegexConfig {
        parts: vec![
            RegexPart::Pattern(r"[a-zA-Z0-9._%+-]+@".to_string()),
            RegexPart::PublicPattern((r"[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}".to_string(), 256)),
        ],
    };

    /// Pattern for extracting From header
    static ref FROM_ADDR_CONFIG: DecomposedRegexConfig = DecomposedRegexConfig {
        parts: vec![
            RegexPart::Pattern(r"(?i)from:.*<".to_string()),
            RegexPart::PublicPattern((r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}".to_string(), 256)),
            RegexPart::Pattern(r">".to_string()),
        ],
    };

    /// Pattern for extracting To header
    static ref TO_ADDR_CONFIG: DecomposedRegexConfig = DecomposedRegexConfig {
        parts: vec![
            RegexPart::Pattern(r"(?i)to:.*<".to_string()),
            RegexPart::PublicPattern((r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}".to_string(), 256)),
            RegexPart::Pattern(r">".to_string()),
        ],
    };

    /// Pattern for extracting Subject
    static ref SUBJECT_CONFIG: DecomposedRegexConfig = DecomposedRegexConfig {
        parts: vec![
            RegexPart::Pattern(r"(?i)subject:\s*".to_string()),
            RegexPart::PublicPattern((r".+?(?=\r?\n\S|\r?\n\r?\n)".to_string(), 512)),
        ],
    };

    /// Pattern for extracting DKIM body hash
    static ref BODY_HASH_CONFIG: DecomposedRegexConfig = DecomposedRegexConfig {
        parts: vec![
            RegexPart::Pattern(r"(?i)bh=".to_string()),
            RegexPart::PublicPattern((r"[A-Za-z0-9+/=]+".to_string(), 128)),
            RegexPart::Pattern(r";".to_string()),
        ],
    };

    /// Pattern for extracting DKIM timestamp
    static ref TIMESTAMP_CONFIG: DecomposedRegexConfig = DecomposedRegexConfig {
        parts: vec![
            RegexPart::Pattern(r"(?i)t=".to_string()),
            RegexPart::PublicPattern((r"\d+".to_string(), 32)),
            RegexPart::Pattern(r";".to_string()),
        ],
    };

    /// Pattern for extracting Message-ID
    static ref MESSAGE_ID_CONFIG: DecomposedRegexConfig = DecomposedRegexConfig {
        parts: vec![
            RegexPart::Pattern(r"(?i)message-id:\s*<".to_string()),
            RegexPart::PublicPattern((r"[^>]+".to_string(), 256)),
            RegexPart::Pattern(r">".to_string()),
        ],
    };
}

// Convenience functions for common extractions
// All use standalone mode (None for nfa_graph parameter)

/// Extract email address indices from input
pub fn extract_email_addr_idxes(input: &str) -> ExtractionResult<Vec<(usize, usize)>> {
    extract_substr_idxes(input, &EMAIL_ADDR_CONFIG, None, false)
}

/// Extract email domain indices from input
pub fn extract_email_domain_idxes(input: &str) -> ExtractionResult<Vec<(usize, usize)>> {
    extract_substr_idxes(input, &EMAIL_DOMAIN_CONFIG, None, false)
}

/// Extract From header email address indices
pub fn extract_from_addr_idxes(input: &str) -> ExtractionResult<Vec<(usize, usize)>> {
    extract_substr_idxes(input, &FROM_ADDR_CONFIG, None, false)
}

/// Extract To header email address indices
pub fn extract_to_addr_idxes(input: &str) -> ExtractionResult<Vec<(usize, usize)>> {
    extract_substr_idxes(input, &TO_ADDR_CONFIG, None, false)
}

/// Extract Subject header indices
pub fn extract_subject_all_idxes(input: &str) -> ExtractionResult<Vec<(usize, usize)>> {
    extract_substr_idxes(input, &SUBJECT_CONFIG, None, false)
}

/// Extract DKIM body hash indices
pub fn extract_body_hash_idxes(input: &str) -> ExtractionResult<Vec<(usize, usize)>> {
    extract_substr_idxes(input, &BODY_HASH_CONFIG, None, false)
}

/// Extract DKIM timestamp indices
pub fn extract_timestamp_idxes(input: &str) -> ExtractionResult<Vec<(usize, usize)>> {
    extract_substr_idxes(input, &TIMESTAMP_CONFIG, None, false)
}

/// Extract Message-ID indices
pub fn extract_message_id_idxes(input: &str) -> ExtractionResult<Vec<(usize, usize)>> {
    extract_substr_idxes(input, &MESSAGE_ID_CONFIG, None, false)
}

// String extraction variants

/// Extract email addresses as strings
pub fn extract_email_addr(input: &str) -> ExtractionResult<Vec<String>> {
    extract_substr(input, &EMAIL_ADDR_CONFIG, None, false)
}

/// Extract From header email address as string
pub fn extract_from_addr(input: &str) -> ExtractionResult<String> {
    let results = extract_substr(input, &FROM_ADDR_CONFIG, None, false)?;
    results.into_iter().next().ok_or(ExtractionError::NoMatch)
}

/// Extract DKIM body hash as string
pub fn extract_body_hash(input: &str) -> ExtractionResult<String> {
    let results = extract_substr(input, &BODY_HASH_CONFIG, None, false)?;
    results.into_iter().next().ok_or(ExtractionError::NoMatch)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_email_addr() {
        let input = "Contact us at support@example.com or sales@example.com";
        let addrs = extract_email_addr(input).unwrap();
        assert_eq!(addrs, vec!["support@example.com", "sales@example.com"]);
    }

    #[test]
    fn test_extract_from_addr() {
        let input = "From: Alice <alice@example.com>\r\n";
        let addr = extract_from_addr(input).unwrap();
        assert_eq!(addr, "alice@example.com");
    }

    #[test]
    fn test_extract_body_hash() {
        let input = "dkim-signature: v=1; a=rsa-sha256; bh=abc123xyz==; d=example.com;";
        let hash = extract_body_hash(input).unwrap();
        assert_eq!(hash, "abc123xyz==");
    }
}
