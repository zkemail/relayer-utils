use serde::{Deserialize, Serialize};

// Re-export new compiler types for convenience
pub use zk_regex_compiler::{DecomposedRegexConfig, NFAGraph, RegexPart};

/// Error type for extraction operations
#[derive(Debug, thiserror::Error)]
pub enum ExtractionError {
    #[error("Invalid regex config: {0}")]
    InvalidConfig(String),

    #[error("Regex match failed: {0}")]
    MatchFailed(String),

    #[error("No matches found")]
    NoMatch,

    #[error("Regex compilation error: {0}")]
    CompilationError(String),

    #[error("NFAGraph parsing error: {0}")]
    NFAGraphError(String),

    #[error("JSON parsing error: {0}")]
    JsonError(String),
}

pub type ExtractionResult<T> = Result<T, ExtractionError>;

/// Legacy config struct for backward compatibility
/// Used to convert old-style configs to new enum-based configs
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LegacyRegexPartConfig {
    pub is_public: bool,
    pub regex_def: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LegacyDecomposedRegexConfig {
    pub parts: Vec<LegacyRegexPartConfig>,
}

impl LegacyRegexPartConfig {
    /// Convert old struct-based config to new enum-based config
    pub fn to_new_part(&self, max_bytes: Option<usize>) -> RegexPart {
        if self.is_public {
            // For public patterns, use max_bytes or default to 256
            RegexPart::PublicPattern((self.regex_def.clone(), max_bytes.unwrap_or(256)))
        } else {
            RegexPart::Pattern(self.regex_def.clone())
        }
    }
}

impl LegacyDecomposedRegexConfig {
    /// Convert old config to new config with optional max_bytes per part
    pub fn to_new_config(&self, max_bytes_per_part: Option<Vec<usize>>) -> DecomposedRegexConfig {
        let parts = self
            .parts
            .iter()
            .enumerate()
            .map(|(i, part)| {
                let max_bytes = max_bytes_per_part.as_ref().and_then(|v| v.get(i).copied());
                part.to_new_part(max_bytes)
            })
            .collect();

        DecomposedRegexConfig { parts }
    }
}
