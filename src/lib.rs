pub mod circuit;
pub mod command_templates;
pub mod constants;
pub mod converters;
pub mod cryptos;
pub mod logger;
pub mod parse_email;
pub mod proof;
pub mod regex;
pub mod wasm;

pub use circuit::*;
pub use command_templates::*;
pub(crate) use constants::*;
pub use converters::*;
pub use cryptos::*;
pub use logger::*;
pub use parse_email::*;
pub use proof::*;

// Re-export commonly used items from regex module
pub use regex::{
    extract_substr_idxes, extract_substr,
    extract_email_addr_idxes, extract_from_addr_idxes, extract_to_addr_idxes,
    extract_subject_all_idxes, extract_body_hash_idxes, extract_timestamp_idxes,
    extract_message_id_idxes, extract_email_domain_idxes,
    pad_string, pad_bytes,
    DecomposedRegexConfig, RegexPart, NFAGraph,
    ExtractionError, ExtractionResult,
};
