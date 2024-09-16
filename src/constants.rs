//! Constants used in the library

pub(crate) const MAX_HEADER_PADDED_BYTES: usize = 1024; // Maximum size of the header in bytes
pub(crate) const MAX_BODY_PADDED_BYTES: usize = 1536; // Maximum size of the body in bytes
pub(crate) const CIRCOM_BIGINT_N: usize = 121; // Bits per chunk
pub(crate) const CIRCOM_BIGINT_K: usize = 17; // Number of chunks
pub(crate) const MAX_EMAIL_ADDR_BYTES: usize = 256; // Maximum size of the email address in bytes
pub(crate) const JSON_LOGGER_KEY: &str = "JSON_LOGGER"; // Key for the JSON_LOGGER env var
