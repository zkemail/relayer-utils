use std::fmt;

#[derive(Debug)]
pub enum WasmBindingError {
    ParseError { context: String, error: String },
    ValidationError { field: String, message: String },
    CryptoError { operation: String, error: String },
    CircuitError { stage: String, error: String },
    SerializationError { context: String, error: String },
}

impl fmt::Display for WasmBindingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ParseError { context, error } =>
                write!(f, "Failed to parse {}: {}", context, error),
            Self::ValidationError { field, message } =>
                write!(f, "Invalid {}: {}", field, message),
            Self::CryptoError { operation, error } =>
                write!(f, "Crypto operation '{}' failed: {}", operation, error),
            Self::CircuitError { stage, error } =>
                write!(f, "Circuit error in {}: {}", stage, error),
            Self::SerializationError { context, error } =>
                write!(f, "Failed to serialize {}: {}", context, error),
        }
    }
}

pub fn validate_email_input(email: &str) -> Result<(), WasmBindingError> {
    if email.is_empty() {
        return Err(WasmBindingError::ValidationError {
            field: "email".to_string(),
            message: "Email cannot be empty".to_string(),
        });
    }
    if !email.contains('@') {
        return Err(WasmBindingError::ValidationError {
            field: "email".to_string(),
            message: "Email must contain @ symbol".to_string(),
        });
    }
    Ok(())
}

pub fn validate_hex_input(hex: &str, field: &str) -> Result<(), WasmBindingError> {
    if !hex.starts_with("0x") {
        return Err(WasmBindingError::ValidationError {
            field: field.to_string(),
            message: "Must start with 0x".to_string(),
        });
    }
    if hex.len() % 2 != 0 {
        return Err(WasmBindingError::ValidationError {
            field: field.to_string(),
            message: "Must have even length".to_string(),
        });
    }
    Ok(())
}

pub mod circuit;
pub mod command_templates;
pub mod constants;
pub mod converters;
pub mod cryptos;
pub mod logger;
pub mod parse_email;
pub mod proof;
pub mod wasm;

pub use circuit::*;
pub use command_templates::*;
pub(crate) use constants::*;
pub use converters::*;
pub use cryptos::*;
pub use logger::*;
pub use parse_email::*;
pub use proof::*;

pub use zk_regex_apis::extract_substrs::*;
pub use zk_regex_apis::padding::*;
