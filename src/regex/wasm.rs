use js_sys::Array;
use wasm_bindgen::prelude::*;
use serde_wasm_bindgen::{from_value, to_value};

use crate::regex::types::{DecomposedRegexConfig, ExtractionError};
use crate::regex::extract::{extract_substr_idxes, extract_substr};
use crate::regex::patterns::*;
use crate::regex::padding::pad_string;

// Core extraction functions
// Note: WASM uses standalone mode (no NFAGraph) for simplicity

#[wasm_bindgen]
#[allow(non_snake_case)]
pub fn extractSubstrIdxes(
    inputStr: &str,
    regexConfigJson: JsValue,
    revealPrivate: bool,
) -> Result<Array, JsValue> {
    // Parse config from JSON
    let config: DecomposedRegexConfig = from_value(regexConfigJson)
        .map_err(|e| JsValue::from_str(&format!("Invalid config: {}", e)))?;

    // Extract indices (standalone mode - no NFAGraph)
    let indices = extract_substr_idxes(inputStr, &config, None, revealPrivate)
        .map_err(|e| JsValue::from_str(&format!("Extraction failed: {}", e)))?;

    // Convert to JS array of [start, end] arrays
    let result = Array::new();
    for (start, end) in indices {
        let pair = Array::new();
        pair.push(&JsValue::from(start));
        pair.push(&JsValue::from(end));
        result.push(&pair);
    }

    Ok(result)
}

#[wasm_bindgen]
#[allow(non_snake_case)]
pub fn extractSubstr(
    inputStr: &str,
    regexConfigJson: JsValue,
    revealPrivate: bool,
) -> Result<Array, JsValue> {
    // Parse config from JSON
    let config: DecomposedRegexConfig = from_value(regexConfigJson)
        .map_err(|e| JsValue::from_str(&format!("Invalid config: {}", e)))?;

    // Extract substrings (standalone mode - no NFAGraph)
    let substrings = extract_substr(inputStr, &config, None, revealPrivate)
        .map_err(|e| JsValue::from_str(&format!("Extraction failed: {}", e)))?;

    // Convert to JS array
    let result = Array::new();
    for s in substrings {
        result.push(&JsValue::from_str(&s));
    }

    Ok(result)
}

// Pre-defined pattern extractors

#[wasm_bindgen]
#[allow(non_snake_case)]
pub fn extractEmailAddrIdxes(inputStr: &str) -> Result<Array, JsValue> {
    let indices = extract_email_addr_idxes(inputStr)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;

    let result = Array::new();
    for (start, end) in indices {
        let pair = Array::new();
        pair.push(&JsValue::from(start));
        pair.push(&JsValue::from(end));
        result.push(&pair);
    }
    Ok(result)
}

#[wasm_bindgen]
#[allow(non_snake_case)]
pub fn extractFromAddrIdxes(inputStr: &str) -> Result<Array, JsValue> {
    let indices = extract_from_addr_idxes(inputStr)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;

    let result = Array::new();
    for (start, end) in indices {
        let pair = Array::new();
        pair.push(&JsValue::from(start));
        pair.push(&JsValue::from(end));
        result.push(&pair);
    }
    Ok(result)
}

#[wasm_bindgen]
#[allow(non_snake_case)]
pub fn extractToAddrIdxes(inputStr: &str) -> Result<Array, JsValue> {
    let indices = extract_to_addr_idxes(inputStr)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;

    let result = Array::new();
    for (start, end) in indices {
        let pair = Array::new();
        pair.push(&JsValue::from(start));
        pair.push(&JsValue::from(end));
        result.push(&pair);
    }
    Ok(result)
}

#[wasm_bindgen]
#[allow(non_snake_case)]
pub fn extractSubjectAllIdxes(inputStr: &str) -> Result<Array, JsValue> {
    let indices = extract_subject_all_idxes(inputStr)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;

    let result = Array::new();
    for (start, end) in indices {
        let pair = Array::new();
        pair.push(&JsValue::from(start));
        pair.push(&JsValue::from(end));
        result.push(&pair);
    }
    Ok(result)
}

#[wasm_bindgen]
#[allow(non_snake_case)]
pub fn extractBodyHashIdxes(inputStr: &str) -> Result<Array, JsValue> {
    let indices = extract_body_hash_idxes(inputStr)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;

    let result = Array::new();
    for (start, end) in indices {
        let pair = Array::new();
        pair.push(&JsValue::from(start));
        pair.push(&JsValue::from(end));
        result.push(&pair);
    }
    Ok(result)
}

#[wasm_bindgen]
#[allow(non_snake_case)]
pub fn extractTimestampIdxes(inputStr: &str) -> Result<Array, JsValue> {
    let indices = extract_timestamp_idxes(inputStr)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;

    let result = Array::new();
    for (start, end) in indices {
        let pair = Array::new();
        pair.push(&JsValue::from(start));
        pair.push(&JsValue::from(end));
        result.push(&pair);
    }
    Ok(result)
}

#[wasm_bindgen]
#[allow(non_snake_case)]
pub fn extractMessageIdIdxes(inputStr: &str) -> Result<Array, JsValue> {
    let indices = extract_message_id_idxes(inputStr)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;

    let result = Array::new();
    for (start, end) in indices {
        let pair = Array::new();
        pair.push(&JsValue::from(start));
        pair.push(&JsValue::from(end));
        result.push(&pair);
    }
    Ok(result)
}

// Padding utilities

#[wasm_bindgen]
#[allow(non_snake_case)]
pub fn padString(str: &str, paddedBytesSize: usize) -> Vec<u8> {
    pad_string(str, paddedBytesSize)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wasm_pad_string() {
        let result = padString("hello", 10);
        assert_eq!(result.len(), 10);
        assert_eq!(&result[0..5], b"hello");
        assert_eq!(&result[5..10], &[0u8; 5]);
    }
}
