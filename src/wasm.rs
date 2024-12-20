#[cfg(target_arch = "wasm32")]
use js_sys::{Array, Promise};
#[cfg(target_arch = "wasm32")]
use rand::rngs::OsRng;
#[cfg(target_arch = "wasm32")]
use serde_wasm_bindgen::{from_value, to_value};
#[cfg(target_arch = "wasm32")]
use wasm_bindgen::prelude::*;

#[cfg(target_arch = "wasm32")]
use crate::{
    bytes_to_fields, email_nullifier, extract_rand_from_signature, field_to_hex,
    generate_circuit_inputs_with_decomposed_regexes_and_external_inputs,
    generate_email_circuit_input, hex_to_field, AccountCode, AccountSalt,
    CircuitInputWithDecomposedRegexesAndExternalInputsParams, DecomposedRegex, EmailCircuitParams,
    ExternalInput, PaddedEmailAddr, ParsedEmail, validate_email_input, WasmBindingError,
};
#[cfg(target_arch = "wasm32")]
use itertools::Itertools;
#[cfg(target_arch = "wasm32")]
use wasm_bindgen_futures::future_to_promise;
#[cfg(target_arch = "wasm32")]
use zk_regex_apis::extractSubstrIdxes;
#[wasm_bindgen]
#[allow(non_snake_case)]
#[cfg(target_arch = "wasm32")]
/// Parses a raw email string into a structured `ParsedEmail` object.
///
/// This function utilizes the `ParsedEmail::new_from_raw_email` method to parse the email,
/// and then serializes the result for JavaScript interoperability.
///
/// # Arguments
///
/// * `raw_email` - A `String` representing the raw email to be parsed.
///
/// # Returns
///
/// A `Promise` that resolves with the serialized `ParsedEmail` or rejects with an error message.
pub async fn parseEmail(raw_email: String) -> Promise {
    match validate_email_input(&raw_email) {
        Ok(_) => {
            match ParsedEmail::new_from_raw_email(&raw_email).await {
                Ok(parsed_email) => {
                    match to_value(&parsed_email) {
                        Ok(serialized_email) => Promise::resolve(&serialized_email),
                        Err(e) => Promise::reject(&JsValue::from_str(&WasmBindingError::SerializationError {
                            context: "parsed_email".to_string(),
                            error: e.to_string(),
                        }.to_string())),
                    }
                },
                Err(err) => Promise::reject(&JsValue::from_str(&WasmBindingError::ParseError {
                    context: "email".to_string(),
                    error: err.to_string(),
                }.to_string())),
            }
        },
        Err(e) => Promise::reject(&JsValue::from_str(&e.to_string())),
    }
}

#[wasm_bindgen]
#[allow(non_snake_case)]
#[cfg(target_arch = "wasm32")]
/// Generates a new `AccountCode` using a secure random number generator.
///
/// This function creates a new `AccountCode` and serializes it for JavaScript interoperability.
///
/// # Returns
///
/// A `Promise` that resolves with the serialized `AccountCode` or rejects with an error message.
pub async fn generateAccountCode() -> Promise {
    match to_value(&AccountCode::new(OsRng)) {
        Ok(serialized_code) => Promise::resolve(&serialized_code),
        Err(_) => Promise::reject(&JsValue::from_str("Failed to serialize AccountCode")),
    }
}

#[wasm_bindgen]
#[allow(non_snake_case)]
#[cfg(target_arch = "wasm32")]
/// Generates an `AccountSalt` using a padded email address and an account code.
///
/// This function converts the email address to a padded format, parses the account code,
/// and generates an `AccountSalt`, which is then serialized for JavaScript interoperability.
///
/// # Arguments
///
/// * `email_addr` - A `String` representing the email address.
/// * `account_code` - A `String` representing the account code in hexadecimal format.
///
/// # Returns
///
/// A `Promise` that resolves with the serialized `AccountSalt` or rejects with an error message.
pub async fn generateAccountSalt(email_addr: String, account_code: String) -> Promise {
    let email_addr = PaddedEmailAddr::from_email_addr(&email_addr);
    let account_code = match hex_to_field(&account_code) {
        Ok(field) => AccountCode::from(field),
        Err(_) => return Promise::reject(&JsValue::from_str("Failed to parse AccountCode")),
    };
    let account_salt = match AccountSalt::new(&email_addr, account_code) {
        Ok(salt) => salt,
        Err(_) => return Promise::reject(&JsValue::from_str("Failed to generate AccountSalt")),
    };
    match to_value(&account_salt) {
        Ok(serialized_salt) => Promise::resolve(&serialized_salt),
        Err(_) => Promise::reject(&JsValue::from_str("Failed to serialize AccountSalt")),
    }
}

#[wasm_bindgen]
#[allow(non_snake_case)]
#[cfg(target_arch = "wasm32")]
/// Pads an email address to a fixed length format.
///
/// This function converts the email address to a padded format and serializes it
/// for JavaScript interoperability.
///
/// # Arguments
///
/// * `email_addr` - A `String` representing the email address to be padded.
///
/// # Returns
///
/// A `Promise` that resolves with the serialized padded email address or rejects with an error message.
pub async fn padEmailAddr(email_addr: String) -> Promise {
    let padded_email_addr = PaddedEmailAddr::from_email_addr(&email_addr);
    match to_value(&padded_email_addr) {
        Ok(serialized_addr) => Promise::resolve(&serialized_addr),
        Err(_) => Promise::reject(&JsValue::from_str("Failed to serialize padded_email_addr")),
    }
}

#[wasm_bindgen]
#[allow(non_snake_case)]
#[cfg(target_arch = "wasm32")]
pub async fn generateCircuitInputsWithDecomposedRegexesAndExternalInputs(
    email: String,
    decomposed_regexes: JsValue,
    external_inputs: JsValue,
    params: JsValue,
) -> Promise {
    // Validate email
    match validate_email_input(&email) {
        Ok(_) => {
            // Deserialize inputs with detailed error messages
            match from_value::<Vec<DecomposedRegex>>(decomposed_regexes) {
                Ok(decomposed_regexes) => {
                    match from_value::<Vec<ExternalInput>>(external_inputs) {
                        Ok(external_inputs) => {
                            let params = if params.is_null() {
                                return Promise::reject(&JsValue::from_str(&WasmBindingError::ValidationError {
                                    field: "params".to_string(),
                                    message: "Circuit params are required".to_string(),
                                }.to_string()));
                            } else {
                                match from_value::<CircuitInputWithDecomposedRegexesAndExternalInputsParams>(params) {
                                    Ok(p) => p,
                                    Err(e) => return Promise::reject(&JsValue::from_str(&WasmBindingError::ValidationError {
                                        field: "params".to_string(),
                                        message: format!("Invalid format: {}", e),
                                    }.to_string())),
                                }
                            };

                            // Generate circuit inputs with error context
                            match generate_circuit_inputs_with_decomposed_regexes_and_external_inputs(
                                &email,
                                decomposed_regexes,
                                external_inputs,
                                params,
                            ).await {
                                Ok(inputs) => {
                                    match to_value(&inputs) {
                                        Ok(v) => Promise::resolve(&v),
                                        Err(e) => Promise::reject(&JsValue::from_str(&WasmBindingError::SerializationError {
                                            context: "circuit_inputs".to_string(),
                                            error: e.to_string(),
                                        }.to_string())),
                                    }
                                },
                                Err(e) => Promise::reject(&JsValue::from_str(&WasmBindingError::CircuitError {
                                    stage: "input_generation".to_string(),
                                    error: e.to_string(),
                                }.to_string())),
                            }
                        },
                        Err(e) => Promise::reject(&JsValue::from_str(&WasmBindingError::ValidationError {
                            field: "external_inputs".to_string(),
                            message: format!("Invalid format: {}", e),
                        }.to_string())),
                    }
                },
                Err(e) => Promise::reject(&JsValue::from_str(&WasmBindingError::ValidationError {
                    field: "decomposed_regexes".to_string(),
                    message: format!("Invalid format: {}", e),
                }.to_string())),
            }
        },
        Err(e) => Promise::reject(&JsValue::from_str(&e.to_string())),
    }
}

#[wasm_bindgen]
#[allow(non_snake_case)]
#[cfg(target_arch = "wasm32")]
/// Pads data for SHA-256 and extends it to a specified maximum length.
///
/// This function pads the input data according to SHA-256 specifications and extends
/// it to a given maximum length. It returns both the padded data and the original
/// message length.
///
/// # Arguments
///
/// * `data` - A `Uint8Array` containing the data to be padded.
/// * `max_sha_bytes` - The maximum length in bytes to which the data should be extended.
///
/// # Returns
///
/// A `Promise` that resolves with an object containing the padded data and message length,
/// or rejects with an error message.
pub async fn sha256Pad(data: JsValue, max_sha_bytes: usize) -> Promise {
    use crate::sha256_pad;

    // Set panic hook early
    console_error_panic_hook::set_once();

    // Wrap the entire operation in catch_unwind
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        // Additional validation
        if max_sha_bytes == 0 {
            return Err("max_sha_bytes must be greater than 0".to_string());
        }

        // Safe conversion of JsValue to Vec<u8>
        let data_vec: Vec<u8> = match from_value(data) {
            Ok(vec) => vec,
            Err(e) => return Err(format!("Failed to convert input data: {}", e)),
        };

        // Validate input size
        if data_vec.len() > max_sha_bytes {
            return Err(format!(
                "Input data length ({}) exceeds max_sha_bytes ({})",
                data_vec.len(),
                max_sha_bytes
            ));
        }

        // Try the padding operation within a Result
        let padding_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            sha256_pad(data_vec, max_sha_bytes)
        }));

        match padding_result {
            Ok((padded_data, message_len)) => {
                // Create the result object
                let result = serde_json::json!({
                    "paddedData": padded_data,
                    "messageLength": message_len
                });

                // Serialize the result
                match to_value(&result) {
                    Ok(serialized) => Ok(serialized),
                    Err(e) => Err(format!("Failed to serialize result: {}", e)),
                }
            }
            Err(_) => Err("Internal error during padding operation".to_string()),
        }
    }));

    // Handle the final result
    match result {
        Ok(Ok(serialized_result)) => Promise::resolve(&serialized_result),
        Ok(Err(err_msg)) => Promise::reject(&JsValue::from_str(&err_msg)),
        Err(panic) => {
            let panic_msg = match panic.downcast::<String>() {
                Ok(msg) => *msg,
                Err(panic) => match panic.downcast::<&str>() {
                    Ok(msg) => msg.to_string(),
                    Err(_) => "Unknown panic occurred during execution".to_string(),
                },
            };
            Promise::reject(&JsValue::from_str(&format!(
                "Critical error: {}",
                panic_msg
            )))
        }
    }
}

#[wasm_bindgen]
#[allow(non_snake_case)]
#[cfg(target_arch = "wasm32")]
/// Computes the Poseidon hash of a public key.
///
/// # Arguments
///
/// * `public_key_n` - A `Uint8Array` containing the public key in little endian format.
///
/// # Returns
///
/// A `Promise` that resolves with the hexadecimal string representation of the hash,
/// or rejects with an error message.
pub async fn publicKeyHash(public_key_n: JsValue) -> Promise {
    use crate::{field_to_hex, public_key_hash};
    console_error_panic_hook::set_once();

    // We'll wrap the logic in a future so we can use `Promise` and `await`.
    let future = async move {
        // Convert JsValue (Uint8Array) to Vec<u8>
        let mut key_bytes: Vec<u8> = from_value(public_key_n)
            .map_err(|e| JsValue::from_str(&format!("Failed to convert input: {}", e)))?;

        // Reverse the bytes for little-endian format
        key_bytes.reverse();

        // Compute the hash
        let hash = public_key_hash(&key_bytes)
            .map_err(|e| JsValue::from_str(&format!("Failed to compute hash: {}", e)))?;

        // Convert hash field to hex string
        let hex_hash = field_to_hex(&hash);
        to_value(&hex_hash)
            .map_err(|e| JsValue::from_str(&format!("Failed to serialize result: {}", e)))
    };

    // Convert the future into a JS Promise
    future_to_promise(async move {
        match future.await {
            Ok(js_value) => Ok(js_value),
            Err(e) => Err(e),
        }
    })
}

#[wasm_bindgen]
#[allow(non_snake_case)]
#[cfg(target_arch = "wasm32")]
/// Generates the circuit inputs for email verification circuits using the given email data, account code, and optional parameters.
///
/// # Arguments
///
/// * `email` - A `String` representing the raw email data to be verified.
/// * `account_code` - A `String` representing the account code in hexadecimal format.
/// * `params` - An object representing the optional parameters for the circuit.
///
/// # Returns
///
/// A `Promise` that resolves with the serialized `CircuitInputs` or rejects with an error message.
pub async fn generateEmailCircuitInput(
    email: String,
    account_code: String,
    params: JsValue,
) -> Promise {
    console_error_panic_hook::set_once();

    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| async move {
        // Parse account_code
        let account_code = AccountCode::from(
            hex_to_field(&account_code)
                .map_err(|e| format!("Failed to parse AccountCode: {}", e))?,
        );
        // Deserialize params from JsValue
        let params: Option<EmailCircuitParams> = if params.is_null() {
            None
        } else {
            let params = from_value(params).map_err(|e| format!("Invalid params: {}", e))?;
            Some(params)
        };

        // Call the core function
        let circuit_inputs = generate_email_circuit_input(&email, &account_code, params)
            .await
            .map_err(|e| format!("Error generating circuit inputs: {}", e))?;

        // Serialize the output to JsValue
        to_value(&circuit_inputs).map_err(|e| format!("Failed to serialize CircuitInputs: {}", e))
    }));

    match result {
        Ok(future) => match future.await {
            Ok(serialized_inputs) => Promise::resolve(&serialized_inputs),
            Err(err_msg) => Promise::reject(&JsValue::from_str(&err_msg)),
        },
        Err(panic) => {
            let panic_msg = match panic.downcast::<String>() {
                Ok(msg) => *msg,
                Err(panic) => match panic.downcast::<&str>() {
                    Ok(msg) => msg.to_string(),
                    Err(_) => "Unknown panic occurred".to_string(),
                },
            };
            Promise::reject(&JsValue::from_str(&format!(
                "Panic occurred: {}",
                panic_msg
            )))
        }
    }
}

#[wasm_bindgen]
#[allow(non_snake_case)]
#[cfg(target_arch = "wasm32")]
/// Extracts the randomness from a given signature in the same manner as circuits.
///
/// # Arguments
///
/// * `signature` - A `Uint8Array` containing the signature data.
///
/// # Returns
///
/// A `Promise` that resolves with the extracted randomness as a hexadecimal string, or rejects with an error message.
pub async fn extractRandFromSignature(signautre: Vec<u8>) -> Promise {
    console_error_panic_hook::set_once();

    let cm_rand = match extract_rand_from_signature(&signautre) {
        Ok(field) => field,
        Err(_) => return Promise::reject(&JsValue::from_str("Failed to extract randomness")),
    };
    match to_value(&field_to_hex(&cm_rand)) {
        Ok(serialized_rand) => Promise::resolve(&serialized_rand),
        Err(_) => Promise::reject(&JsValue::from_str("Failed to serialize randomness")),
    }
}

#[wasm_bindgen]
#[allow(non_snake_case)]
#[cfg(target_arch = "wasm32")]
/// Commits an email address using a given signature as the randomness.
///
/// # Arguments
///
/// * `email_addr` - A `String` representing the email address to be committed.
/// * `signature` - A `Uint8Array` containing the signature data to be used as randomness.
///
/// # Returns
///
/// A `Promise` that resolves with the commitment as a hexadecimal string, or rejects with an error message.
pub async fn emailAddrCommitWithSignature(email_addr: String, signautre: Vec<u8>) -> Promise {
    use crate::PaddedEmailAddr;

    console_error_panic_hook::set_once();

    let padded_email_addr = PaddedEmailAddr::from_email_addr(&email_addr);
    let cm = match padded_email_addr.to_commitment_with_signature(&signautre) {
        Ok(cm) => cm,
        Err(_) => return Promise::reject(&JsValue::from_str("Failed to commit email address")),
    };

    match to_value(&field_to_hex(&cm)) {
        Ok(cm) => Promise::resolve(&cm),
        Err(_) => Promise::reject(&JsValue::from_str("Failed to serialize randomness")),
    }
}

#[wasm_bindgen]
#[allow(non_snake_case)]
#[cfg(target_arch = "wasm32")]
/// Converts a byte array to a list of field elements.
///
/// # Arguments
///
/// * `bytes` - A `Uint8Array` containing the byte array to convert.
///
/// # Returns
///
/// A `Promise` that resolves with a list of field elements as hexadecimal strings, or rejects with an error message.
pub async fn bytesToFields(bytes: JsValue) -> Promise {
    use wasm_bindgen::JsValue;

    console_error_panic_hook::set_once();

    let bytes: Vec<u8> = match from_value(bytes) {
        Ok(bytes) => bytes,
        Err(_) => return Promise::reject(&JsValue::from_str("Failed to convert input to bytes")),
    };
    let fields = bytes_to_fields(&bytes)
        .into_iter()
        .map(|field| field_to_hex(&field))
        .collect_vec();
    match to_value(&fields) {
        Ok(serialized_fields) => Promise::resolve(&serialized_fields),
        Err(_) => Promise::reject(&JsValue::from_str("Failed to serialize fields")),
    }
}

#[wasm_bindgen]
#[allow(non_snake_case)]
#[cfg(target_arch = "wasm32")]
/// Computes the nullifier for an email address using a given signature.
///
/// # Arguments
///
/// * `signature` - A `Uint8Array` containing the signature data to be used for the nullifier.
///
/// # Returns
///
/// A `Promise` that resolves with the email nullifier as a hexadecimal string, or rejects with an error message.
pub async fn emailNullifier(mut signautre: Vec<u8>) -> Promise {
    use js_sys::Promise;

    use crate::field_to_hex;

    console_error_panic_hook::set_once();

    // Reverse the bytes for little-endian format
    signautre.reverse();
    match email_nullifier(&signautre) {
        Ok(field) => Promise::resolve(&JsValue::from_str(&field_to_hex(&field))),
        Err(_) => Promise::reject(&JsValue::from_str("Failed to compute email nullifier")),
    }
}

#[wasm_bindgen]
#[allow(non_snake_case)]
#[cfg(target_arch = "wasm32")]
/// Extracts the indices of the invitation code in the given input string.
///
/// # Arguments
///
/// * `inputStr` - A `String` representing the input string to extract the invitation code indices from.
///
/// # Returns
///
/// A `Promise` that resolves with an array of arrays containing the start and end indices of the invitation code substrings,
pub fn extractInvitationCodeIdxes(inputStr: &str) -> Result<Array, JsValue> {
    let regex_config = include_str!("../regexes/invitation_code.json");
    extractSubstrIdxes(inputStr, JsValue::from_str(regex_config), false)
}

#[wasm_bindgen]
#[allow(non_snake_case)]
#[cfg(target_arch = "wasm32")]
/// Extracts the indices of the invitation code with prefix in the given input string.
///
/// # Arguments
///
/// * `inputStr` - A `String` representing the input string to extract the invitation code indices from.
///
/// # Returns
///
/// A `Promise` that resolves with an array of arrays containing the start and end indices of the invitation code substrings,
pub fn extractInvitationCodeWithPrefixIdxes(inputStr: &str) -> Result<Array, JsValue> {
    let regex_config = include_str!("../regexes/invitation_code_with_prefix.json");
    extractSubstrIdxes(inputStr, JsValue::from_str(regex_config), false)
}
