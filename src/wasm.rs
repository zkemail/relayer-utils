#[cfg(target_arch = "wasm32")]
use js_sys::Promise;
#[cfg(target_arch = "wasm32")]
use rand::rngs::OsRng;
#[cfg(target_arch = "wasm32")]
use serde_wasm_bindgen::{from_value, to_value};
#[cfg(target_arch = "wasm32")]
use wasm_bindgen::prelude::*;

#[cfg(target_arch = "wasm32")]
use crate::{
    generate_circuit_inputs_with_decomposed_regexes_and_external_inputs, hex_to_field, AccountCode,
    AccountSalt, CircuitInputWithDecomposedRegexesAndExternalInputsParams, DecomposedRegex,
    ExternalInput, PaddedEmailAddr, ParsedEmail,
};

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
    match ParsedEmail::new_from_raw_email(&raw_email).await {
        Ok(parsed_email) => match to_value(&parsed_email) {
            Ok(serialized_email) => Promise::resolve(&serialized_email),
            Err(err) => Promise::reject(&JsValue::from_str(&format!(
                "Failed to serialize ParsedEmail: {}",
                err
            ))),
        },
        Err(err) => Promise::reject(&JsValue::from_str(&format!(
            "Failed to parse email: {}",
            err
        ))),
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
    email_addr: String,
    decomposed_regexes: JsValue,
    external_inputs: JsValue,
    params: JsValue,
) -> Promise {
    console_error_panic_hook::set_once();

    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| async move {
        // Deserialize decomposed_regexes
        let decomposed_regexes: Vec<DecomposedRegex> = from_value(decomposed_regexes)
            .map_err(|_| String::from("Invalid decomposed_regexes input"))?;

        // Deserialize external_inputs
        let external_inputs: Vec<ExternalInput> = from_value(external_inputs)
            .map_err(|_| String::from("Invalid external_inputs input"))?;

        // Deserialize params
        let params: CircuitInputWithDecomposedRegexesAndExternalInputsParams =
            from_value(params).map_err(|_| String::from("Invalid params input"))?;

        // Call the async function and await the result
        let circuit_inputs = generate_circuit_inputs_with_decomposed_regexes_and_external_inputs(
            &email_addr,
            decomposed_regexes,
            external_inputs,
            params,
        )
        .await
        .map_err(|err| format!("Failed to generate CircuitInputs: {}", err))?;

        // Serialize the output to JsValue
        to_value(&circuit_inputs).map_err(|_| String::from("Failed to serialize CircuitInputs"))
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
