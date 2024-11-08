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
