//! Circuit-related functions for the JavaScript API.

use neon::{
    context::{Context, FunctionContext},
    object::Object,
    prelude::Handle,
    result::JsResult,
    types::{JsBoolean, JsNumber, JsObject, JsPromise, JsString, JsValue},
};

use crate::{
    generate_email_circuit_input, hex_to_field_node, runtime, AccountCode, EmailCircuitParams,
};

/// Asynchronously generates email authentication input.
///
/// This function takes an email, an account code, and an optional flag to ignore the body hash check.
/// It returns a promise that resolves with the generated email authentication input or rejects with an error message.
///
/// # Arguments
/// * `cx` - Function context for JavaScript environment interaction.
/// * `email` - A `JsString` representing the user's email.
/// * `account_code` - A `JsString` representing the account code, which is converted from hex to the field.
/// * `ignore_body_hash_check` - An optional `JsBoolean` indicating whether to ignore the body hash check.
///
/// # Returns
/// A `JsPromise` that resolves with the generated email authentication input.
pub(crate) fn generate_email_circuit_input_node(mut cx: FunctionContext) -> JsResult<JsPromise> {
    // Extract the email and account_code from the JavaScript arguments and convert account_code.
    let email = cx.argument::<JsString>(0)?.value(&mut cx);
    let account_code = cx.argument::<JsString>(1)?.value(&mut cx);
    let account_code = AccountCode::from(hex_to_field_node(&mut cx, &account_code)?);
    let params = cx.argument_opt(3).map(|arg| {
        let params = arg.downcast::<JsObject, _>(&mut cx).unwrap();
        let sha_precompute_selector = params
            .get(&mut cx, "shaPrecomputeSelector")
            .ok()
            .and_then(|val: Handle<JsValue>| val.downcast::<JsString, _>(&mut cx).ok())
            .map(|js_string| js_string.value(&mut cx));
        let max_header_length = params
            .get(&mut cx, "maxHeaderLength")
            .ok()
            .and_then(|val: Handle<JsValue>| val.downcast::<JsNumber, _>(&mut cx).ok())
            .map(|js_number| js_number.value(&mut cx) as usize);
        let max_body_length = params
            .get(&mut cx, "maxBodyLength")
            .ok()
            .and_then(|val: Handle<JsValue>| val.downcast::<JsNumber, _>(&mut cx).ok())
            .map(|js_number| js_number.value(&mut cx) as usize);
        let ignore_body_hash_check = params
            .get(&mut cx, "ignoreBodyHashCheck")
            .ok()
            .and_then(|val: Handle<JsValue>| val.downcast::<JsBoolean, _>(&mut cx).ok())
            .map(|js_boolean| js_boolean.value(&mut cx));
        EmailCircuitParams {
            sha_precompute_selector,
            max_header_length,
            max_body_length,
            ignore_body_hash_check,
        }
    });

    // Create a new channel and promise for the async operation.
    let channel = cx.channel();
    let (deferred, promise) = cx.promise();

    // Retrieve the runtime for spawning the async task.
    let rt = runtime(&mut cx)?;

    // Spawn an async task to generate the email authentication input.
    rt.spawn(async move {
        // Call the Rust async function to generate the email authentication input.
        let email_auth_input = generate_email_circuit_input(&email, &account_code, params).await;

        // Use the deferred object to settle the promise once the async operation is complete.
        deferred.settle_with(&channel, move |mut cx| match email_auth_input {
            Ok(email_auth_input) => {
                // Convert the result to a JavaScript string and resolve the promise with it.
                let email_auth_input = cx.string(email_auth_input);
                Ok(email_auth_input)
            }
            Err(err) => {
                // If an error occurs, throw a JavaScript error with the provided message.
                cx.throw_error(format!("Could not generate email auth input: {}", err))
            }
        });
    });

    // Return the promise to the JavaScript side.
    Ok(promise)
}
