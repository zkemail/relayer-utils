//! Circuit-related functions for the JavaScript API.

use neon::{
    context::{Context, FunctionContext},
    result::JsResult,
    types::{JsBoolean, JsPromise, JsString},
};

use crate::{
    generate_account_creation_input, generate_email_auth_input, generate_email_sender_input,
    hex_to_field_node, runtime, AccountCode,
};

/// Asynchronously generates account creation input from an email and a random string.
///
/// The function accepts an email and a relayer-provided random string, returning a promise that
/// resolves to the generated input or rejects with an error message.
///
/// # Arguments
/// * `cx` - Function context for JavaScript environment interaction.
///
/// # Returns
/// A `JsPromise` that resolves with the generated account creation input.
pub(crate) fn generate_account_creation_input_node(mut cx: FunctionContext) -> JsResult<JsPromise> {
    // Extract the email and relayer_rand from the JavaScript arguments.
    let email = cx.argument::<JsString>(0)?.value(&mut cx);
    let relayer_rand = cx.argument::<JsString>(1)?.value(&mut cx);

    // Create a new channel for the async task and a promise for the JavaScript side.
    let channel = cx.channel();
    let (deferred, promise) = cx.promise();

    // Get the runtime for spawning the async task.
    let rt = runtime(&mut cx)?;

    // Spawn an async task to generate the account creation input.
    rt.spawn(async move {
        // Call the actual Rust async function to generate the account creation input.
        let account_creation_input = generate_account_creation_input(&email, &relayer_rand).await;
        // Use the deferred object to settle the promise once the async operation is complete.
        deferred.settle_with(&channel, move |mut cx| match account_creation_input {
            Ok(account_creation_input) => {
                // Convert the result to a JavaScript string and resolve the promise with it.
                let account_creation_input = cx.string(account_creation_input);
                Ok(account_creation_input)
            }
            Err(err) => {
                // If an error occurs, throw a JavaScript error with the provided message.
                cx.throw_error(format!(
                    "Could not generate account creation input: {}",
                    err
                ))
            }
        });
    });

    // Return the promise to the JavaScript side.
    Ok(promise)
}

/// Asynchronously generates email sender input from an email and an account code.
///
/// This function takes an email and an account code, returning a promise that
/// resolves with the generated email sender input or rejects with an error message.
///
/// # Arguments
/// * `cx` - Function context for JavaScript environment interaction.
///
/// # Returns
/// A `JsPromise` that resolves with the generated email sender input.
pub(crate) fn generate_email_sender_input_node(mut cx: FunctionContext) -> JsResult<JsPromise> {
    // Extract the email and account_code from the JavaScript arguments.
    let email = cx.argument::<JsString>(0)?.value(&mut cx);
    let account_code = cx.argument::<JsString>(1)?.value(&mut cx);

    // Create a new channel and promise for the async operation.
    let channel = cx.channel();
    let (deferred, promise) = cx.promise();

    // Retrieve the runtime for spawning the async task.
    let rt = runtime(&mut cx)?;

    // Spawn an async task to generate the email sender input.
    rt.spawn(async move {
        // Call the Rust async function to generate the email sender input.
        let email_sender_input = generate_email_sender_input(&email, &account_code).await;
        // Use the deferred object to settle the promise once the async operation is complete.
        deferred.settle_with(&channel, move |mut cx| match email_sender_input {
            Ok(email_sender_input) => {
                // Convert the result to a JavaScript string and resolve the promise with it.
                let email_sender_input = cx.string(email_sender_input);
                Ok(email_sender_input)
            }
            Err(err) => {
                // If an error occurs, throw a JavaScript error with the provided message.
                cx.throw_error(format!("Could not generate email sender input: {}", err))
            }
        });
    });

    // Return the promise to the JavaScript side.
    Ok(promise)
}

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
pub(crate) fn generate_email_auth_input_node(mut cx: FunctionContext) -> JsResult<JsPromise> {
    // Extract the email and account_code from the JavaScript arguments and convert account_code.
    let email = cx.argument::<JsString>(0)?.value(&mut cx);
    let account_code = cx.argument::<JsString>(1)?.value(&mut cx);
    let account_code = AccountCode::from(hex_to_field_node(&mut cx, &account_code)?);

    // Determine if the body hash check should be ignored, defaulting to false if the argument is not provided.
    let ignore_body_hash_check = cx.argument_opt(2).map_or(false, |arg| {
        arg.downcast::<JsBoolean, _>(&mut cx)
            .unwrap_or_else(|_| cx.boolean(false))
            .value(&mut cx)
    });

    // Create a new channel and promise for the async operation.
    let channel = cx.channel();
    let (deferred, promise) = cx.promise();

    // Retrieve the runtime for spawning the async task.
    let rt = runtime(&mut cx)?;

    // Spawn an async task to generate the email authentication input.
    rt.spawn(async move {
        // Call the Rust async function to generate the email authentication input.
        let email_auth_input =
            generate_email_auth_input(&email, &account_code, ignore_body_hash_check).await;

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
