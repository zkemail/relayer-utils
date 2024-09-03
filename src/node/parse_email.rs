//! This module contains the `parse_email_node` function that is used to parse a raw email string

use neon::{
    context::{Context, FunctionContext},
    object::Object,
    result::JsResult,
    types::{JsPromise, JsString},
};

use crate::{runtime, ParsedEmail};

/// Parses a raw email string and returns a promise with the parsed email object.
///
/// This function takes a raw email string, parses it to extract the signature, public key,
/// and canonicalized header, and then constructs a JavaScript object with these properties.
/// The promise resolves with this object or rejects with an error if parsing fails.
///
/// # Arguments
/// * `cx` - The function context.
///
/// # Returns
/// A `JsResult` containing a `JsPromise` that resolves with the parsed email object.
pub(crate) fn parse_email_node(mut cx: FunctionContext) -> JsResult<JsPromise> {
    // Retrieve the raw email string from the JavaScript argument.
    let raw_email = cx.argument::<JsString>(0)?.value(&mut cx);
    // Get the current thread's channel and create a promise.
    let channel = cx.channel();
    let (deferred, promise) = cx.promise();
    // Retrieve the runtime for spawning the async task.
    let rt = runtime(&mut cx)?;

    // Spawn an async task to parse the raw email.
    rt.spawn(async move {
        // Attempt to parse the email asynchronously.
        let parsed_email = ParsedEmail::new_from_raw_email(&raw_email).await;
        // Use the deferred object to settle the promise once the async operation is complete.
        deferred.settle_with(&channel, move |mut cx| {
            match parsed_email {
                // If parsing is successful, construct a JavaScript object with the parsed data.
                Ok(parsed_email) => {
                    let signature_str = parsed_email.signature_string();
                    let public_key_str = parsed_email.public_key_string();
                    let obj = cx.empty_object();
                    let canonicalized_header = cx.string(parsed_email.canonicalized_header);
                    obj.set(&mut cx, "canonicalizedHeader", canonicalized_header)?;
                    let signature = cx.string(&signature_str);
                    obj.set(&mut cx, "signature", signature)?;

                    let public_key = cx.string(&public_key_str);
                    obj.set(&mut cx, "publicKey", public_key)?;
                    Ok(obj)
                }
                // If parsing fails, reject the promise with an error.
                Err(err) => cx.throw_error(format!("Could not parse the raw email: {}", err)),
            }
        });
    });

    // Return the promise to the JavaScript side.
    Ok(promise)
}
