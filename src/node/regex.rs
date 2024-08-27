//! JavaScript bindings for the regex APIs.

use neon::{
    context::{Context, FunctionContext},
    object::Object,
    result::JsResult,
    types::{JsArray, JsNumber, JsString},
};
use std::convert::TryInto;
use zk_regex_apis::extract_substrs::{
    extract_body_hash_idxes, extract_email_addr_idxes, extract_email_addr_with_name_idxes,
    extract_email_domain_idxes, extract_from_addr_idxes, extract_from_all_idxes,
    extract_message_id_idxes, extract_subject_all_idxes, extract_substr_idxes,
    extract_timestamp_idxes, DecomposedRegexConfig,
};
use zk_regex_apis::padding::pad_string;

/// Pads a string with zeros up to a specified size and returns an array of the padded bytes.
///
/// This function takes a string and a target byte size, pads the string with zeros up to the target size,
/// and returns a JavaScript array containing the padded bytes.
///
/// # Arguments
/// * `cx` - The function context.
///
/// # Returns
/// A `JsResult` containing a `JsArray` of the padded bytes.
pub(crate) fn pad_string_node(mut cx: FunctionContext) -> JsResult<JsArray> {
    // Retrieve the string and the target padded bytes size from the JavaScript arguments.
    let string = cx.argument::<JsString>(0)?.value(&mut cx);
    let padded_bytes_size = cx.argument::<JsNumber>(1)?.value(&mut cx) as usize;

    // Pad the string with zeros up to the specified size.
    let padded_bytes = pad_string(&string, padded_bytes_size);

    // Create a new JavaScript array to hold the padded bytes.
    let padded_array = JsArray::new(&mut cx, padded_bytes_size as u32);

    // Populate the JavaScript array with the padded bytes.
    for (idx, byte) in padded_bytes.into_iter().enumerate() {
        let js_byte = cx.number(byte);
        padded_array.set(&mut cx, idx as u32, js_byte)?;
    }

    // Return the JavaScript array.
    Ok(padded_array)
}

/// Extracts substring indices from a string based on a given regex configuration and returns them as an array of arrays.
///
/// This function takes a string and a regex configuration, extracts the indices of substrings that match the regex,
/// and returns a JavaScript array where each element is a two-element array containing the start and end indices of a match.
///
/// # Arguments
/// * `cx` - The function context.
///
/// # Returns
/// A `JsResult` containing a `JsArray` of arrays with the start and end indices of each match.
pub(crate) fn extract_substr_idxes_node(mut cx: FunctionContext) -> JsResult<JsArray> {
    // Retrieve the input string and regex configuration string from the JavaScript arguments.
    let input_str = cx.argument::<JsString>(0)?.value(&mut cx);
    let regex_config_str = cx.argument::<JsString>(1)?.value(&mut cx);

    // Parse the regex configuration string into a `DecomposedRegexConfig`.
    let regex_config = match serde_json::from_str::<DecomposedRegexConfig>(&regex_config_str) {
        Ok(regex_config) => regex_config,
        Err(e) => return cx.throw_error(e.to_string()),
    };

    // Extract the substring indices using the regex configuration.
    let substr_idxes = match extract_substr_idxes(&input_str, &regex_config) {
        Ok(substr_idxes) => substr_idxes,
        Err(e) => return cx.throw_error(e.to_string()),
    };

    // Create a new JavaScript array to hold the start and end indices of each match.
    let js_array = JsArray::new(&mut cx, substr_idxes.len() as u32);

    // Populate the JavaScript array with the indices.
    for (i, (start_idx, end_idx)) in substr_idxes.iter().enumerate() {
        let start_end_array = JsArray::new(&mut cx, 2u32);
        let start_idx = cx.number(*start_idx as f64);
        start_end_array.set(&mut cx, 0, start_idx)?;
        let end_idx = cx.number(*end_idx as f64);
        start_end_array.set(&mut cx, 1, end_idx)?;
        js_array.set(&mut cx, i as u32, start_end_array)?;
    }

    // Return the JavaScript array.
    Ok(js_array)
}

/// Extracts indices of email addresses from a string and returns them as an array of arrays.
///
/// This function takes a string, identifies all substrings that match the pattern of an email address,
/// and returns a JavaScript array where each element is a two-element array containing the start and end indices of a match.
///
/// # Arguments
/// * `cx` - The function context.
///
/// # Returns
/// A `JsResult` containing a `JsArray` of arrays with the start and end indices of each email address match.
pub(crate) fn extract_email_addr_idxes_node(mut cx: FunctionContext) -> JsResult<JsArray> {
    // Retrieve the input string from the JavaScript argument.
    let input_str = cx.argument::<JsString>(0)?.value(&mut cx);

    // Extract the indices of email addresses using the regex configuration.
    let substr_idxes = match extract_email_addr_idxes(&input_str) {
        Ok(substr_idxes) => substr_idxes,
        Err(e) => return cx.throw_error(e.to_string()),
    };

    // Create a new JavaScript array to hold the start and end indices of each email address match.
    let js_array = JsArray::new(&mut cx, substr_idxes.len() as u32);

    // Populate the JavaScript array with the indices.
    for (i, (start_idx, end_idx)) in substr_idxes.iter().enumerate() {
        let start_end_array = JsArray::new(&mut cx, 2u32);
        let start_idx = cx.number(*start_idx as f64);
        start_end_array.set(&mut cx, 0, start_idx)?;
        let end_idx = cx.number(*end_idx as f64);
        start_end_array.set(&mut cx, 1, end_idx)?;
        js_array.set(&mut cx, i as u32, start_end_array)?;
    }

    // Return the JavaScript array.
    Ok(js_array)
}

/// Extracts indices of email domains from a string and returns them as an array of arrays.
///
/// This function takes a string, identifies all substrings that match the pattern of an email domain,
/// and returns a JavaScript array where each element is a two-element array containing the start and end indices of a match.
///
/// # Arguments
/// * `cx` - The function context.
///
/// # Returns
/// A `JsResult` containing a `JsArray` of arrays with the start and end indices of each email domain match.
pub(crate) fn extract_email_domain_idxes_node(mut cx: FunctionContext) -> JsResult<JsArray> {
    // Retrieve the input string from the JavaScript argument.
    let input_str = cx.argument::<JsString>(0)?.value(&mut cx);

    // Extract the indices of email domains using the regex configuration.
    let substr_idxes = match extract_email_domain_idxes(&input_str) {
        Ok(substr_idxes) => substr_idxes,
        Err(e) => return cx.throw_error(e.to_string()),
    };

    // Create a new JavaScript array to hold the start and end indices of each email domain match.
    let js_array = JsArray::new(&mut cx, substr_idxes.len() as u32);

    // Populate the JavaScript array with the indices.
    for (i, (start_idx, end_idx)) in substr_idxes.iter().enumerate() {
        let start_end_array = JsArray::new(&mut cx, 2u32);
        let start_idx = cx.number(*start_idx as f64);
        start_end_array.set(&mut cx, 0, start_idx)?;
        let end_idx = cx.number(*end_idx as f64);
        start_end_array.set(&mut cx, 1, end_idx)?;
        js_array.set(&mut cx, i as u32, start_end_array)?;
    }

    // Return the JavaScript array.
    Ok(js_array)
}

/// Extracts indices of email addresses with names from a string and returns them as an array of arrays.
///
/// This function takes a string, identifies all substrings that match the pattern of an email address with a name,
/// and returns a JavaScript array where each element is a two-element array containing the start and end indices of a match.
///
/// # Arguments
/// * `cx` - The function context.
///
/// # Returns
/// A `JsResult` containing a `JsArray` of arrays with the start and end indices of each email address with name match.
pub(crate) fn extract_email_addr_with_name_idxes_node(
    mut cx: FunctionContext,
) -> JsResult<JsArray> {
    // Retrieve the input string from the JavaScript argument.
    let input_str = cx.argument::<JsString>(0)?.value(&mut cx);

    // Extract the indices of email addresses with names using the regex configuration.
    let substr_idxes = match extract_email_addr_with_name_idxes(&input_str) {
        Ok(substr_idxes) => substr_idxes,
        Err(e) => return cx.throw_error(e.to_string()),
    };

    // Create a new JavaScript array to hold the start and end indices of each match.
    let js_array = JsArray::new(&mut cx, substr_idxes.len() as u32);

    // Populate the JavaScript array with the indices.
    for (i, (start_idx, end_idx)) in substr_idxes.iter().enumerate() {
        let start_end_array = JsArray::new(&mut cx, 2u32);
        let start_idx = cx.number(*start_idx as f64);
        start_end_array.set(&mut cx, 0, start_idx)?;
        let end_idx = cx.number(*end_idx as f64);
        start_end_array.set(&mut cx, 1, end_idx)?;
        js_array.set(&mut cx, i as u32, start_end_array)?;
    }

    // Return the JavaScript array.
    Ok(js_array)
}

/// Extracts indices of 'From' fields from a string and returns them as an array of arrays.
///
/// This function takes a string, identifies all substrings that match the pattern of 'From' fields,
/// and returns a JavaScript array where each element is a two-element array containing the start and end indices of a match.
///
/// # Arguments
/// * `cx` - The function context.
///
/// # Returns
/// A `JsResult` containing a `JsArray` of arrays with the start and end indices of each 'From' field match.
pub(crate) fn extract_from_all_idxes_node(mut cx: FunctionContext) -> JsResult<JsArray> {
    // Retrieve the input string from the JavaScript argument.
    let input_str = cx.argument::<JsString>(0)?.value(&mut cx);

    // Extract the indices of 'From' fields using the regex configuration.
    let substr_idxes = match extract_from_all_idxes(&input_str) {
        Ok(substr_idxes) => substr_idxes,
        Err(e) => return cx.throw_error(e.to_string()),
    };

    // Create a new JavaScript array to hold the start and end indices of each match.
    let js_array = JsArray::new(&mut cx, substr_idxes.len() as u32);

    // Populate the JavaScript array with the indices.
    for (i, (start_idx, end_idx)) in substr_idxes.iter().enumerate() {
        let start_end_array = JsArray::new(&mut cx, 2u32);
        let start_idx = cx.number(*start_idx as f64);
        start_end_array.set(&mut cx, 0, start_idx)?;
        let end_idx = cx.number(*end_idx as f64);
        start_end_array.set(&mut cx, 1, end_idx)?;
        js_array.set(&mut cx, i as u32, start_end_array)?;
    }

    // Return the JavaScript array.
    Ok(js_array)
}

/// Extracts indices of 'From' addresses from a string and returns them as an array of arrays.
///
/// This function takes a string, identifies all substrings that match the pattern of 'From' addresses,
/// and returns a JavaScript array where each element is a two-element array containing the start and end indices of a match.
///
/// # Arguments
/// * `cx` - The function context.
///
/// # Returns
/// A `JsResult` containing a `JsArray` of arrays with the start and end indices of each 'From' address match.
pub(crate) fn extract_from_addr_idxes_node(mut cx: FunctionContext) -> JsResult<JsArray> {
    // Retrieve the input string from the JavaScript argument.
    let input_str = cx.argument::<JsString>(0)?.value(&mut cx);

    // Extract the indices of 'From' addresses using the regex configuration.
    let substr_idxes = match extract_from_addr_idxes(&input_str) {
        Ok(substr_idxes) => substr_idxes,
        Err(e) => return cx.throw_error(e.to_string()),
    };

    // Create a new JavaScript array to hold the start and end indices of each 'From' address match.
    let js_array = JsArray::new(&mut cx, substr_idxes.len() as u32);

    // Populate the JavaScript array with the indices.
    for (i, (start_idx, end_idx)) in substr_idxes.iter().enumerate() {
        let start_end_array = JsArray::new(&mut cx, 2u32);
        let start_idx = cx.number(*start_idx as f64);
        start_end_array.set(&mut cx, 0, start_idx)?;
        let end_idx = cx.number(*end_idx as f64);
        start_end_array.set(&mut cx, 1, end_idx)?;
        js_array.set(&mut cx, i as u32, start_end_array)?;
    }

    // Return the JavaScript array.
    Ok(js_array)
}

/// Extracts indices of 'Subject' fields from a string and returns them as an array of arrays.
///
/// This function takes a string, identifies all substrings that match the pattern of 'Subject' fields,
/// and returns a JavaScript array where each element is a two-element array containing the start and end indices of a match.
///
/// # Arguments
/// * `cx` - The function context.
///
/// # Returns
/// A `JsResult` containing a `JsArray` of arrays with the start and end indices of each 'Subject' field match.
pub(crate) fn extract_subject_all_idxes_node(mut cx: FunctionContext) -> JsResult<JsArray> {
    // Retrieve the input string from the JavaScript argument.
    let input_str = cx.argument::<JsString>(0)?.value(&mut cx);

    // Extract the indices of 'Subject' fields using the regex configuration.
    let substr_idxes = match extract_subject_all_idxes(&input_str) {
        Ok(substr_idxes) => substr_idxes,
        Err(e) => return cx.throw_error(e.to_string()),
    };

    // Create a new JavaScript array to hold the start and end indices of each 'Subject' field match.
    let js_array = JsArray::new(&mut cx, substr_idxes.len() as u32);

    // Populate the JavaScript array with the indices.
    for (i, (start_idx, end_idx)) in substr_idxes.iter().enumerate() {
        let start_end_array = JsArray::new(&mut cx, 2u32);
        let start_idx = cx.number(*start_idx as f64);
        start_end_array.set(&mut cx, 0, start_idx)?;
        let end_idx = cx.number(*end_idx as f64);
        start_end_array.set(&mut cx, 1, end_idx)?;
        js_array.set(&mut cx, i as u32, start_end_array)?;
    }

    // Return the JavaScript array.
    Ok(js_array)
}

/// Extracts indices of body hash strings from a string and returns them as an array of arrays.
///
/// This function takes a string, identifies all substrings that match the pattern of a body hash,
/// and returns a JavaScript array where each element is a two-element array containing the start and end indices of a match.
///
/// # Arguments
/// * `cx` - The function context.
///
/// # Returns
/// A `JsResult` containing a `JsArray` of arrays with the start and end indices of each body hash match.
pub(crate) fn extract_body_hash_idxes_node(mut cx: FunctionContext) -> JsResult<JsArray> {
    // Retrieve the input string from the JavaScript argument.
    let input_str = cx.argument::<JsString>(0)?.value(&mut cx);

    // Extract the indices of body hash strings using the regex configuration.
    let substr_idxes = match extract_body_hash_idxes(&input_str) {
        Ok(substr_idxes) => substr_idxes,
        Err(e) => return cx.throw_error(e.to_string()),
    };

    // Create a new JavaScript array to hold the start and end indices of each match.
    let js_array = JsArray::new(&mut cx, substr_idxes.len() as u32);

    // Populate the JavaScript array with the indices.
    for (i, (start_idx, end_idx)) in substr_idxes.iter().enumerate() {
        let start_end_array = JsArray::new(&mut cx, 2u32);
        let start_idx = cx.number(*start_idx as f64);
        start_end_array.set(&mut cx, 0, start_idx)?;
        let end_idx = cx.number(*end_idx as f64);
        start_end_array.set(&mut cx, 1, end_idx)?;
        js_array.set(&mut cx, i as u32, start_end_array)?;
    }

    // Return the JavaScript array.
    Ok(js_array)
}

/// Extracts indices of timestamp strings from a string and returns them as an array of arrays.
///
/// This function takes a string, identifies all substrings that match the pattern of a timestamp,
/// and returns a JavaScript array where each element is a two-element array containing the start and end indices of a match.
///
/// # Arguments
/// * `cx` - The function context.
///
/// # Returns
/// A `JsResult` containing a `JsArray` of arrays with the start and end indices of each timestamp match.
pub(crate) fn extract_timestamp_idxes_node(mut cx: FunctionContext) -> JsResult<JsArray> {
    // Retrieve the input string from the JavaScript argument.
    let input_str = cx.argument::<JsString>(0)?.value(&mut cx);

    // Extract the indices of timestamp strings using the regex configuration.
    let substr_idxes = match extract_timestamp_idxes(&input_str) {
        Ok(substr_idxes) => substr_idxes,
        Err(e) => return cx.throw_error(e.to_string()),
    };

    // Create a new JavaScript array to hold the start and end indices of each match.
    let js_array = JsArray::new(&mut cx, substr_idxes.len() as u32);

    // Populate the JavaScript array with the indices.
    for (i, (start_idx, end_idx)) in substr_idxes.iter().enumerate() {
        let start_end_array = JsArray::new(&mut cx, 2u32);
        let start_idx = cx.number(*start_idx as f64);
        start_end_array.set(&mut cx, 0, start_idx)?;
        let end_idx = cx.number(*end_idx as f64);
        start_end_array.set(&mut cx, 1, end_idx)?;
        js_array.set(&mut cx, i as u32, start_end_array)?;
    }

    // Return the JavaScript array.
    Ok(js_array)
}

/// Extracts indices of message ID strings from a string and returns them as an array of arrays.
///
/// This function takes a string, identifies all substrings that match the pattern of a message ID,
/// and returns a JavaScript array where each element is a two-element array containing the start and end indices of a match.
///
/// # Arguments
/// * `cx` - The function context.
///
/// # Returns
/// A `JsResult` containing a `JsArray` of arrays with the start and end indices of each message ID match.
pub(crate) fn extract_message_id_idxes_node(mut cx: FunctionContext) -> JsResult<JsArray> {
    // Retrieve the input string from the JavaScript argument.
    let input_str = cx.argument::<JsString>(0)?.value(&mut cx);

    // Extract the indices of message ID strings using the regex configuration.
    let substr_idxes = match extract_message_id_idxes(&input_str) {
        Ok(substr_idxes) => substr_idxes,
        Err(e) => return cx.throw_error(e.to_string()),
    };

    // Create a new JavaScript array to hold the start and end indices of each match.
    let js_array = JsArray::new(&mut cx, substr_idxes.len() as u32);

    // Populate the JavaScript array with the indices.
    for (i, (start_idx, end_idx)) in substr_idxes.iter().enumerate() {
        let start_end_array = JsArray::new(&mut cx, 2u32);
        let start_idx = cx.number(*start_idx as f64);
        start_end_array.set(&mut cx, 0, start_idx)?;
        let end_idx = cx.number(*end_idx as f64);
        start_end_array.set(&mut cx, 1, end_idx)?;
        js_array.set(&mut cx, i as u32, start_end_array)?;
    }

    // Return the JavaScript array.
    Ok(js_array)
}

/// Extracts indices of invitation code strings from a string and returns them as an array of arrays.
///
/// This function takes a string and a regex configuration for invitation codes,
/// extracts the indices of substrings that match the invitation code pattern,
/// and returns a JavaScript array where each element is a two-element array containing the start and end indices of a match.
///
/// # Arguments
/// * `cx` - The function context.
///
/// # Returns
/// A `JsResult` containing a `JsArray` of arrays with the start and end indices of each invitation code match.
pub(crate) fn extract_invitation_code_idxes_node(mut cx: FunctionContext) -> JsResult<JsArray> {
    // Retrieve the input string from the JavaScript argument.
    let input_str = cx.argument::<JsString>(0)?.value(&mut cx);

    // Load the regex configuration for invitation codes from a JSON file.
    let regex_config =
        serde_json::from_str(include_str!("../../regexes/invitation_code.json")).unwrap();

    // Extract the indices of invitation code strings using the regex configuration.
    let substr_idxes = match extract_substr_idxes(&input_str, &regex_config) {
        Ok(substr_idxes) => substr_idxes,
        Err(e) => return cx.throw_error(e.to_string()),
    };

    // Create a new JavaScript array to hold the start and end indices of each match.
    let js_array = JsArray::new(&mut cx, substr_idxes.len() as u32);

    // Populate the JavaScript array with the indices.
    for (i, (start_idx, end_idx)) in substr_idxes.iter().enumerate() {
        let start_end_array = JsArray::new(&mut cx, 2u32);
        let start_idx = cx.number(*start_idx as f64);
        start_end_array.set(&mut cx, 0, start_idx)?;
        let end_idx = cx.number(*end_idx as f64);
        start_end_array.set(&mut cx, 1, end_idx)?;
        js_array.set(&mut cx, i as u32, start_end_array)?;
    }

    // Return the JavaScript array.
    Ok(js_array)
}

/// Extracts the first timestamp from a string and returns it as a number.
///
/// This function takes a string, identifies the first substring that matches the pattern of a timestamp,
/// and returns the timestamp as a number.
///
/// # Arguments
/// * `cx` - The function context.
///
/// # Returns
/// A `JsResult` containing a `JsNumber` representing the first timestamp found in the string.
pub(crate) fn extract_timestamp_int_node(mut cx: FunctionContext) -> JsResult<JsNumber> {
    // Retrieve the input string from the JavaScript argument.
    let input_str = cx.argument::<JsString>(0)?.value(&mut cx);

    // Extract the indices of timestamp strings using the regex configuration.
    let substr_idxes = match extract_timestamp_idxes(&input_str) {
        Ok(substr_idxes) => substr_idxes,
        Err(e) => return cx.throw_error(e.to_string()),
    };

    // Get the substring corresponding to the first timestamp match.
    let timestamp_str = &input_str[substr_idxes[0].0..substr_idxes[0].1];

    // Parse the timestamp string into an integer.
    let timestamp_int = match timestamp_str.parse::<u64>() {
        Ok(timestamp_int) => timestamp_int,
        Err(e) => return cx.throw_error(e.to_string()),
    };

    // Convert the integer to a JavaScript number and return it.
    let timestamp_int = cx.number(timestamp_int as f64);
    Ok(timestamp_int)
}

/// Extracts indices of invitation codes with a specific prefix from a string and returns them as an array of arrays.
///
/// This function takes a string and a regex configuration for invitation codes with a prefix,
/// extracts the indices of substrings that match the pattern,
/// and returns a JavaScript array where each element is a two-element array containing the start and end indices of a match.
///
/// # Arguments
/// * `cx` - The function context.
///
/// # Returns
/// A `JsResult` containing a `JsArray` of arrays with the start and end indices of each invitation code with prefix match.
pub(crate) fn extract_invitation_code_with_prefix_idxes_node(
    mut cx: FunctionContext,
) -> JsResult<JsArray> {
    // Retrieve the input string from the JavaScript argument.
    let input_str = cx.argument::<JsString>(0)?.value(&mut cx);

    // Load the regex configuration for invitation codes with a prefix from a JSON file.
    let regex_config = serde_json::from_str(include_str!(
        "../../regexes/invitation_code_with_prefix.json"
    ))
    .unwrap();

    // Extract the indices of invitation codes with a prefix using the regex configuration.
    let substr_idxes = match extract_substr_idxes(&input_str, &regex_config) {
        Ok(substr_idxes) => substr_idxes,
        Err(e) => return cx.throw_error(e.to_string()),
    };

    // Create a new JavaScript array to hold the start and end indices of each match.
    let js_array = JsArray::new(&mut cx, substr_idxes.len().try_into().unwrap());

    // Populate the JavaScript array with the indices.
    for (i, (start_idx, end_idx)) in substr_idxes.iter().enumerate() {
        let start_end_array = JsArray::new(&mut cx, 2u32);
        let start_idx = cx.number(*start_idx as f64);
        start_end_array.set(&mut cx, 0, start_idx)?;
        let end_idx = cx.number(*end_idx as f64);
        start_end_array.set(&mut cx, 1, end_idx)?;
        js_array.set(&mut cx, i as u32, start_end_array)?;
    }

    // Return the JavaScript array.
    Ok(js_array)
}
