//! Node.js functions for converting between field elements and byte arrays.

use neon::{
    context::{Context, FunctionContext},
    object::Object,
    result::{JsResult, NeonResult},
    types::{JsArray, JsNumber},
};
use poseidon_rs::Fr;

use crate::{bytes_to_fields, field_to_hex, hex_to_field};

/// Converts a hexadecimal string to a field element.
///
/// This function takes a hexadecimal string and attempts to convert it into a field element.
/// If the conversion is successful, the field element is returned, otherwise an error is thrown.
///
/// # Arguments
/// * `cx` - The function context.
/// * `input_strs` - The hexadecimal string to be converted.
///
/// # Returns
/// A `NeonResult` containing the field element or an error.
pub(crate) fn hex_to_field_node(cx: &mut FunctionContext, input_strs: &str) -> NeonResult<Fr> {
    // Attempt to convert the hexadecimal string to a field element.
    match hex_to_field(input_strs) {
        Ok(field) => Ok(field),
        Err(e) => cx.throw_error(e.to_string()),
    }
}

/// Converts a JavaScript array of bytes into an array of field elements.
///
/// This function takes a JavaScript array of bytes, converts each byte to a field element,
/// and returns a new JavaScript array containing the field elements.
///
/// # Arguments
/// * `cx` - The function context.
///
/// # Returns
/// A `JsResult` containing a JavaScript array of field elements.
pub(crate) fn bytes_to_fields_node(mut cx: FunctionContext) -> JsResult<JsArray> {
    // Retrieve the input array from the JavaScript context.
    let input_str = cx.argument::<JsArray>(0)?;
    let input_vec = input_str.to_vec(&mut cx)?;

    // Convert the JavaScript array elements to bytes.
    let mut input_bytes = vec![];
    for val in input_vec.into_iter() {
        let val = match val.downcast::<JsNumber, _>(&mut cx) {
            Ok(v) => v.value(&mut cx),
            Err(e) => return cx.throw_error(e.to_string()),
        };
        input_bytes.push(val as u8);
    }

    // Convert the bytes to field elements.
    let fields = bytes_to_fields(&input_bytes);

    // Create a new JavaScript array to hold the field elements.
    let js_array = JsArray::new(&mut cx, fields.len() as u32);

    // Populate the JavaScript array with the field elements.
    for (i, field) in fields.into_iter().enumerate() {
        let field = cx.string(field_to_hex(&field));
        js_array.set(&mut cx, i as u32, field)?;
    }

    // Return the JavaScript array.
    Ok(js_array)
}
