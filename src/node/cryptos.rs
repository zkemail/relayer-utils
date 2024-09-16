//! Cryptographic functions for the node.js bindings.

use halo2curves::ff::Field;
use neon::{
    context::{Context, FunctionContext},
    object::Object,
    result::JsResult,
    types::{JsArray, JsString},
};
use poseidon_rs::Fr;
use rand_core::OsRng;

use crate::{
    email_nullifier, extract_rand_from_signature, field_to_hex, hex_to_field_node, public_key_hash,
    AccountCode, AccountSalt, PaddedEmailAddr, RelayerRand,
};

/// Generates a random value for the relayer and returns it as a hexadecimal string.
///
/// This function creates a new random value using the operating system's RNG,
/// then converts it to a hexadecimal string and returns it to the JavaScript context.
///
/// # Arguments
/// * `cx` - The function context.
///
/// # Returns
/// A `JsResult` containing a `JsString` of the hexadecimal representation of the random value.
pub(crate) fn gen_relayer_rand_node(mut cx: FunctionContext) -> JsResult<JsString> {
    // Initialize the OS random number generator.
    let mut rng = OsRng;
    // Generate a new random value for the relayer.
    let relayer_rand = RelayerRand::new(&mut rng);
    // Convert the random value to a hexadecimal string.
    let relayer_rand_str = field_to_hex(&relayer_rand.0);
    // Return the hexadecimal string to the JavaScript context.
    Ok(cx.string(relayer_rand_str))
}

/// Extracts a random field element from a signature and returns it as a hexadecimal string.
///
/// This function takes a hexadecimal string representing a signature, decodes it,
/// extracts the random field element, converts it to a hexadecimal string, and returns it.
///
/// # Arguments
/// * `cx` - The function context.
///
/// # Returns
/// A `JsResult` containing a `JsString` of the hexadecimal representation of the random field element.
pub(crate) fn extract_rand_from_signature_node(mut cx: FunctionContext) -> JsResult<JsString> {
    // Retrieve the signature string from the JavaScript argument.
    let signature = cx.argument::<JsString>(0)?.value(&mut cx);
    // Decode the hexadecimal signature, skipping the "0x" prefix.
    let signature = match hex::decode(&signature[2..]) {
        Ok(bytes) => bytes,
        Err(e) => {
            // If decoding fails, throw a JavaScript error with a descriptive message.
            return cx.throw_error(&format!("signature is an invalid hex string: {}", e));
        }
    };

    // Extract the random field element from the signature.
    let rand = match extract_rand_from_signature(&signature) {
        Ok(fr) => fr,
        Err(e) => {
            // If extraction fails, throw a JavaScript error with a descriptive message.
            return cx.throw_error(&format!("extract_rand_from_signature failed: {}", e));
        }
    };
    // Convert the random field element to a hexadecimal string.
    let rand_str = field_to_hex(&rand);
    // Return the hexadecimal string to the JavaScript context.
    Ok(cx.string(rand_str))
}

/// Generates a new account code and returns it as a hexadecimal string.
///
/// This function uses the operating system's RNG to generate a new account code,
/// which is then converted to a hexadecimal string and returned to the JavaScript context.
///
/// # Arguments
/// * `cx` - The function context.
///
/// # Returns
/// A `JsResult` containing a `JsString` of the hexadecimal representation of the account code.
pub(crate) fn gen_account_code_node(mut cx: FunctionContext) -> JsResult<JsString> {
    // Initialize the OS random number generator.
    let mut rng = OsRng;
    // Generate a new account code.
    let account_code = AccountCode::new(&mut rng);
    // Convert the account code to a hexadecimal string.
    let account_code_str = field_to_hex(&account_code.0);
    // Return the hexadecimal string to the JavaScript context.
    Ok(cx.string(account_code_str))
}

/// Computes the hash of a public key and returns it as a hexadecimal string.
///
/// This function takes a hexadecimal string representing a public key, decodes it,
/// computes its hash, and returns the hash as a hexadecimal string.
///
/// # Arguments
/// * `cx` - The function context.
///
/// # Returns
/// A `JsResult` containing a `JsString` of the hexadecimal representation of the public key hash.
pub(crate) fn public_key_hash_node(mut cx: FunctionContext) -> JsResult<JsString> {
    // Retrieve the public key string from the JavaScript argument and decode it.
    let public_key_n = cx.argument::<JsString>(0)?.value(&mut cx);
    let mut public_key_n = match hex::decode(&public_key_n[2..]) {
        Ok(bytes) => bytes,
        Err(e) => {
            // If decoding fails, throw a JavaScript error with a descriptive message.
            return cx.throw_error(&format!("public_key_n is an invalid hex string: {}", e));
        }
    };
    // Reverse the bytes as required by the domain logic.
    public_key_n.reverse();
    // Compute the hash of the public key.
    let hash_field = match public_key_hash(&public_key_n) {
        Ok(hash_field) => hash_field,
        Err(e) => {
            // If hashing fails, throw a JavaScript error with a descriptive message.
            return cx.throw_error(&format!("public_key_hash failed: {}", e));
        }
    };
    // Convert the hash to a hexadecimal string.
    let hash_str = field_to_hex(&hash_field);
    // Return the hexadecimal string to the JavaScript context.
    Ok(cx.string(hash_str))
}

/// Computes the nullifier for an email based on its signature and returns it as a hexadecimal string.
///
/// This function takes a signature, decodes it from hexadecimal, reverses the bytes (if necessary),
/// computes the nullifier, and returns it as a hexadecimal string.
///
/// # Arguments
/// * `cx` - The function context.
///
/// # Returns
/// A `JsResult` containing a `JsString` of the hexadecimal representation of the email nullifier.
pub(crate) fn email_nullifier_node(mut cx: FunctionContext) -> JsResult<JsString> {
    // Retrieve the signature from the JavaScript argument, decode and reverse it.
    let signature = cx.argument::<JsString>(0)?.value(&mut cx);
    let mut signature = match hex::decode(&signature[2..]) {
        Ok(bytes) => bytes,
        Err(e) => return cx.throw_error(&format!("signature is an invalid hex string: {}", e)),
    };
    signature.reverse();

    // Compute the nullifier from the signature.
    let nullifier = match email_nullifier(&signature) {
        Ok(nullifier) => nullifier,
        Err(e) => return cx.throw_error(&format!("email_nullifier failed: {}", e)),
    };

    // Convert the nullifier to a hexadecimal string and return it.
    let nullifier_str = field_to_hex(&nullifier);
    Ok(cx.string(nullifier_str))
}

/// Generates a commitment for an account code and returns it as a hexadecimal string.
///
/// This function takes an account code, an email address, and a relayer's random hash,
/// computes the commitment, and returns it as a hexadecimal string.
///
/// # Arguments
/// * `cx` - The function context.
///
/// # Returns
/// A `JsResult` containing a `JsString` of the hexadecimal representation of the account code commitment.
pub(crate) fn account_code_commit_node(mut cx: FunctionContext) -> JsResult<JsString> {
    // Retrieve the account code, email address, and relayer's random hash from the JavaScript arguments.
    let account_code = cx.argument::<JsString>(0)?.value(&mut cx);
    let email_addr = cx.argument::<JsString>(1)?.value(&mut cx);
    let relayer_rand_hash = cx.argument::<JsString>(2)?.value(&mut cx);

    // Convert the account code and relayer's random hash from hexadecimal to field elements.
    let account_code = hex_to_field_node(&mut cx, &account_code)?;
    let padded_email_addr = PaddedEmailAddr::from_email_addr(&email_addr);
    let relayer_rand_hash = hex_to_field_node(&mut cx, &relayer_rand_hash)?;

    // Compute the commitment for the account code.
    let account_code_commit =
        match AccountCode(account_code).to_commitment(&padded_email_addr, &relayer_rand_hash) {
            Ok(fr) => fr,
            Err(e) => return cx.throw_error(&format!("AccountCodeCommit failed: {}", e)),
        };

    // Convert the commitment to a hexadecimal string and return it.
    let account_code_commit_str = field_to_hex(&account_code_commit);
    Ok(cx.string(account_code_commit_str))
}

/// Computes the hash of a relayer's random value and returns it as a hexadecimal string.
///
/// This function takes a hexadecimal string representing a relayer's random value,
/// converts it to a field element, computes its hash, and returns the hash as a hexadecimal string.
///
/// # Arguments
/// * `cx` - The function context.
///
/// # Returns
/// A `JsResult` containing a `JsString` of the hexadecimal representation of the relayer's random hash.
pub(crate) fn relayer_rand_hash_node(mut cx: FunctionContext) -> JsResult<JsString> {
    // Retrieve the relayer's random value from the JavaScript argument and convert it.
    let relayer_rand = cx.argument::<JsString>(0)?.value(&mut cx);
    let relayer_rand = hex_to_field_node(&mut cx, &relayer_rand)?;

    // Compute the hash of the relayer's random value.
    let relayer_rand_hash = match RelayerRand(relayer_rand).hash() {
        Ok(fr) => fr,
        Err(e) => {
            // If hashing fails, throw a JavaScript error with a descriptive message.
            return cx.throw_error(&format!("RelayerRand hash failed: {}", e));
        }
    };

    // Convert the hash to a hexadecimal string and return it.
    let relayer_rand_hash_str = field_to_hex(&relayer_rand_hash);
    Ok(cx.string(relayer_rand_hash_str))
}

/// Generates a salt for an account based on an email address and account code, returning it as a hexadecimal string.
///
/// This function takes an email address and an account code, generates a salt for the account,
/// and returns the salt as a hexadecimal string.
///
/// # Arguments
/// * `cx` - The function context.
///
/// # Returns
/// A `JsResult` containing a `JsString` of the hexadecimal representation of the account salt.
pub(crate) fn account_salt_node(mut cx: FunctionContext) -> JsResult<JsString> {
    // Retrieve the email address and account code from the JavaScript arguments.
    let email_addr = cx.argument::<JsString>(0)?.value(&mut cx);
    let padded_email_addr = PaddedEmailAddr::from_email_addr(&email_addr);
    let account_code_str = cx.argument::<JsString>(1)?.value(&mut cx);
    let account_code = hex_to_field_node(&mut cx, &account_code_str)?;

    // Generate the account salt using the email address and account code.
    let account_salt = match AccountSalt::new(&padded_email_addr, AccountCode(account_code)) {
        Ok(account_salt) => account_salt,
        Err(e) => {
            // If salt generation fails, throw a JavaScript error with a descriptive message.
            return cx.throw_error(&format!("AccountSalt failed: {}", e));
        }
    };

    // Convert the account salt to a hexadecimal string and return it.
    let account_salt_str = field_to_hex(&account_salt.0);
    Ok(cx.string(account_salt_str))
}

/// Generates a random commitment randomness for an email address and returns it as a hexadecimal string.
///
/// This function creates a new random field element using the operating system's RNG,
/// then converts it to a hexadecimal string and returns it to the JavaScript context.
///
/// # Arguments
/// * `cx` - The function context.
///
/// # Returns
/// A `JsResult` containing a `JsString` of the hexadecimal representation of the commitment randomness.
pub(crate) fn email_addr_commit_rand_node(mut cx: FunctionContext) -> JsResult<JsString> {
    // Initialize the OS random number generator.
    let mut rng = OsRng;
    // Generate a random field element.
    let commit_rand = Fr::random(&mut rng);
    // Convert the field element to a hexadecimal string.
    let commit_rand_str = field_to_hex(&commit_rand);
    // Return the hexadecimal string to the JavaScript context.
    Ok(cx.string(commit_rand_str))
}

/// Generates a commitment for an email address using a provided randomness and returns it as a hexadecimal string.
///
/// This function takes an email address and a randomness value, computes the commitment,
/// and returns it as a hexadecimal string.
///
/// # Arguments
/// * `cx` - The function context.
///
/// # Returns
/// A `JsResult` containing a `JsString` of the hexadecimal representation of the email address commitment.
pub(crate) fn email_addr_commit_node(mut cx: FunctionContext) -> JsResult<JsString> {
    // Retrieve the email address and randomness from the JavaScript arguments.
    let email_addr = cx.argument::<JsString>(0)?.value(&mut cx);
    let rand = cx.argument::<JsString>(1)?.value(&mut cx);
    // Convert the randomness from a hexadecimal string to a field element.
    let rand = hex_to_field_node(&mut cx, &rand)?;
    // Convert the email address to a padded form.
    let padded_email_addr = PaddedEmailAddr::from_email_addr(&email_addr);
    // Compute the commitment for the email address using the provided randomness.
    let email_addr_commit = match padded_email_addr.to_commitment(&rand) {
        Ok(fr) => fr,
        Err(e) => {
            // If commitment computation fails, throw a JavaScript error with a descriptive message.
            return cx.throw_error(&format!("EmailAddrCommit failed: {}", e));
        }
    };
    // Convert the commitment to a hexadecimal string and return it.
    let email_addr_commit_str = field_to_hex(&email_addr_commit);
    Ok(cx.string(email_addr_commit_str))
}

/// Generates a commitment for an email address using a signature and returns it as a hexadecimal string.
///
/// This function takes an email address and a signature, computes the commitment using the signature,
/// and returns it as a hexadecimal string.
///
/// # Arguments
/// * `cx` - The function context.
/// * `email_addr` - A `JsString` representing the email address.
/// * `signature` - A `JsString` representing the signature in hexadecimal format.
///
/// # Returns
/// A `JsResult` containing a `JsString` of the hexadecimal representation of the email address commitment.
pub(crate) fn email_addr_commit_with_signature_node(mut cx: FunctionContext) -> JsResult<JsString> {
    // Retrieve the email address and signature from the JavaScript arguments.
    let email_addr = cx.argument::<JsString>(0)?.value(&mut cx);
    let signature = cx.argument::<JsString>(1)?.value(&mut cx);
    // Decode the hexadecimal signature, skipping the "0x" prefix.
    let signature = match hex::decode(&signature[2..]) {
        Ok(bytes) => bytes,
        Err(e) => return cx.throw_error(&format!("signature is an invalid hex string: {}", e)),
    };

    // Convert the email address to its padded form.
    let padded_email_addr = PaddedEmailAddr::from_email_addr(&email_addr);
    // Compute the commitment for the email address using the signature.
    let email_addr_commit = match padded_email_addr.to_commitment_with_signature(&signature) {
        Ok(fr) => fr,
        Err(e) => return cx.throw_error(&format!("EmailAddrCommit failed: {}", e)),
    };
    // Convert the commitment to a hexadecimal string and return it.
    let email_addr_commit_str = field_to_hex(&email_addr_commit);
    Ok(cx.string(email_addr_commit_str))
}

/// Pads an email address and returns it as an array of bytes.
///
/// This function takes an email address, pads it according to the domain logic,
/// and returns the padded email as an array of bytes.
///
/// # Arguments
/// * `cx` - The function context.
/// * `email_addr` - A `JsString` representing the email address to be padded.
///
/// # Returns
/// A `JsResult` containing a `JsArray` of bytes representing the padded email address.
pub(crate) fn pad_email_addr_node(mut cx: FunctionContext) -> JsResult<JsArray> {
    // Retrieve the email address from the JavaScript argument.
    let email_addr = cx.argument::<JsString>(0)?.value(&mut cx);
    // Pad the email address.
    let padded_email_addr = PaddedEmailAddr::from_email_addr(&email_addr);
    // Create a new JavaScript array to hold the padded email bytes.
    let padded_email_addr_bytes =
        JsArray::new(&mut cx, padded_email_addr.padded_bytes.len() as u32);
    // Populate the JavaScript array with the padded email bytes.
    for (idx, byte) in padded_email_addr.padded_bytes.into_iter().enumerate() {
        let js_byte = cx.number(byte);
        padded_email_addr_bytes.set(&mut cx, idx as u32, js_byte)?;
    }
    // Return the JavaScript array.
    Ok(padded_email_addr_bytes)
}
