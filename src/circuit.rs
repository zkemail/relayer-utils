use anyhow::Result;
use num_bigint::BigInt;
use serde::{Deserialize, Serialize};
use std::cmp;

use crate::{
    field_to_hex, generate_partial_sha, remove_quoted_printable_soft_breaks, sha256_pad,
    to_circom_bigint_bytes, vec_u8_to_bigint, AccountCode, PaddedEmailAddr, ParsedEmail,
    MAX_BODY_PADDED_BYTES, MAX_HEADER_PADDED_BYTES,
};

#[derive(Serialize, Deserialize)]
struct EmailCircuitInput {
    padded_header: Vec<u8>,               // The padded version of the email header
    padded_body: Option<Vec<u8>>,         // The padded version of the email body, if present
    body_hash_idx: Option<usize>,         // The index in header where the body hash is stored
    public_key: Vec<String>, // The public key associated with the email, in string format
    signature: Vec<String>,  // The signature of the email, in string format
    padded_header_len: usize, // The length of the padded header
    padded_body_len: Option<usize>, // The length of the padded body, if present
    precomputed_sha: Option<Vec<u8>>, // The precomputed SHA-256 hash of part of the body, if needed
    account_code: String,    // The account code associated with the email
    from_addr_idx: usize,    // The index of the sender's address in header
    subject_idx: usize,      // The index of the email subject in header
    domain_idx: usize,       // The index of the email domain in header
    timestamp_idx: usize,    // The index of the timestamp in header
    code_idx: usize,         // The index of the invitation code in header or body
    command_idx: usize,      // The index of the command in body
    padded_cleaned_body: Option<Vec<u8>>, // The padded body after removing quoted-printable soft breaks, if needed
}

#[derive(Serialize, Deserialize)]
pub struct EmailCircuitParams {
    pub ignore_body_hash_check: Option<bool>, // Flag to ignore the body hash check
    pub max_header_length: Option<usize>,     // The maximum length of the email header
    pub max_body_length: Option<usize>,       // The maximum length of the email body
    pub sha_precompute_selector: Option<String>, // Text to select the part of the body to precompute the SHA-256 hash
}

#[derive(Serialize, Deserialize)]
struct ClaimCircuitInput {
    email_addr: Vec<u8>,  // The email address in byte format
    cm_rand: String,      // Random string used for commitment randomness
    account_code: String, // The account code as a string
}

struct CircuitInput {
    pub header_padded: Vec<u8>, // The padded version of the email header
    pub pubkey: Vec<String>,    // The public key in string format
    pub signature: Vec<String>, // The signature in string format
    pub header_len_padded_bytes: usize, // The length of the padded header in bytes
    pub precomputed_sha: Option<Vec<u8>>, // The precomputed SHA-256 hash of the body, if present
    pub body_padded: Option<Vec<u8>>, // The padded version of the email body, if present
    pub body_len_padded_bytes: Option<usize>, // The length of the padded body in bytes, if present
    pub body_hash_idx: Option<usize>, // The index in header where the body hash is stored
}

pub struct CircuitInputParams {
    body: Vec<u8>,                           // The email body in bytes
    header: Vec<u8>,                         // The email header in bytes
    body_hash_idx: usize,                    // The index of the body hash within the circuit
    rsa_signature: BigInt,                   // The RSA signature as a BigInt
    rsa_public_key: BigInt,                  // The RSA public key as a BigInt
    sha_precompute_selector: Option<String>, // Selector for SHA-256 precomputation
    max_header_length: usize,                // The maximum length of the email header
    max_body_length: usize,                  // The maximum length of the email body
    ignore_body_hash_check: bool,            // Flag to ignore the body hash check
}

pub struct CircuitParams {
    pub body: Vec<u8>,          // The email body in bytes
    pub header: Vec<u8>,        // The email header in bytes
    pub body_hash_idx: usize,   // The index of the body hash in the header
    pub rsa_signature: BigInt,  // The RSA signature as a BigInt
    pub rsa_public_key: BigInt, // The RSA public key as a BigInt
}

pub struct CircuitOptions {
    pub sha_precompute_selector: Option<String>, // Selector for SHA-256 precomputation
    pub max_header_length: Option<usize>,        // The maximum length of the email header
    pub max_body_length: Option<usize>,          // The maximum length of the email body
    pub ignore_body_hash_check: Option<bool>,    // Flag to ignore the body hash check
}

impl CircuitInputParams {
    /// Creates a new `CircuitInputParams` instance with provided parameters and options.
    ///
    /// # Arguments
    ///
    /// * `params` - A `CircuitParams` struct containing:
    ///   * `body`: A vector of bytes representing the email body.
    ///   * `header`: A vector of bytes representing the email header.
    ///   * `body_hash_idx`: The index of the body hash within the circuit.
    ///   * `rsa_signature`: The RSA signature as a BigInt.
    ///   * `rsa_public_key`: The RSA public key as a BigInt.
    ///
    /// * `options` - A `CircuitOptions` struct containing optional parameters:
    ///   * `sha_precompute_selector`: Selector for SHA-256 precomputation.
    ///   * `max_header_length`: Maximum length of the email header, with a default value if not provided.
    ///   * `max_body_length`: Maximum length of the email body, with a default value if not provided.
    ///   * `ignore_body_hash_check`: Flag to ignore the body hash check, defaults to false if not provided.
    ///
    /// # Returns
    ///
    /// A `CircuitInputParams` instance with the specified parameters and options applied.
    pub fn new(params: CircuitParams, options: CircuitOptions) -> Self {
        CircuitInputParams {
            body: params.body,
            header: params.header,
            body_hash_idx: params.body_hash_idx,
            rsa_signature: params.rsa_signature,
            rsa_public_key: params.rsa_public_key,
            sha_precompute_selector: options.sha_precompute_selector,
            // Use the provided max_header_length or default to MAX_HEADER_PADDED_BYTES
            max_header_length: options.max_header_length.unwrap_or(MAX_HEADER_PADDED_BYTES),
            // Use the provided max_body_length or default to MAX_BODY_PADDED_BYTES
            max_body_length: options.max_body_length.unwrap_or(MAX_BODY_PADDED_BYTES),
            // Use the provided ignore_body_hash_check or default to false
            ignore_body_hash_check: options.ignore_body_hash_check.unwrap_or(false),
        }
    }
}

/// Generates the inputs for the circuit from the given parameters.
///
/// This function takes `CircuitInputParams` which includes the email body and header,
/// RSA signature and public key, and other optional parameters. It processes these
/// inputs to create a `CircuitInput` struct which is used in the zero-knowledge proof
/// circuit.
///
/// # Arguments
///
/// * `params` - A `CircuitInputParams` struct containing the necessary parameters.
///
/// # Returns
///
/// A `Result` which is either a `CircuitInput` struct on success or an error on failure.
///
/// # Panics
///
/// This function panics if the partial SHA-256 generation fails.
fn generate_circuit_inputs(params: CircuitInputParams) -> Result<CircuitInput> {
    // Pad the header to the specified maximum length or the default
    let (header_padded, header_padded_len) =
        sha256_pad(params.header.clone(), params.max_header_length);

    // Calculate the length needed for SHA-256 padding of the body
    let body_sha_length = ((params.body.len() + 63 + 65) / 64) * 64;
    // Pad the body to the maximum length or the calculated SHA-256 padding length
    let (body_padded, body_padded_len) = sha256_pad(
        params.body,
        cmp::max(params.max_body_length, body_sha_length),
    );

    // Ensure that the error type returned by `generate_partial_sha` is sized
    // by converting it into an `anyhow::Error` if it's not already.
    let result = generate_partial_sha(
        body_padded,
        body_padded_len,
        params.sha_precompute_selector,
        params.max_body_length,
    );

    // Use match to handle the result and convert any error into an anyhow::Error
    let (precomputed_sha, body_remaining, body_remaining_length) = match result {
        Ok((sha, remaining, len)) => (sha, remaining, len),
        Err(e) => panic!("Failed to generate partial SHA: {:?}", e),
    };

    // Initialize the circuit input with the padded header and RSA information
    let mut circuit_input = CircuitInput {
        header_padded,
        pubkey: to_circom_bigint_bytes(params.rsa_public_key),
        signature: to_circom_bigint_bytes(params.rsa_signature),
        header_len_padded_bytes: header_padded_len,
        precomputed_sha: None,
        body_padded: None,
        body_len_padded_bytes: None,
        body_hash_idx: None,
    };

    // If body hash check is not ignored, include the precomputed SHA and body information
    if !params.ignore_body_hash_check {
        circuit_input.precomputed_sha = Some(precomputed_sha);
        circuit_input.body_hash_idx = Some(params.body_hash_idx);
        circuit_input.body_padded = Some(body_remaining);
        circuit_input.body_len_padded_bytes = Some(body_remaining_length);
    }

    Ok(circuit_input)
}

/// Asynchronously generates the circuit input for an email.
///
/// This function processes an email and its associated account code along with optional
/// parameters to produce a JSON string that represents the input to the zero-knowledge
/// proof circuit for email authentication.
///
/// # Arguments
///
/// * `email` - A string slice that holds the raw email data.
/// * `account_code` - A reference to the `AccountCode` associated with the email.
/// * `params` - Optional parameters for the circuit input generation encapsulated in `EmailCircuitParams`.
///
/// # Returns
///
/// A `Result` which is either a JSON string of the `EmailCircuitInput` on success or an error on failure.
pub async fn generate_email_circuit_input(
    email: &str,
    account_code: &AccountCode,
    params: Option<EmailCircuitParams>,
) -> Result<String> {
    // Parse the raw email to extract canonicalized body and header, and other components
    let parsed_email = ParsedEmail::new_from_raw_email(email).await?;

    // Clone the fields that are used by value before the move occurs
    let public_key = parsed_email.public_key.clone();
    let signature = parsed_email.signature.clone();

    // Create a CircuitParams struct from the parsed email
    let circuit_params = CircuitParams {
        body: parsed_email.canonicalized_body.as_bytes().to_vec(),
        header: parsed_email.canonicalized_header.as_bytes().to_vec(),
        body_hash_idx: parsed_email.get_body_hash_idxes()?.0,
        rsa_signature: vec_u8_to_bigint(signature),
        rsa_public_key: vec_u8_to_bigint(public_key),
    };

    // Create a CircuitOptions struct from the optional parameters
    let circuit_options = CircuitOptions {
        sha_precompute_selector: params
            .as_ref()
            .and_then(|p| p.sha_precompute_selector.clone()),
        max_header_length: params.as_ref().and_then(|p| p.max_header_length),
        max_body_length: params.as_ref().and_then(|p| p.max_body_length),
        ignore_body_hash_check: params.as_ref().and_then(|p| p.ignore_body_hash_check),
    };

    // Create circuit input parameters from the CircuitParams and CircuitOptions structs
    let circuit_input_params = CircuitInputParams::new(circuit_params, circuit_options);

    // Generate the circuit inputs from the parameters
    let email_circuit_inputs = generate_circuit_inputs(circuit_input_params)?;

    // Extract indices for various email components
    let from_addr_idx = parsed_email.get_from_addr_idxes()?.0;
    let domain_idx = parsed_email.get_email_domain_idxes()?.0;
    let subject_idx = parsed_email.get_subject_all_idxes()?.0;
    // Handle optional indices with default fallbacks
    let code_idx = match parsed_email.get_invitation_code_idxes(
        params
            .as_ref()
            .map_or(false, |p| p.ignore_body_hash_check.unwrap_or(false)),
    ) {
        Ok(indexes) => indexes.0,
        Err(_) => 0,
    };
    let timestamp_idx = match parsed_email.get_timestamp_idxes() {
        Ok(indexes) => indexes.0,
        Err(_) => 0,
    };
    let command_idx = match parsed_email.get_command_idxes() {
        Ok(indexes) => indexes.0,
        Err(_) => 0,
    };

    // Clean the body if necessary
    let padded_cleaned_body = if parsed_email.need_soft_line_breaks() {
        email_circuit_inputs
            .body_padded
            .clone()
            .map(remove_quoted_printable_soft_breaks)
    } else {
        None
    };

    // Construct the email circuit input from the generated data
    let email_auth_input = EmailCircuitInput {
        padded_header: email_circuit_inputs.header_padded,
        public_key: email_circuit_inputs.pubkey,
        signature: email_circuit_inputs.signature,
        padded_header_len: email_circuit_inputs.header_len_padded_bytes,
        account_code: field_to_hex(&account_code.0),
        from_addr_idx,
        subject_idx,
        domain_idx,
        timestamp_idx,
        code_idx,
        padded_body: email_circuit_inputs.body_padded,
        body_hash_idx: email_circuit_inputs.body_hash_idx,
        padded_body_len: email_circuit_inputs.body_len_padded_bytes,
        precomputed_sha: email_circuit_inputs.precomputed_sha,
        command_idx,
        padded_cleaned_body,
    };

    // Serialize the email circuit input to JSON and return
    Ok(serde_json::to_string(&email_auth_input)?)
}

/// Asynchronously generates the circuit input for a claim.
///
/// This function takes an email address, a random string for commitment randomness,
/// and an account code to produce a JSON string that represents the input to the
/// zero-knowledge proof circuit for claim generation.
///
/// # Arguments
///
/// * `email_address` - A string slice that holds the email address.
/// * `email_address_rand` - A string slice used for commitment randomness.
/// * `account_code` - A string slice representing the account code.
///
/// # Returns
///
/// A `Result` which is either a JSON string of the `ClaimCircuitInput` on success or an error on failure.
pub async fn generate_claim_input(
    email_address: &str,
    email_address_rand: &str,
    account_code: &str,
) -> Result<String> {
    // Convert the email address to a padded format
    let padded_email_address = PaddedEmailAddr::from_email_addr(email_address);
    // Collect the padded bytes into a vector
    let padded_email_addr_bytes = padded_email_address.padded_bytes;

    // Construct the claim circuit input
    let claim_input = ClaimCircuitInput {
        email_addr: padded_email_addr_bytes,
        cm_rand: email_address_rand.to_string(),
        account_code: account_code.to_string(),
    };

    // Serialize the claim circuit input to JSON and return
    Ok(serde_json::to_string(&claim_input)?)
}
