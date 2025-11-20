mod circom;
mod noir;
mod utils;

pub use circom::*;
pub use noir::*;
pub use utils::*;

use anyhow::Result;
use num_bigint::BigInt;
use serde::{Deserialize, Serialize};
use std::cmp;

use crate::{
    generate_partial_sha, generate_partial_sha_old, remove_quoted_printable_soft_breaks,
    sha256_pad, to_circom_bigint_bytes, MAX_BODY_PADDED_BYTES, MAX_HEADER_PADDED_BYTES,
};

#[derive(Debug, Clone)]
pub struct CircuitInputParams {
    body: Vec<u8>,                           // The email body in bytes
    header: Vec<u8>,                         // The email header in bytes
    body_hash_idx: usize,                    // The index of the body hash within the circuit
    rsa_signature: BigInt,                   // The RSA signature as a BigInt
    rsa_public_key: BigInt,                  // The RSA public key as a BigInt
    sha_precompute_selector: Option<String>, // Regex Selector for SHA-256 precomputation
    max_header_length: usize,                // The maximum length of the email header
    max_body_length: usize,                  // The maximum length of the email body
    ignore_body_hash_check: bool,            // Flag to ignore the body hash check
}

struct CircuitInput {
    pub header_padded: Vec<u8>, // The padded version of the email header
    pub pubkey: Vec<String>,    // The public key in string format
    pub signature: Vec<String>, // The signature in string format
    pub header_len_padded_bytes: usize, // The length of the padded header in bytes
    pub precomputed_sha: Option<Vec<u8>>, // The precomputed SHA-256 hash of the body, if present
    pub body_padded: Option<Vec<u8>>, // The padded version of the email body, if present
    pub body_padded_len: Option<usize>, // The length of the padded body in bytes, if present
    pub body_hash_idx: Option<usize>, // The index in header where the body hash is stored
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

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct ExternalInput {
    pub name: String,          // The name of the external input
    pub value: Option<String>, // The optional value of the external input
    pub max_length: usize,     // The maximum length of the input value
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct CircuitInputWithDecomposedRegexesAndExternalInputsParams {
    pub prover_eth_address: Option<String>, // The Ethereum address of the prover
    pub max_header_length: usize,           // The maximum length of the email header
    pub max_body_length: usize,             // The maximum length of the email body
    pub ignore_body_hash_check: bool,       // Flag to ignore the body hash check
    pub remove_soft_line_breaks: bool,      // Flag to remove soft line breaks from the body
    pub sha_precompute_selector: Option<String>, // Optional regex selector for SHA-256 precomputation
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

    // Initialize the circuit input with the padded header and RSA information
    let mut circuit_input = CircuitInput {
        header_padded,
        pubkey: to_circom_bigint_bytes(params.rsa_public_key),
        signature: to_circom_bigint_bytes(params.rsa_signature),
        header_len_padded_bytes: header_padded_len,
        precomputed_sha: None,
        body_padded: None,
        body_padded_len: None,
        body_hash_idx: None,
    };

    // If body hash check is not ignored, include the precomputed SHA and body information
    if !params.ignore_body_hash_check {
        // Pass the UNPADDED body - the circuit's partial_sha256_var_end handles SHA padding
        let body_for_sha = params.body.clone();
        let body_original_len = body_for_sha.len();

        let mut adjusted_selector = params.sha_precompute_selector;

        if adjusted_selector.is_some() {
            let (cleaned_body, position_map) =
                remove_quoted_printable_soft_breaks(params.body.clone());
            adjusted_selector = Some(get_adjusted_selector(
                &params.body,
                &adjusted_selector.as_ref().unwrap(),
                &cleaned_body,
                &position_map,
            )?);
        }

        // Ensure that the error type returned by `generate_partial_sha` is sized
        // by converting it into an `anyhow::Error` if it's not already.
        let result = generate_partial_sha(
            body_for_sha,
            body_original_len,
            adjusted_selector,
            params.max_body_length,
        );

        // Use match to handle the result and convert any error into an anyhow::Error
        let (precomputed_sha, body_remaining_padded, body_remaining_length) = match result {
            Ok((sha, remaining, len)) => (sha, remaining, len),
            Err(e) => panic!("Failed to generate partial SHA: {:?}", e),
        };

        circuit_input.precomputed_sha = Some(precomputed_sha);
        circuit_input.body_hash_idx = Some(params.body_hash_idx);
        circuit_input.body_padded = Some(body_remaining_padded);
        circuit_input.body_padded_len = Some(body_remaining_length);
    }

    Ok(circuit_input)
}
// TODO : Just suppported for older circom compiler
fn generate_circuit_inputs_old(params: CircuitInputParams) -> Result<CircuitInput> {
    // Pad the header to the specified maximum length or the default
    let (header_padded, header_padded_len) =
        sha256_pad(params.header.clone(), params.max_header_length);

    // Initialize the circuit input with the padded header and RSA information
    let mut circuit_input = CircuitInput {
        header_padded,
        pubkey: to_circom_bigint_bytes(params.rsa_public_key),
        signature: to_circom_bigint_bytes(params.rsa_signature),
        header_len_padded_bytes: header_padded_len,
        precomputed_sha: None,
        body_padded: None,
        body_padded_len: None,
        body_hash_idx: None,
    };

    // If body hash check is not ignored, include the precomputed SHA and body information
    if !params.ignore_body_hash_check {
        // Calculate the length needed for SHA-256 padding of the body
        let body_sha_length = ((params.body.len() + 63 + 65) / 64) * 64;
        // Pad the body to accommodate both SHA-256 requirements and maximum length constraints
        let (body_padded, body_sha_block_len) = sha256_pad(
            params.body.clone(),
            cmp::max(params.max_body_length, body_sha_length),
        );

        let mut adjusted_selector = params.sha_precompute_selector;

        if adjusted_selector.is_some() {
            let (cleaned_body, position_map) =
                remove_quoted_printable_soft_breaks(params.body.clone());
            adjusted_selector = Some(get_adjusted_selector(
                &params.body,
                &adjusted_selector.as_ref().unwrap(),
                &cleaned_body,
                &position_map,
            )?);
        }

        // Ensure that the error type returned by `generate_partial_sha` is sized
        // by converting it into an `anyhow::Error` if it's not already.
        let result = generate_partial_sha_old(
            body_padded,
            body_sha_block_len,
            adjusted_selector,
            params.max_body_length,
        );

        // Use match to handle the result and convert any error into an anyhow::Error
        let (precomputed_sha, body_remaining_padded, body_remaining_length) = match result {
            Ok((sha, remaining, len)) => (sha, remaining, len),
            Err(e) => panic!("Failed to generate partial SHA: {:?}", e),
        };

        circuit_input.precomputed_sha = Some(precomputed_sha);
        circuit_input.body_hash_idx = Some(params.body_hash_idx);
        circuit_input.body_padded = Some(body_remaining_padded);
        circuit_input.body_padded_len = Some(body_remaining_length);
    }

    Ok(circuit_input)
}
