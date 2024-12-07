use anyhow::Result;
use num_bigint::BigInt;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{cmp, collections::VecDeque};
use zk_regex_apis::extract_substrs::{
    extract_substr_idxes, DecomposedRegexConfig, RegexPartConfig,
};

use crate::{
    field_to_hex, find_index_in_body, generate_partial_sha, hex_to_u256,
    remove_quoted_printable_soft_breaks, sha256_pad, string_to_circom_bigint_bytes,
    to_circom_bigint_bytes, vec_u8_to_bigint, AccountCode, PaddedEmailAddr, ParsedEmail,
    MAX_BODY_PADDED_BYTES, MAX_HEADER_PADDED_BYTES,
};

#[derive(Serialize, Deserialize)]
struct EmailCircuitInput {
    padded_header: Vec<u8>,           // The padded version of the email header
    padded_body: Option<Vec<u8>>,     // The padded version of the email body, if present
    body_hash_idx: Option<usize>,     // The index in header where the body hash is stored
    public_key: Vec<String>,          // The public key associated with the email, in string format
    signature: Vec<String>,           // The signature of the email, in string format
    padded_header_len: usize,         // The length of the padded header
    padded_body_len: Option<usize>,   // The length of the padded body, if present
    precomputed_sha: Option<Vec<u8>>, // The precomputed SHA-256 hash of part of the body, if needed
    account_code: String,             // The account code associated with the email
    from_addr_idx: usize,             // The index of the sender's address in header
    #[serde(skip_serializing_if = "Option::is_none")]
    subject_idx: Option<usize>, // The index of the email subject in header
    domain_idx: usize,                // The index of the email domain in header
    timestamp_idx: usize,             // The index of the timestamp in header
    code_idx: usize,                  // The index of the invitation code in header or body
    command_idx: usize,               // The index of the command in body
    padded_cleaned_body: Option<Vec<u8>>, // The padded body after removing quoted-printable soft breaks, if needed
}

#[derive(Serialize, Deserialize)]
pub struct EmailCircuitParams {
    pub ignore_body_hash_check: Option<bool>, // Flag to ignore the body hash check
    pub max_header_length: Option<usize>,     // The maximum length of the email header
    pub max_body_length: Option<usize>,       // The maximum length of the email body
    pub sha_precompute_selector: Option<String>, // Regex selector for SHA-256 precomputation
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
pub struct DecomposedRegex {
    pub parts: Vec<RegexPartConfig>, // The parts of the regex configuration
    pub name: String,                // The name of the decomposed regex
    pub max_length: usize,           // The maximum length of the regex match
    pub location: String, // The location where the regex is applied (e.g., header or body)
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct CircuitInputWithDecomposedRegexesAndExternalInputsParams {
    pub prover_eth_address: Option<String>, // The Ethereum address of the prover
    pub max_header_length: usize,           // The maximum length of the email header
    pub max_body_length: usize,             // The maximum length of the email body
    pub ignore_body_hash_check: bool,       // Flag to ignore the body hash check
    pub remove_soft_lines_breaks: bool,     // Flag to remove soft line breaks from the body
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
        body_len_padded_bytes: None,
        body_hash_idx: None,
    };

    // If body hash check is not ignored, include the precomputed SHA and body information
    if !params.ignore_body_hash_check {
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
    let email_circuit_inputs = generate_circuit_inputs(circuit_input_params.clone())?;

    // Extract indices for various email components
    let from_addr_idx = parsed_email.get_from_addr_idxes()?.0;
    let domain_idx = parsed_email.get_email_domain_idxes()?.0;
    let subject_idx = if email_circuit_inputs.body_padded.is_none() {
        Some(parsed_email.get_subject_all_idxes()?.0)
    } else {
        None
    };
    // Handle optional indices with default fallbacks
    let mut code_idx = match parsed_email.get_invitation_code_idxes(
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
    let mut command_idx =
        match parsed_email.get_command_idxes(circuit_input_params.ignore_body_hash_check) {
            Ok(indexes) => indexes.0,
            Err(_) => 0,
        };

    // Clean the body
    let padded_cleaned_body = email_circuit_inputs
        .body_padded
        .clone()
        .map(remove_quoted_printable_soft_breaks);

    if email_circuit_inputs.precomputed_sha.is_some() {
        let code = parsed_email
            .get_invitation_code(circuit_input_params.ignore_body_hash_check)
            .unwrap_or_default();
        let command = parsed_email.get_command(circuit_input_params.ignore_body_hash_check)?;

        // Body is padded and cleaned, so use it for search
        let search_body = padded_cleaned_body.as_ref();

        // Find indices for the code and command in the body
        code_idx = find_index_in_body(search_body, &code);
        command_idx = find_index_in_body(search_body, &command);
    }

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

/// Asynchronously generates circuit inputs with decomposed regexes and external inputs.
///
/// This function processes an email, applies decomposed regexes, and incorporates external inputs
/// to produce a JSON object representing the inputs for a zero-knowledge proof circuit.
///
/// # Arguments
///
/// * `email` - A string slice containing the raw email data.
/// * `decomposed_regexes` - A vector of `DecomposedRegex` structs for regex processing.
/// * `external_inputs` - A vector of `ExternalInput` structs for additional inputs.
/// * `params` - Parameters for circuit input generation encapsulated in `CircuitInputWithDecomposedRegexesAndExternalInputsParams`.
///
/// # Returns
///
/// A `Result` which is either a JSON object of the circuit inputs on success or an error on failure.
pub async fn generate_circuit_inputs_with_decomposed_regexes_and_external_inputs(
    email: &str,
    decomposed_regexes: Vec<DecomposedRegex>,
    external_inputs: Vec<ExternalInput>,
    params: CircuitInputWithDecomposedRegexesAndExternalInputsParams,
) -> Result<Value> {
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
        sha_precompute_selector: params.sha_precompute_selector,
        max_header_length: Some(params.max_header_length),
        max_body_length: Some(params.max_body_length),
        ignore_body_hash_check: Some(params.ignore_body_hash_check),
    };

    // Create circuit input parameters from the CircuitParams and CircuitOptions structs
    let circuit_input_params = CircuitInputParams::new(circuit_params, circuit_options);

    // Generate the circuit inputs from the parameters
    let email_circuit_inputs = generate_circuit_inputs(circuit_input_params.clone())?;

    // Create a JSON object to hold the circuit inputs
    let mut circuit_inputs = json!({
        "emailHeader": email_circuit_inputs.header_padded,
        "emailHeaderLength": email_circuit_inputs.header_len_padded_bytes,
        "pubkey": email_circuit_inputs.pubkey,
        "signature": email_circuit_inputs.signature,
    });

    // Include body-related inputs if the body hash check is not ignored
    if !params.ignore_body_hash_check {
        circuit_inputs["bodyHashIndex"] = email_circuit_inputs.body_hash_idx.into();
        circuit_inputs["precomputedSHA"] = email_circuit_inputs.precomputed_sha.into();
        circuit_inputs["emailBody"] = email_circuit_inputs.body_padded.clone().into();
        circuit_inputs["emailBodyLength"] = email_circuit_inputs.body_len_padded_bytes.into();
    }

    // Clean the body by removing quoted-printable soft breaks if necessary
    let cleaned_body = email_circuit_inputs
        .body_padded
        .clone()
        .map(remove_quoted_printable_soft_breaks);

    // Add the cleaned body to the circuit inputs if soft line breaks are to be removed
    if params.remove_soft_lines_breaks {
        circuit_inputs["decodedEmailBodyIn"] = cleaned_body.clone().into();
    }

    // Process each decomposed regex and add the resulting indices to the circuit inputs
    for decomposed_regex in decomposed_regexes {
        let mut decomposed_regex_config = DecomposedRegexConfig {
            parts: VecDeque::new().into(),
        };
        for part in decomposed_regex.parts {
            decomposed_regex_config.parts.push(part);
        }

        // Determine the input string based on the regex location
        let input = if decomposed_regex.location == "header" {
            &String::from_utf8_lossy(&email_circuit_inputs.header_padded.clone()).into_owned()
        } else if decomposed_regex.location == "body" && params.remove_soft_lines_breaks {
            &cleaned_body
                .as_ref()
                .map(|v| String::from_utf8_lossy(v).into_owned())
                .unwrap_or_else(|| String::new())
        } else {
            &email_circuit_inputs
                .body_padded
                .as_ref()
                .map(|v| String::from_utf8_lossy(v).into_owned())
                .unwrap_or_else(|| String::new())
        };

        // Extract substring indices using the decomposed regex configuration
        let idxes: Vec<(usize, usize)> =
            extract_substr_idxes(input, &decomposed_regex_config, false)?;

        // Add the first index to the circuit inputs
        circuit_inputs[format!("{}RegexIdx", decomposed_regex.name)] = idxes[0].0.into();
    }

    // Process each external input and add it to the circuit inputs
    for external_input in external_inputs {
        let mut value =
            string_to_circom_bigint_bytes(&external_input.value.as_deref().unwrap_or(""))?;
        let signal_length = compute_signal_length(external_input.max_length);

        // Pad the value to the signal length
        if value.len() < signal_length {
            value.extend(
                vec![0; signal_length - value.len()]
                    .into_iter()
                    .map(|num| num.to_string()),
            );
        }

        // Add the external input to the circuit inputs
        circuit_inputs[external_input.name] = value.into();
    }

    if params.prover_eth_address.is_some() {
        circuit_inputs["proverETHAddress"] =
            hex_to_u256(params.prover_eth_address.as_deref().unwrap_or(""))?
                .to_string()
                .into();
    } else {
        circuit_inputs["proverETHAddress"] = "0".into();
    }

    // Return the circuit inputs as a JSON object
    Ok(circuit_inputs)
}

/// Computes the signal length required for a given maximum length.
///
/// This function calculates the number of 31-byte segments needed to accommodate
/// the given `max_length`. If there is a remainder when dividing by 31, an additional
/// segment is added to ensure the entire length is covered.
///
/// # Arguments
///
/// * `max_length` - The maximum length of the input for which the signal length is computed.
///
/// # Returns
///
/// The computed signal length as a `usize`.
pub fn compute_signal_length(max_length: usize) -> usize {
    (max_length / 31) + if max_length % 31 != 0 { 1 } else { 0 }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[tokio::test]
    async fn test_generate_regex_inputs() -> Result<()> {
        // Get the test file path relative to the project root
        let test_file = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join("fixtures")
            .join("test.eml");

        let email = std::fs::read_to_string(test_file)?;

        let mut decomposed_regexes = Vec::new();
        let part_1 = RegexPartConfig {
            is_public: false,
            regex_def: "Hi".to_string(),
        };
        let part_2 = RegexPartConfig {
            is_public: true,
            regex_def: "!".to_string(),
        };

        decomposed_regexes.push(DecomposedRegex {
            parts: vec![part_1, part_2],
            name: "hi".to_string(),
            max_length: 64,
            location: "body".to_string(),
        });

        let external_inputs = vec![];

        let input = generate_circuit_inputs_with_decomposed_regexes_and_external_inputs(
            &email,
            decomposed_regexes,
            external_inputs,
            CircuitInputWithDecomposedRegexesAndExternalInputsParams {
                max_body_length: 2816,
                max_header_length: 1024,
                ignore_body_hash_check: false,
                remove_soft_lines_breaks: true,
                sha_precompute_selector: None,
                prover_eth_address: Some("0x9401296121FC9B78F84fc856B1F8dC88f4415B2e".to_string()),
            },
        )
        .await?;

        // Save the input to a file in the test output directory
        let output_file = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join("outputs")
            .join("input.json");

        // Create the output directory if it doesn't exist
        if let Some(parent) = output_file.parent() {
            std::fs::create_dir_all(parent)?;
        }

        // Save the input to a file
        let input_str = serde_json::to_string_pretty(&input)?;
        std::fs::write(output_file, input_str)?;

        Ok(())
    }

    #[tokio::test]
    async fn test_generate_regex_inputs_with_external_inputs() -> Result<()> {
        // Get the test file path relative to the project root
        let test_file = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join("fixtures")
            .join("test.eml");

        let email = std::fs::read_to_string(test_file)?;

        let mut decomposed_regexes = Vec::new();
        let part_1 = RegexPartConfig {
            is_public: false,
            regex_def: "Hi".to_string(),
        };
        let part_2 = RegexPartConfig {
            is_public: true,
            regex_def: "!".to_string(),
        };

        decomposed_regexes.push(DecomposedRegex {
            parts: vec![part_1, part_2],
            name: "hi".to_string(),
            max_length: 64,
            location: "body".to_string(),
        });

        let external_inputs = vec![ExternalInput {
            name: "address".to_string(),
            value: Some("testerman@zkemail.com".to_string()),
            max_length: 64,
        }];

        let input = generate_circuit_inputs_with_decomposed_regexes_and_external_inputs(
            &email,
            decomposed_regexes,
            external_inputs,
            CircuitInputWithDecomposedRegexesAndExternalInputsParams {
                max_body_length: 2816,
                max_header_length: 1024,
                ignore_body_hash_check: false,
                remove_soft_lines_breaks: true,
                sha_precompute_selector: None,
                prover_eth_address: Some("0x9401296121FC9B78F84fc856B1F8dC88f4415B2e".to_string()),
            },
        )
        .await?;

        // Save the input to a file in the test output directory
        let output_file = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join("outputs")
            .join("input.json");

        // Create the output directory if it doesn't exist
        if let Some(parent) = output_file.parent() {
            std::fs::create_dir_all(parent)?;
        }

        // Save the input to a file
        let input_str = serde_json::to_string_pretty(&input)?;
        std::fs::write(output_file, input_str)?;

        Ok(())
    }

    #[tokio::test]
    async fn test_generate_regex_inputs_with_external_inputs_with_sha_precompute_selector(
    ) -> Result<()> {
        // Get the test file path relative to the project root
        let test_file = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join("fixtures")
            .join("x.eml");

        let email = std::fs::read_to_string(test_file)?;

        let mut decomposed_regexes = Vec::new();
        let part_1 = RegexPartConfig {
            is_public: false,
            regex_def: "email was meant for @".to_string(),
        };
        let part_2 = RegexPartConfig {
            is_public: true,
            regex_def: "[a-zA-Z0-9_]+".to_string(),
        };

        decomposed_regexes.push(DecomposedRegex {
            parts: vec![part_1, part_2],
            name: "handle".to_string(),
            max_length: 64,
            location: "body".to_string(),
        });

        let external_inputs = vec![ExternalInput {
            name: "address".to_string(),
            max_length: 64,
            value: Some("0x9401296121FC9B78F84fc856B1F8dC88f4415B2e".to_string()),
        }];

        let input = generate_circuit_inputs_with_decomposed_regexes_and_external_inputs(
            &email,
            decomposed_regexes,
            external_inputs,
            CircuitInputWithDecomposedRegexesAndExternalInputsParams {
                max_body_length: 2816,
                max_header_length: 1024,
                ignore_body_hash_check: false,
                remove_soft_lines_breaks: true,
                sha_precompute_selector: Some(">Not my account<".to_string()),
                prover_eth_address: Some("0x9401296121FC9B78F84fc856B1F8dC88f4415B2e".to_string()),
            },
        )
        .await?;

        // Save the input to a file in the test output directory
        let output_file = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join("outputs")
            .join("input.json");

        // Create the output directory if it doesn't exist
        if let Some(parent) = output_file.parent() {
            std::fs::create_dir_all(parent)?;
        }

        // Save the input to a file
        let input_str = serde_json::to_string_pretty(&input)?;
        std::fs::write(output_file, input_str)?;

        Ok(())
    }
}
