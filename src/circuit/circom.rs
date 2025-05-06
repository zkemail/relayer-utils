use anyhow::Result;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::VecDeque;
use zk_regex_apis::extract_substrs::{
    extract_substr_idxes, DecomposedRegexConfig, RegexPartConfig,
};

use crate::{
    field_to_hex, find_index_in_body, hex_to_u256, remove_quoted_printable_soft_breaks,
    string_to_circom_bigint_bytes, vec_u8_to_bigint, AccountCode, PaddedEmailAddr, ParsedEmail,
};

use super::{
    generate_circuit_inputs, CircuitInputParams,
    CircuitInputWithDecomposedRegexesAndExternalInputsParams, CircuitOptions, CircuitParams,
    ExternalInput,
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
#[serde(rename_all = "camelCase")]
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

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct DecomposedRegex {
    pub parts: Vec<RegexPartConfig>, // The parts of the regex configuration
    pub name: String,                // The name of the decomposed regex
    pub max_length: usize,           // The maximum length of the regex match
    pub location: String, // The location where the regex is applied (e.g., header or body)
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
    let parsed_email = ParsedEmail::new_from_raw_email(
        email,
        params
            .as_ref()
            .and_then(|p| p.ignore_body_hash_check)
            .unwrap_or(false),
    )
    .await?;

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
        if let Some((search_body, _)) = padded_cleaned_body.as_ref() {
            // Find indices for the code and command in the body
            code_idx = find_index_in_body(Some(search_body), &code);
            command_idx = find_index_in_body(Some(search_body), &command);
        } else {
            // Handle the case where padded_cleaned_body is None
            code_idx = 0; // or some other default value
            command_idx = 0; // or some other default value
        }
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
        padded_cleaned_body: padded_cleaned_body.map(|(cleaned_body, _)| cleaned_body),
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
    let parsed_email =
        ParsedEmail::new_from_raw_email(email, params.ignore_body_hash_check).await?;

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
    if params.remove_soft_line_breaks {
        if let Some((cleaned_body_vec, _)) = cleaned_body.clone() {
            circuit_inputs["decodedEmailBodyIn"] = cleaned_body_vec.into();
        }
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
            String::from_utf8_lossy(&email_circuit_inputs.header_padded.clone()).into_owned()
        } else if decomposed_regex.location == "body" && params.remove_soft_line_breaks {
            cleaned_body
                .as_ref()
                .map(|(v, _)| String::from_utf8_lossy(v).into_owned())
                .unwrap_or_else(|| String::new())
        } else {
            email_circuit_inputs
                .body_padded
                .as_ref()
                .map(|v| String::from_utf8_lossy(v).into_owned())
                .unwrap_or_else(|| String::new())
        };

        // Extract substring indices using the decomposed regex configuration
        let idxes: Vec<(usize, usize)> =
            extract_substr_idxes(&input, &decomposed_regex_config, false)?;

        // Add the first index to the circuit inputs
        circuit_inputs[format!("{}RegexIdx", decomposed_regex.name)] = idxes[0].0.into();

        for (i, idx) in idxes.iter().enumerate().skip(1) {
            // Add the remaining indices to the circuit inputs
            circuit_inputs[format!("{}RegexIdx{}", decomposed_regex.name, i)] = idx.0.into();
        }
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
    max_length / 31 + (if max_length % 31 != 0 { 1 } else { 0 })
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
                remove_soft_line_breaks: true,
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
                remove_soft_line_breaks: true,
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
        if std::env::var("CI").is_ok() {
            println!("Skipping test that requires confidential data in CI environment");
            return Ok(());
        }

        // Get the test file path relative to the project root
        let test_file = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join("fixtures")
            .join("confidential")
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
                max_body_length: 3136,
                max_header_length: 1024,
                ignore_body_hash_check: false,
                remove_soft_line_breaks: true,
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

    #[tokio::test]
    async fn test_generate_regex_inputs_binance() -> Result<()> {
        if std::env::var("CI").is_ok() {
            println!("Skipping test that requires confidential data in CI environment");
            return Ok(());
        }

        // Get the test file path relative to the project root
        let test_file = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join("fixtures")
            .join("confidential")
            .join("binance.eml");

        let email = std::fs::read_to_string(test_file)?;

        let mut decomposed_regexes = Vec::new();

        // Email Recipient regex
        let email_recipient_parts = vec![
            RegexPartConfig {
                is_public: false,
                regex_def: "(\r\n|^)to:".to_string(),
            },
            RegexPartConfig {
                is_public: false,
                regex_def: "([^\r\n]+<)?".to_string(),
            },
            RegexPartConfig {
                is_public: true,
                regex_def: "[a-zA-Z0-9!#$%&\\*\\+-/=\\?\\^_`{\\|}~\\.]+@[a-zA-Z0-9_\\.-]+"
                    .to_string(),
            },
            RegexPartConfig {
                is_public: false,
                regex_def: ">?\r\n".to_string(),
            },
        ];
        decomposed_regexes.push(DecomposedRegex {
            parts: email_recipient_parts,
            name: "emailRecipient".to_string(),
            max_length: 64,
            location: "header".to_string(),
        });

        // Sender Domain regex
        let sender_domain_parts = vec![
            RegexPartConfig {
                is_public: false,
                regex_def: "(\r\n|^)from:[^\r\n]*@".to_string(),
            },
            RegexPartConfig {
                is_public: true,
                regex_def: "[A-Za-z0-9][A-Za-z0-9\\.-]+\\.[A-Za-z]{2,}".to_string(),
            },
            RegexPartConfig {
                is_public: false,
                regex_def: "[>\r\n]".to_string(),
            },
        ];
        decomposed_regexes.push(DecomposedRegex {
            parts: sender_domain_parts,
            name: "senderDomain".to_string(),
            max_length: 64,
            location: "header".to_string(),
        });

        // Email Timestamp regex
        let email_timestamp_parts = vec![
            RegexPartConfig {
                is_public: false,
                regex_def: "(\r\n|^)dkim-signature:".to_string(),
            },
            RegexPartConfig {
                is_public: false,
                regex_def: "([a-z]+=[^;]+; )+t=".to_string(),
            },
            RegexPartConfig {
                is_public: true,
                regex_def: "[0-9]+".to_string(),
            },
            RegexPartConfig {
                is_public: false,
                regex_def: ";".to_string(),
            },
        ];
        decomposed_regexes.push(DecomposedRegex {
            parts: email_timestamp_parts,
            name: "emailTimestamp".to_string(),
            max_length: 64,
            location: "header".to_string(),
        });

        // Subject regex
        let subject_parts = vec![
            RegexPartConfig {
                is_public: false,
                regex_def: "(\r\n|^)subject:".to_string(),
            },
            RegexPartConfig {
                is_public: true,
                regex_def: "[^\r\n]+".to_string(),
            },
            RegexPartConfig {
                is_public: false,
                regex_def: "\r\n".to_string(),
            },
        ];
        decomposed_regexes.push(DecomposedRegex {
            parts: subject_parts,
            name: "subject".to_string(),
            max_length: 128,
            location: "header".to_string(),
        });

        let external_inputs = vec![ExternalInput {
            name: "address".to_string(),
            max_length: 44,
            value: Some("0x9401296121FC9B78F84fc856B1F8dC88f4415B2e".to_string()),
        }];

        let input = generate_circuit_inputs_with_decomposed_regexes_and_external_inputs(
            &email,
            decomposed_regexes,
            external_inputs,
            CircuitInputWithDecomposedRegexesAndExternalInputsParams {
                max_body_length: 0,
                max_header_length: 1024,
                ignore_body_hash_check: true,
                remove_soft_line_breaks: true,
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
}
