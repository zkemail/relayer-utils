use crate::{
    circuit::generate_circuit_inputs_old,
    regex::{DecomposedRegexConfig, RegexPart},
};
use anyhow::Result;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::VecDeque;
use zk_regex_compiler::{gen_circuit_inputs, NFAGraph, ProverInputs, ProvingFramework};

use crate::{
    field_to_hex, find_index_in_body, hex_to_u256, remove_quoted_printable_soft_breaks,
    string_to_circom_bigint_bytes, trim_sha256_padding, vec_u8_to_bigint, AccountCode,
    HaystackLocation, PaddedEmailAddr, ParsedEmail,
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
    pub remove_soft_line_breaks: Option<bool>,
}

#[derive(Serialize, Deserialize)]
struct ClaimCircuitInput {
    email_addr: Vec<u8>,  // The email address in byte format
    cm_rand: String,      // Random string used for commitment randomness
    account_code: String, // The account code as a string
}

/// Serializable wrapper for RegexPart that can be used in JSON files
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(untagged)]
pub enum SerializableRegexPart {
    Pattern(String),
    PublicPattern((String, usize)),
}

impl From<SerializableRegexPart> for RegexPart {
    fn from(part: SerializableRegexPart) -> Self {
        match part {
            SerializableRegexPart::Pattern(p) => RegexPart::Pattern(p),
            SerializableRegexPart::PublicPattern((p, max)) => RegexPart::PublicPattern((p, max)),
        }
    }
}

impl From<RegexPart> for SerializableRegexPart {
    fn from(part: RegexPart) -> Self {
        match part {
            RegexPart::Pattern(p) => SerializableRegexPart::Pattern(p),
            RegexPart::PublicPattern((p, max)) => SerializableRegexPart::PublicPattern((p, max)),
        }
    }
}

impl From<&RegexPart> for SerializableRegexPart {
    fn from(part: &RegexPart) -> Self {
        match part {
            RegexPart::Pattern(p) => SerializableRegexPart::Pattern(p.clone()),
            RegexPart::PublicPattern((p, max)) => {
                SerializableRegexPart::PublicPattern((p.clone(), *max))
            }
        }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DecomposedRegex {
    #[serde(with = "regex_parts_serde")]
    pub parts: Vec<RegexPart>, // The parts of the regex configuration (using new RegexPart enum)
    pub name: String, // The name of the decomposed regex

    // Support both old field name "maxLength" and new split fields
    #[serde(alias = "maxLength")]
    pub max_match_length: usize, // The maximum length of the regex match
    #[serde(default)]
    pub max_haystack_length: Option<usize>, // The maximum length of the haystack

    // Support both old "location" and new "haystackLocation"
    #[serde(alias = "location")]
    pub haystack_location: String, // The location where the regex is applied (e.g., header or body)

    // Make optional for backwards compatibility
    #[serde(default)]
    pub regex_graph_json: Option<String>,

    // Default to Circom for old circuits
    #[serde(default = "default_proving_framework")]
    pub proving_framework: ProvingFramework,
}

fn default_proving_framework() -> ProvingFramework {
    ProvingFramework::Circom
}

impl std::fmt::Debug for DecomposedRegex {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DecomposedRegex")
            .field("name", &self.name)
            .field("max_match_length", &self.max_match_length)
            .field("max_haystack_length", &self.max_haystack_length)
            .field("haystack_location", &self.haystack_location)
            .field(
                "regex_graph_json",
                &self.regex_graph_json.as_ref().map(|_| "<json>"),
            )
            .field("proving_framework", &self.proving_framework)
            .finish()
    }
}

impl Clone for DecomposedRegex {
    fn clone(&self) -> Self {
        DecomposedRegex {
            parts: self
                .parts
                .iter()
                .map(|p| match p {
                    RegexPart::Pattern(s) => RegexPart::Pattern(s.clone()),
                    RegexPart::PublicPattern((s, n)) => RegexPart::PublicPattern((s.clone(), *n)),
                })
                .collect(),
            name: self.name.clone(),
            max_match_length: self.max_match_length,
            max_haystack_length: self.max_haystack_length,
            haystack_location: self.haystack_location.clone(),
            regex_graph_json: self.regex_graph_json.clone(),
            proving_framework: self.proving_framework,
        }
    }
}

impl DecomposedRegex {
    /// Check if this uses the new compiler with NFAGraph
    pub fn has_nfa_graph(&self) -> bool {
        self.regex_graph_json
            .as_ref()
            .map(|s| !s.is_empty())
            .unwrap_or(false)
    }

    /// Calculate max_haystack_length from parts if not provided
    pub fn get_max_haystack_length(&self) -> usize {
        self.max_haystack_length.unwrap_or_else(|| {
            // For legacy, use the provided maxLength or default
            self.max_match_length
        })
    }
}

// Untagged enum for deserializing both new and legacy regex part formats
#[derive(Deserialize)]
#[serde(untagged)]
enum RegexPartInput {
    New(SerializableRegexPart),
    Legacy(crate::regex::types::LegacyRegexPartConfig),
}

impl From<RegexPartInput> for RegexPart {
    fn from(input: RegexPartInput) -> Self {
        match input {
            RegexPartInput::New(part) => part.into(),
            RegexPartInput::Legacy(part) => part.to_new_part(None),
        }
    }
}

// Custom serde module for Vec<RegexPart>
mod regex_parts_serde {
    use super::*;
    use serde::{Deserializer, Serializer};

    pub fn serialize<S>(parts: &[RegexPart], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let serializable: Vec<SerializableRegexPart> = parts.iter().map(|p| p.into()).collect();
        serializable.serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<RegexPart>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let inputs: Vec<RegexPartInput> = Vec::deserialize(deserializer)?;
        Ok(inputs.into_iter().map(Into::into).collect())
    }
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
        padded_body_len: email_circuit_inputs.body_padded_len,
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
    let padded_email_address = PaddedEmailAddr::from_email_addr(email_address)?;
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

/// Generate circuit inputs for a decomposed regex using legacy path (without NFAGraph)
/// This replicates the OLD format that circuits compiled with the old compiler
///
/// Old format generates: {name}RegexIdx, {name}RegexIdx1, {name}RegexIdx2, etc.
/// (NOT the new MatchStart/MatchLength/States/CaptureGroup format)
fn generate_legacy_circuit_inputs(
    decomposed_regex: &DecomposedRegex,
    haystack: &str,
) -> Result<serde_json::Map<String, Value>> {
    use crate::regex::{extract_substr_idxes, DecomposedRegexConfig};

    // Convert parts to DecomposedRegexConfig for extraction
    let parts: Vec<RegexPart> = decomposed_regex
        .parts
        .iter()
        .map(|part| match part {
            RegexPart::Pattern(s) => RegexPart::Pattern(s.clone()),
            RegexPart::PublicPattern((s, n)) => RegexPart::PublicPattern((s.clone(), *n)),
        })
        .collect();

    let decomposed_regex_config = DecomposedRegexConfig { parts };

    // Extract substring indices without NFAGraph (standalone mode)
    let idxes: Vec<(usize, usize)> = extract_substr_idxes(
        haystack,
        &decomposed_regex_config,
        None,  // No NFAGraph - uses standalone mode
        false, // Don't reveal private parts
    )
    .map_err(|e| anyhow::anyhow!("Failed to extract regex matches: {}", e))?;

    let mut circuit_inputs = serde_json::Map::new();

    // OLD FORMAT: Generate {name}RegexIdx fields (not MatchStart/MatchLength!)
    // This matches exactly what old circuits expect

    if idxes.is_empty() {
        return Err(anyhow::anyhow!(
            "No match found for regex '{}' in haystack",
            decomposed_regex.name
        ));
    }

    // Add the first index (full match start position)
    circuit_inputs.insert(
        format!("{}RegexIdx", decomposed_regex.name),
        json!(idxes[0].0),
    );

    // Add remaining indices (capture group start positions)
    for (i, idx) in idxes.iter().enumerate().skip(1) {
        circuit_inputs.insert(
            format!("{}RegexIdx{}", decomposed_regex.name, i),
            json!(idx.0),
        );
    }

    Ok(circuit_inputs)
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
    let email_circuit_inputs;
    if decomposed_regexes[0].has_nfa_graph() {
        email_circuit_inputs = generate_circuit_inputs(circuit_input_params.clone())?;
    } else {
        // TODO: remove all this temperory code for supporting old one
        email_circuit_inputs = generate_circuit_inputs_old(circuit_input_params.clone())?;
    }

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
        circuit_inputs["emailBodyLength"] = email_circuit_inputs.body_padded_len.into();
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
        // Convert location string to enum
        let haystack_location = match decomposed_regex.haystack_location.as_str() {
            "header" => HaystackLocation::Header,
            "body" => HaystackLocation::Body,
            _ => {
                return Err(anyhow::anyhow!(
                    "Invalid location: {}",
                    decomposed_regex.haystack_location
                ))
            }
        };

        let haystack = match haystack_location {
            HaystackLocation::Header => {
                let original_bytes = &email_circuit_inputs.header_padded;
                let trimmed_bytes = trim_sha256_padding(original_bytes);
                String::from_utf8_lossy(trimmed_bytes).into_owned()
            }
            HaystackLocation::Body => {
                let body_bytes = if params.remove_soft_line_breaks {
                    cleaned_body
                        .as_ref()
                        .map(|(v, _)| v.clone())
                        .unwrap_or_else(Vec::new)
                } else {
                    email_circuit_inputs
                        .body_padded
                        .as_ref()
                        .map(|v| v.clone())
                        .unwrap_or_else(Vec::new)
                };

                let trimmed_bytes = trim_sha256_padding(&body_bytes);
                let haystack_string = String::from_utf8(trimmed_bytes.to_vec())
                    .map_err(|e| anyhow::anyhow!("Failed to convert body to UTF-8: {}", e))?;
                haystack_string
            }
        };

        // CONDITIONAL PATH: Check if NFAGraph is available
        if decomposed_regex.has_nfa_graph() {
            // NEW PATH: Use NFAGraph-based generation for circuits compiled with new compiler
            let mut decomposed_regex_config = DecomposedRegexConfig {
                parts: VecDeque::new().into(),
            };
            for part in &decomposed_regex.parts {
                let cloned_part = match part {
                    RegexPart::Pattern(s) => RegexPart::Pattern(s.clone()),
                    RegexPart::PublicPattern((s, n)) => RegexPart::PublicPattern((s.clone(), *n)),
                };
                decomposed_regex_config.parts.push(cloned_part);
            }

            // Use zk_regex_compiler instead of extract_substr_idxes
            // TODO: Same gen_circuit_input is written for noir as well, so we can combine both the functions after this function call
            let regex_graph_json = decomposed_regex.regex_graph_json.as_ref()
                .ok_or_else(|| anyhow::anyhow!("regex_graph_json is missing for decomposed regex"))?;
            let regex_result = gen_circuit_inputs(
                &NFAGraph::from_json(regex_graph_json)?,
                &haystack,
                decomposed_regex.get_max_haystack_length(),
                decomposed_regex.max_match_length,
                decomposed_regex.proving_framework,
            )?;
            match regex_result {
                ProverInputs::Circom(circom_inputs) => {
                    let match_start = circom_inputs.match_start;
                    // Add Circom-specific fields
                    circuit_inputs[format!("{}MatchStart", decomposed_regex.name)] =
                        serde_json::Value::Number(match_start.into());
                    circuit_inputs[format!("{}MatchLength", decomposed_regex.name)] =
                        serde_json::Value::Number(circom_inputs.match_length.into());
                    circuit_inputs[format!("{}CurrentStates", decomposed_regex.name)] =
                        circom_inputs.curr_states.into();
                    circuit_inputs[format!("{}NextStates", decomposed_regex.name)] =
                        circom_inputs.next_states.into();

                    // Add capture group fields if they exist
                    if let Some(capture_group_ids) = circom_inputs.capture_group_ids {
                        for (i, id) in capture_group_ids.iter().enumerate() {
                            circuit_inputs
                                [format!("{}CaptureGroup{}Id", decomposed_regex.name, i)] =
                                serde_json::Value::Array(
                                    id.iter()
                                        .map(|s| serde_json::Value::Number((*s as u64).into()))
                                        .collect(),
                                );
                        }

                        if let Some(capture_group_starts) = circom_inputs.capture_group_starts {
                            for (i, start) in capture_group_starts.iter().enumerate() {
                                circuit_inputs
                                    [format!("{}CaptureGroup{}Start", decomposed_regex.name, i)] =
                                    serde_json::Value::Array(
                                        start
                                            .iter()
                                            .map(|s| serde_json::Value::Number((*s as u64).into()))
                                            .collect(),
                                    );
                            }
                        } else {
                            return Err(anyhow::anyhow!("Capture group starts are missing"));
                        }
                        if let Some(capture_group_indices) =
                            circom_inputs.capture_group_start_indices
                        {
                            circuit_inputs
                                [format!("{}CaptureGroupStartIndices", decomposed_regex.name)] =
                                serde_json::Value::Array(
                                    capture_group_indices
                                        .iter()
                                        .map(|s| serde_json::Value::Number((*s as i64).into()))
                                        .collect(),
                                );
                        } else {
                            return Err(anyhow::anyhow!("Capture group indices are missing"));
                        }
                    }
                }
                ProverInputs::Noir(_) => {
                    return Err(anyhow::anyhow!(
                        "Noir is not supported in this Circom function"
                    ));
                }
            }
        } else {
            // LEGACY PATH: Use standalone extraction for old circuits without NFAGraph
            let legacy_inputs = generate_legacy_circuit_inputs(&decomposed_regex, &haystack)?;
            for (key, value) in legacy_inputs {
                circuit_inputs[key] = value;
            }
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

// TODO : write test for the above functionality
