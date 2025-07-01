mod structs;
mod utils;

pub use structs::*;
pub use utils::*;

use anyhow::Result;
use num_bigint::{BigUint, ToBigInt};
use serde_json::Value;

use zk_regex_compiler::{gen_circuit_inputs, NFAGraph, ProverInputs};

use crate::{
    remove_quoted_printable_soft_breaks, string_to_circom_bigint_bytes, vec_u8_to_bigint,
    ParsedEmail,
};

use super::{
    compute_signal_length, generate_circuit_inputs, CircuitInputParams,
    CircuitInputWithDecomposedRegexesAndExternalInputsParams, CircuitOptions, CircuitParams,
    ExternalInput,
};

pub const MODULUS_BITS: usize = 2048;

pub async fn generate_noir_circuit_input(
    email: &str,
    params: NoirInputGenerationArgs,
) -> Result<NoirCircuitInputs> {
    // Parse the raw email to extract canonicalized body and header, and other components
    let parsed_email =
        ParsedEmail::new_from_raw_email(email, params.ignore_body_hash_check.unwrap_or(true))
            .await?;

    // Clone the fields that are used by value before the move occurs
    let public_key = BigUint::from_bytes_be(&parsed_email.public_key)
        .to_bigint()
        .unwrap();
    let signature = BigUint::from_bytes_be(&parsed_email.signature)
        .to_bigint()
        .unwrap();

    // Create a CircuitParams struct from the parsed email
    let circuit_params = CircuitParams {
        body: parsed_email.canonicalized_body.as_bytes().to_vec(),
        header: parsed_email.canonicalized_header.as_bytes().to_vec(),
        body_hash_idx: parsed_email.get_body_hash_idxes()?.0,
        rsa_signature: vec_u8_to_bigint(parsed_email.signature),
        rsa_public_key: vec_u8_to_bigint(parsed_email.public_key),
    };

    // Create a CircuitOptions struct from the optional parameters
    let circuit_options = CircuitOptions {
        sha_precompute_selector: params.sha_precompute_selector.clone(),
        max_header_length: params.max_headers_length,
        max_body_length: params.max_body_length,
        ignore_body_hash_check: params.ignore_body_hash_check,
    };

    // Create circuit input parameters from the CircuitParams and CircuitOptions structs
    let circuit_input_params = CircuitInputParams::new(circuit_params, circuit_options);

    // Generate the circuit inputs from the parameters
    let email_circuit_inputs = generate_circuit_inputs(circuit_input_params.clone())?;

    // Create the Pubkey struct for the NoirCircuitInput
    let pubkey = Pubkey {
        modulus: bn_to_limb_str_array(&public_key, Some(MODULUS_BITS)),
        redc: bn_to_redc_limb_str_array(&public_key, Some(MODULUS_BITS)),
    };

    // Get the DKIM header sequence
    let dkim_header_sequence = get_header_sequence(
        &parsed_email.canonicalized_header.as_bytes(),
        "dkim-signature",
    )?;

    // Create the BoundedVec for the header
    let header = BoundedVec {
        storage: email_circuit_inputs.header_padded,
        len: parsed_email.canonicalized_header.as_bytes().len(),
    };

    // Create the BoundedVec for the signature
    let signature = bn_to_limb_str_array(&signature, Some(MODULUS_BITS));

    // Initialize the NoirCircuitInput struct with required fields
    let mut noir_circuit_input = NoirCircuitInputs {
        header,
        pubkey,
        signature,
        dkim_header_sequence,
        body: None,
        body_hash_index: None,
        partial_body_real_length: None,
        partial_body_hash: None,
        header_mask: None,
        body_mask: None,
        decoded_body: None,
        from_header_sequence: None,
        from_address_sequence: None,
        to_header_sequence: None,
        to_address_sequence: None,
    };

    if email_circuit_inputs.body_padded.is_some() {
        let body_padded = email_circuit_inputs.body_padded.clone().unwrap();

        if params.ignore_body_hash_check.is_some_and(|x| !x) {
            if email_circuit_inputs.body_hash_idx.is_none() {
                return Err(anyhow::anyhow!(
                    "Body hash check is enabled but body hash index is missing"
                ));
            }

            noir_circuit_input.body = Some(BoundedVec {
                storage: body_padded.clone(),
                len: parsed_email.canonicalized_body.len(),
            });
            noir_circuit_input.body_hash_index = email_circuit_inputs.body_hash_idx;
        }

        if params.sha_precompute_selector.is_some() {
            noir_circuit_input.partial_body_real_length =
                Some(parsed_email.canonicalized_body.len());
            let partial_hash = u8_to_u32(email_circuit_inputs.precomputed_sha.unwrap().as_slice())?;
            noir_circuit_input.partial_body_hash = Some(partial_hash);

            // Calculate remaining body length after SHA cutoff
            // TODO: This will fail if the selector is not found in the body (i.e selector is without soft line breaks).
            let selector = params.sha_precompute_selector.unwrap();
            let selector_bytes = selector.as_bytes();
            let body_bytes = parsed_email.canonicalized_body.as_bytes();
            let selector_index = body_bytes
                .windows(selector_bytes.len())
                .position(|window| window == selector_bytes)
                .ok_or_else(|| anyhow::anyhow!("Selector not found in body"))?;
            let sha_cutoff_index = (selector_index / 64) * 64;
            let remaining_body_length = body_bytes.len() - sha_cutoff_index;
            noir_circuit_input.body.as_mut().unwrap().len = remaining_body_length;
        }

        if params.body_mask.is_some() {
            noir_circuit_input.body_mask = params.body_mask;
        }

        if params.remove_soft_line_breaks.is_some_and(|x| x) {
            let (cleaned_body, index_map) =
                remove_quoted_printable_soft_breaks(body_padded.clone());
            noir_circuit_input.decoded_body = Some(BoundedVec {
                storage: cleaned_body,
                len: index_map.len(),
            });
        }
    }

    if params.header_mask.is_some() {
        noir_circuit_input.header_mask = params.header_mask;
    }

    if params.extract_from.is_some_and(|extract_from| extract_from) {
        let from_header_sequence =
            get_address_header_sequence(&parsed_email.canonicalized_header.as_bytes(), "from")?;
        noir_circuit_input.from_header_sequence = Some(from_header_sequence[0].clone());
        noir_circuit_input.from_address_sequence = Some(from_header_sequence[1].clone());
    }

    if params.extract_to.is_some_and(|extract_to| extract_to) {
        let to_header_sequence =
            get_address_header_sequence(&parsed_email.canonicalized_header.as_bytes(), "to")?;
        noir_circuit_input.to_header_sequence = Some(to_header_sequence[0].clone());
        noir_circuit_input.to_address_sequence = Some(to_header_sequence[1].clone());
    }

    Ok(noir_circuit_input)
}

pub async fn generate_noir_circuit_inputs_with_regexes_and_external_inputs(
    email: &str,
    regex_inputs: Vec<RegexInput>,
    external_inputs: Vec<ExternalInput>,
    params: CircuitInputWithDecomposedRegexesAndExternalInputsParams,
) -> Result<Value> {
    // Generate basic email circuit inputs first
    let email_circuit_params = NoirInputGenerationArgs {
        max_headers_length: Some(params.max_header_length),
        max_body_length: Some(params.max_body_length),
        ignore_body_hash_check: Some(params.ignore_body_hash_check),
        remove_soft_line_breaks: Some(params.remove_soft_line_breaks),
        sha_precompute_selector: params.sha_precompute_selector,
        ..Default::default()
    };
    let noir_circuit_input = generate_noir_circuit_input(email, email_circuit_params).await?;

    // Convert the NoirCircuitInputs to a JSON Value as the base
    let mut circuit_inputs = to_json_value(&noir_circuit_input)?;

    // Add prover ethereum address if provided
    if let Some(prover_eth_address) = &params.prover_eth_address {
        circuit_inputs["prover_address"] =
            serde_json::Value::Array(vec![serde_json::Value::String(prover_eth_address.clone())]);
    } else {
        circuit_inputs["prover_address"] =
            serde_json::Value::Array(vec![serde_json::Value::String("0x0".to_string())]);
    }

    // Process external inputs and add them to the circuit inputs
    for external_input in external_inputs {
        // Use the existing utility function to convert the string to a Vec<String> of byte values
        let mut value_as_byte_strings =
            string_to_circom_bigint_bytes(&external_input.value.as_deref().unwrap_or(""))?;

        let signal_length = compute_signal_length(external_input.max_length);

        // Pad the Vec<String> with "0" strings if it's shorter than the target length
        if value_as_byte_strings.len() < signal_length {
            value_as_byte_strings.extend(
                std::iter::repeat("0".to_string())
                    .take(signal_length - value_as_byte_strings.len()),
            );
        }

        // Convert the Vec<String> to a serde_json::Value::Array of serde_json::Value::String
        let json_value_array = serde_json::Value::Array(
            value_as_byte_strings
                .into_iter()
                .map(serde_json::Value::String)
                .collect(),
        );
        circuit_inputs[external_input.name] = json_value_array;
    }

    // Process each regex input
    for regex_input in regex_inputs {
        let haystack = match regex_input.haystack_location {
            HaystackLocation::Header => {
                let original_bytes =
                    &noir_circuit_input.header.storage[..noir_circuit_input.header.len];
                let trimmed_bytes = trim_sha256_padding(original_bytes);
                let haystack_string = String::from_utf8(trimmed_bytes.to_vec())
                    .map_err(|e| anyhow::anyhow!("Failed to convert header to UTF-8: {}", e))?;

                haystack_string
            }
            HaystackLocation::Body => {
                let body = if params.remove_soft_line_breaks {
                    noir_circuit_input.decoded_body.as_ref().unwrap()
                } else {
                    noir_circuit_input.body.as_ref().unwrap()
                };

                let original_bytes = &body.storage[..body.len];
                let trimmed_bytes = trim_sha256_padding(original_bytes);
                let haystack_string = String::from_utf8(trimmed_bytes.to_vec())
                    .map_err(|e| anyhow::anyhow!("Failed to convert body to UTF-8: {}", e))?;

                haystack_string
            }
        };

        // Use zk_regex_compiler to generate regex circuit inputs
        let regex_result = gen_circuit_inputs(
            &NFAGraph::from_json(&regex_input.regex_graph_json)?,
            &haystack,
            regex_input.max_haystack_length,
            regex_input.max_match_length,
            regex_input.proving_framework,
        )?;

        match regex_result {
            // Add regex fields to circuit inputs with the regex name as prefix
            ProverInputs::Noir(noir_inputs) => {
                circuit_inputs[format!("{}_match_start", regex_input.name)] =
                    serde_json::Value::Number(noir_inputs.match_start.into());
                circuit_inputs[format!("{}_match_length", regex_input.name)] =
                    serde_json::Value::Number(noir_inputs.match_length.into());
                circuit_inputs[format!("{}_current_states", regex_input.name)] =
                    serde_json::Value::Array(
                        noir_inputs
                            .curr_states
                            .iter()
                            .map(|s| serde_json::Value::Number((*s as u64).into()))
                            .collect(),
                    );
                circuit_inputs[format!("{}_next_states", regex_input.name)] =
                    serde_json::Value::Array(
                        noir_inputs
                            .next_states
                            .iter()
                            .map(|s| serde_json::Value::Number((*s as u64).into()))
                            .collect(),
                    );

                // Add capture group fields if they exist
                if let Some(capture_group_ids) = noir_inputs.capture_group_ids {
                    for (i, id) in capture_group_ids.iter().enumerate() {
                        circuit_inputs
                            [format!("{}_capture_group_{}_id", regex_input.name, i + 1)] =
                            serde_json::Value::Array(
                                id.iter()
                                    .map(|s| serde_json::Value::Number((*s as u64).into()))
                                    .collect(),
                            );
                    }

                    if let Some(capture_group_starts) = noir_inputs.capture_group_starts {
                        for (i, start) in capture_group_starts.iter().enumerate() {
                            circuit_inputs
                                [format!("{}_capture_group_{}_start", regex_input.name, i + 1)] =
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

                    if let Some(capture_group_indices) = noir_inputs.capture_group_start_indices {
                        circuit_inputs
                            [format!("{}_capture_group_start_indices", regex_input.name)] =
                            serde_json::Value::Array(
                                capture_group_indices
                                    .iter()
                                    .map(|s| serde_json::Value::Number((*s as u64).into()))
                                    .collect(),
                            );
                    } else {
                        return Err(anyhow::anyhow!("Capture group indices are missing"));
                    }
                }
            }
            ProverInputs::Circom(_) => {
                return Err(anyhow::anyhow!("Circom is not supported yet"));
            }
        }
    }

    Ok(circuit_inputs)
}

/// Converts a NoirCircuitInputs struct to a JSON Value
///
/// This is useful for compatibility with systems expecting JSON output
pub fn to_json_value(input: &NoirCircuitInputs) -> Result<Value> {
    let json_value = serde_json::to_value(input)?;
    Ok(json_value)
}

/// Generates a Noir circuit input and converts it to a JSON Value for backward compatibility
///
/// This function maintains compatibility with the original JSON interface
pub async fn generate_noir_circuit_input_json(
    email: &str,
    params: NoirInputGenerationArgs,
) -> Result<Value> {
    let noir_circuit_input = generate_noir_circuit_input(email, params).await?;
    to_json_value(&noir_circuit_input)
}

#[cfg(test)]
mod tests {
    use crate::circuit::noir::{
        generate_noir_circuit_input, generate_noir_circuit_input_json,
        structs::NoirInputGenerationArgs,
    };
    use serde_json::to_string_pretty;

    #[tokio::test]
    async fn test_generate_noir_circuit_input() {
        let email = include_str!("../../../tests/fixtures/test.eml");
        let params = NoirInputGenerationArgs {
            max_headers_length: Some(576),
            extract_from: Some(true),
            ..Default::default()
        };

        // Test the struct-based approach
        let noir_circuit_input = generate_noir_circuit_input(email, params.clone())
            .await
            .unwrap();

        // Convert to JSON string for debugging
        let json_output = to_string_pretty(&noir_circuit_input).unwrap();
        println!(
            "noir_circuit_input struct converted to JSON: {}",
            json_output
        );

        // Test the JSON-based approach for backward compatibility
        let json_value = generate_noir_circuit_input_json(email, params)
            .await
            .unwrap();
        println!("noir_circuit_input direct JSON: {}", json_value);
    }
}
