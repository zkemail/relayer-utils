use anyhow::Result;
use num_bigint::BigInt;
use serde::{Deserialize, Serialize};
use std::cmp;

use crate::{
    field_to_hex, generate_partial_sha, sha256_pad, to_circom_bigint_bytes, vec_u8_to_bigint,
    AccountCode, PaddedEmailAddr, ParsedEmail, MAX_BODY_PADDED_BYTES, MAX_HEADER_PADDED_BYTES,
};

#[derive(Serialize, Deserialize)]
struct EmailCircuitInput {
    padded_header: Vec<u8>,
    padded_body: Option<Vec<u8>>,
    body_hash_idx: Option<usize>,
    public_key: Vec<String>,
    signature: Vec<String>,
    padded_header_len: usize,
    padded_body_len: Option<usize>,
    precomputed_sha: Option<Vec<u8>>,
    account_code: String,
    from_addr_idx: usize,
    subject_idx: usize,
    domain_idx: usize,
    timestamp_idx: usize,
    code_idx: usize,
    command_idx: usize,
}

#[derive(Serialize, Deserialize)]
pub struct EmailCircuitParams {
    pub ignore_body_hash_check: Option<bool>,
    pub max_header_length: Option<usize>,
    pub max_body_length: Option<usize>,
    pub sha_precompute_selector: Option<String>,
}

#[derive(Serialize, Deserialize)]
struct ClaimCircuitInput {
    email_addr: Vec<u8>,
    cm_rand: String,
    account_code: String,
}

struct CircuitInput {
    pub header_padded: Vec<u8>,
    pub pubkey: Vec<String>,
    pub signature: Vec<String>,
    pub header_len_padded_bytes: usize,
    pub precomputed_sha: Option<Vec<u8>>,
    pub body_padded: Option<Vec<u8>>,
    pub body_len_padded_bytes: Option<usize>,
    pub body_hash_idx: Option<usize>,
}

pub struct CircuitInputParams {
    body: Vec<u8>,
    header: Vec<u8>,
    body_hash_idx: usize,
    rsa_signature: BigInt,
    rsa_public_key: BigInt,
    sha_precompute_selector: Option<String>,
    max_header_length: usize,
    max_body_length: usize,
    ignore_body_hash_check: bool,
}

impl CircuitInputParams {
    // Provides default values for optional parameters
    pub fn new(
        body: Vec<u8>,
        header: Vec<u8>,
        body_hash_idx: usize,
        rsa_signature: BigInt,
        rsa_public_key: BigInt,
        sha_precompute_selector: Option<String>,
        max_header_length: Option<usize>,
        max_body_length: Option<usize>,
        ignore_body_hash_check: Option<bool>,
    ) -> Self {
        CircuitInputParams {
            body,
            header,
            body_hash_idx,
            rsa_signature,
            rsa_public_key,
            sha_precompute_selector,
            max_header_length: max_header_length.unwrap_or(MAX_HEADER_PADDED_BYTES),
            max_body_length: max_body_length.unwrap_or(MAX_BODY_PADDED_BYTES),
            ignore_body_hash_check: ignore_body_hash_check.unwrap_or(false),
        }
    }
}

fn generate_circuit_inputs(params: CircuitInputParams) -> CircuitInput {
    let (header_padded, header_padded_len) =
        sha256_pad(params.header.clone(), params.max_header_length);
    let body_sha_length = ((params.body.len() + 63 + 65) / 64) * 64;
    let (body_padded, body_padded_len) = sha256_pad(
        params.body,
        cmp::max(params.max_body_length, body_sha_length),
    );

    let result = generate_partial_sha(
        body_padded,
        body_padded_len,
        params.sha_precompute_selector,
        params.max_body_length,
    );

    let (precomputed_sha, body_remaining, body_remaining_length) = match result {
        Ok((sha, remaining, len)) => (sha, remaining, len),
        Err(e) => panic!("Failed to generate partial SHA: {:?}", e),
    };

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

    if !params.ignore_body_hash_check {
        circuit_input.precomputed_sha = Some(precomputed_sha);
        circuit_input.body_hash_idx = Some(params.body_hash_idx);
        circuit_input.body_padded = Some(body_remaining);
        circuit_input.body_len_padded_bytes = Some(body_remaining_length);
    }
    circuit_input
}

pub async fn generate_email_circuit_input(
    email: &str,
    account_code: &AccountCode,
    params: Option<EmailCircuitParams>,
) -> Result<String> {
    let parsed_email = ParsedEmail::new_from_raw_email(&email).await?;
    let circuit_input_params = CircuitInputParams::new(
        parsed_email.canonicalized_body.as_bytes().to_vec(),
        parsed_email.canonicalized_header.as_bytes().to_vec(),
        parsed_email.get_body_hash_idxes()?.0,
        vec_u8_to_bigint(parsed_email.clone().signature),
        vec_u8_to_bigint(parsed_email.clone().public_key),
        params
            .as_ref()
            .and_then(|p| p.sha_precompute_selector.clone()),
        params.as_ref().and_then(|p| p.max_header_length),
        params.as_ref().and_then(|p| p.max_body_length),
        params.as_ref().and_then(|p| p.ignore_body_hash_check),
    );
    let email_circuit_inputs = generate_circuit_inputs(circuit_input_params);

    let from_addr_idx = parsed_email.get_from_addr_idxes()?.0;
    let domain_idx = parsed_email.get_email_domain_idxes()?.0;
    let subject_idx = parsed_email.get_subject_all_idxes()?.0;
    let code_idx = match parsed_email.get_invitation_code_idxes() {
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

    let email_auth_input = EmailCircuitInput {
        padded_header: email_circuit_inputs.header_padded,
        public_key: email_circuit_inputs.pubkey,
        signature: email_circuit_inputs.signature,
        padded_header_len: email_circuit_inputs.header_len_padded_bytes,
        account_code: field_to_hex(&account_code.0),
        from_addr_idx: from_addr_idx,
        subject_idx: subject_idx,
        domain_idx: domain_idx,
        timestamp_idx: timestamp_idx,
        code_idx,
        padded_body: email_circuit_inputs.body_padded,
        body_hash_idx: email_circuit_inputs.body_hash_idx,
        padded_body_len: email_circuit_inputs.body_len_padded_bytes,
        precomputed_sha: email_circuit_inputs.precomputed_sha,
        command_idx,
    };

    Ok(serde_json::to_string(&email_auth_input)?)
}

pub async fn generate_claim_input(
    email_address: &str,
    email_address_rand: &str,
    account_code: &str,
) -> Result<String> {
    let padded_email_address = PaddedEmailAddr::from_email_addr(email_address);
    let mut padded_email_addr_bytes = vec![];

    for byte in padded_email_address.padded_bytes.into_iter() {
        padded_email_addr_bytes.push(byte);
    }

    let claim_input = ClaimCircuitInput {
        email_addr: padded_email_addr_bytes,
        cm_rand: email_address_rand.to_string(),
        account_code: account_code.to_string(),
    };

    Ok(serde_json::to_string(&claim_input)?)
}
