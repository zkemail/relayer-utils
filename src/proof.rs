#![allow(clippy::upper_case_acronyms)]
#![allow(clippy::identity_op)]

use anyhow::Result;
use ethers::abi::{self, Token};
use ethers::types::{Bytes, U256};

use ::serde::Deserialize;

use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

use crate::{field_to_hex, hex_to_field, AccountCode, AccountSalt, PaddedEmailAddr};

/// Represents the response from the prover.
#[derive(Debug, Clone, Deserialize)]
pub struct ProverRes {
    /// The proof in JSON format.
    proof: ProofJson,
    /// The public signals associated with the proof.
    pub_signals: Vec<String>,
}

/// Represents the proof in JSON format.
#[derive(Debug, Clone, Deserialize)]
pub struct ProofJson {
    /// The pi_a component of the proof.
    pi_a: Vec<String>,
    /// The pi_b component of the proof.
    pi_b: Vec<Vec<String>>,
    /// The pi_c component of the proof.
    pi_c: Vec<String>,
}

impl ProofJson {
    /// Converts the proof to Ethereum-compatible bytes.
    ///
    /// # Returns
    ///
    /// A `Result` containing the Ethereum-compatible bytes or an error.
    pub fn to_eth_bytes(&self) -> Result<Bytes> {
        // Convert pi_a to Token::FixedArray
        let pi_a = Token::FixedArray(vec![
            Token::Uint(U256::from_dec_str(self.pi_a[0].as_str())?),
            Token::Uint(U256::from_dec_str(self.pi_a[1].as_str())?),
        ]);

        // Convert pi_b to nested Token::FixedArray
        let pi_b = Token::FixedArray(vec![
            Token::FixedArray(vec![
                Token::Uint(U256::from_dec_str(self.pi_b[0][1].as_str())?),
                Token::Uint(U256::from_dec_str(self.pi_b[0][0].as_str())?),
            ]),
            Token::FixedArray(vec![
                Token::Uint(U256::from_dec_str(self.pi_b[1][1].as_str())?),
                Token::Uint(U256::from_dec_str(self.pi_b[1][0].as_str())?),
            ]),
        ]);

        // Convert pi_c to Token::FixedArray
        let pi_c = Token::FixedArray(vec![
            Token::Uint(U256::from_dec_str(self.pi_c[0].as_str())?),
            Token::Uint(U256::from_dec_str(self.pi_c[1].as_str())?),
        ]);

        // Encode the tokens and return as Bytes
        Ok(Bytes::from(abi::encode(&[pi_a, pi_b, pi_c])))
    }
}

/// Generates a proof for the given input.
///
/// # Arguments
///
/// * `input` - The input string for proof generation.
/// * `request` - The request string.
/// * `address` - The address string.
///
/// # Returns
///
/// A `Result` containing a tuple of `Bytes` (the proof) and `Vec<U256>` (public signals) or an error.
pub async fn generate_proof(
    input: &str,
    request: &str,
    address: &str,
) -> Result<(Bytes, Vec<U256>)> {
    let client = reqwest::Client::new();

    // Send POST request to the prover
    let res = client
        .post(format!("{}/prove/{}", address, request))
        .json(&serde_json::json!({ "input": input }))
        .send()
        .await?
        .error_for_status()?;

    // Parse the response JSON
    let res_json = res.json::<ProverRes>().await?;

    // Convert the proof to Ethereum-compatible bytes
    let proof = res_json.proof.to_eth_bytes()?;

    // Convert public signals to U256
    let pub_signals = res_json
        .pub_signals
        .into_iter()
        .map(|str| U256::from_dec_str(&str).expect("pub signal should be u256"))
        .collect();

    Ok((proof, pub_signals))
}

/// Calculates a default hash for the given input string.
///
/// # Arguments
///
/// * `input` - The input string to hash.
///
/// # Returns
///
/// A string representation of the calculated hash.
pub fn calculate_default_hash(input: &str) -> String {
    let mut hasher = DefaultHasher::new();
    input.hash(&mut hasher);
    let hash_code = hasher.finish();

    hash_code.to_string()
}

/// Calculates the account salt based on the email address and account code.
///
/// # Arguments
///
/// * `email_addr` - The email address string.
/// * `account_code` - The account code string.
///
/// # Returns
///
/// A string representation of the calculated account salt.
pub fn calculate_account_salt(email_addr: &str, account_code: &str) -> String {
    // Pad the email address
    let padded_email_addr = PaddedEmailAddr::from_email_addr(email_addr);

    // Convert account code to field element
    let account_code = if account_code.starts_with("0x") {
        hex_to_field(account_code).unwrap()
    } else {
        hex_to_field(&format!("0x{}", account_code)).unwrap()
    };
    let account_code = AccountCode::from(account_code);

    // Generate account salt
    let account_salt = AccountSalt::new(&padded_email_addr, account_code).unwrap();

    // Convert account salt to hexadecimal representation
    field_to_hex(&account_salt.0)
}
