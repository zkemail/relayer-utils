#![allow(clippy::upper_case_acronyms)]
#![allow(clippy::identity_op)]

use anyhow::Result;
use ethers::abi::{self, Token};
use ethers::types::{Bytes, U256};

use ::serde::Deserialize;

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

pub async fn generate_proof_gpu(
    input: &str,
    blueprint_id: &str,
    proof_id: &str,
    zkey_download_url: &str,
    circuit_cpp_download_url: &str,
    api_key: &str,
    address: &str,
) -> Result<(Bytes, Vec<U256>)> {
    let client = reqwest::Client::new();

    // Parse input string as JSON value
    let input_json: serde_json::Value = serde_json::from_str(input)?;

    // Send POST request to the prover
    let res = client
        .post(address)
        .header("x-api-key", api_key)
        .header("Content-Type", "application/json")
        .json(&serde_json::json!({
            "blueprintId": blueprint_id,
            "proofId": proof_id,
            "zkeyDownloadUrl": zkey_download_url,
            "circuitCppDownloadUrl": circuit_cpp_download_url,
            "input": input_json
        }))
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
