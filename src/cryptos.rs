//! Cryptographic functions.

use crate::EmailHeaders;
use crate::{field_to_hex, hex_to_field};
use anyhow::Result;
use base64::{self, engine::general_purpose, Engine as _};
use cfdkim::{self, verify_email_with_key, DKIMError, DkimPublicKey};
use ethers::types::Bytes;
use halo2curves::ff::Field;
use mailparse::ParsedMail;
use poseidon_rs::{poseidon_bytes, poseidon_fields, Fr, PoseidonError};
use rand_core::RngCore;
use regex::Regex;
use rsa::pkcs8::DecodePublicKey;
use rsa::traits::PublicKeyParts;
use rsa::{pkcs1::DecodeRsaPublicKey, RsaPublicKey};
use serde::{
    de::{self, Visitor},
    Deserialize, Deserializer, Serialize, Serializer,
};
use std::collections::HashMap;
use std::{
    collections::hash_map::DefaultHasher,
    error::Error,
    fmt,
    hash::{Hash, Hasher},
};
use zk_regex_apis::padding::pad_string;

use crate::{
    converters::{
        bytes_chunk_fields, bytes_to_fields, int64_to_bytes, int8_to_bytes, merge_u8_arrays,
    },
    MAX_EMAIL_ADDR_BYTES,
};

const GAPPS_DOMAIN: &str = "gappssmtp.com";
const DKIM_API_URL: &str = "https://archive.zk.email/api/key";

type ShaResult = Vec<u8>; // The result of a SHA-256 hash operation.
type RemainingBody = Vec<u8>; // The remaining part of a message after a SHA-256 hash operation.
type RemainingBodyLength = usize; // The length of the remaining message body in bytes.
type PartialShaResult = Result<(ShaResult, RemainingBody, RemainingBodyLength), Box<dyn Error>>; // The result of a partial SHA-256 hash operation, including the hash, remaining body, and its length, or an error.

#[derive(Debug, Clone, Copy)]
/// `RelayerRand` is a single field element representing a random value.
pub struct RelayerRand(pub Fr);

impl RelayerRand {
    /// Constructs a new `RelayerRand` using a random number generator.
    ///
    /// # Arguments
    ///
    /// * `r` - A mutable reference to an object that implements `RngCore`.
    ///
    /// # Returns
    ///
    /// A new instance of `RelayerRand`.
    pub fn new<R: RngCore>(mut r: R) -> Self {
        Self(Fr::random(&mut r))
    }

    /// Constructs a new `RelayerRand` from a given seed.
    ///
    /// # Arguments
    ///
    /// * `seed` - A byte slice used as the seed for randomness.
    ///
    /// # Returns
    ///
    /// A result that is either a new instance of `RelayerRand` or a `PoseidonError`.
    pub fn new_from_seed(seed: &[u8]) -> Result<Self, PoseidonError> {
        let value = poseidon_bytes(seed)?;
        Ok(Self(value))
    }

    /// Hashes the `RelayerRand` using Poseidon hash function.
    ///
    /// # Returns
    ///
    /// A result that is either the Poseidon hash of the `RelayerRand` or a `PoseidonError`.
    pub fn hash(&self) -> Result<Fr, PoseidonError> {
        poseidon_fields(&[self.0])
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
/// `PaddedEmailAddr` is a structure that holds a padded email address and its original length.
pub struct PaddedEmailAddr {
    pub padded_bytes: Vec<u8>, // Padded email address bytes
    pub email_addr_len: usize, // Original email address length
}

impl PaddedEmailAddr {
    /// Creates a new `PaddedEmailAddr` from a given email address.
    ///
    /// # Arguments
    ///
    /// * `email_addr` - A string slice representing the email address to be padded.
    ///
    /// # Returns
    ///
    /// A new instance of `PaddedEmailAddr`.
    pub fn from_email_addr(email_addr: &str) -> Self {
        let email_addr_len = email_addr.as_bytes().len();
        let padded_bytes = pad_string(email_addr, MAX_EMAIL_ADDR_BYTES);
        Self {
            padded_bytes,
            email_addr_len,
        }
    }

    /// Converts the padded email address into a vector of field elements.
    ///
    /// # Returns
    ///
    /// A vector of `Fr` representing the field elements of the padded email address.
    pub fn to_email_addr_fields(&self) -> Vec<Fr> {
        bytes_to_fields(&self.padded_bytes)
    }

    /// Creates a commitment to the padded email address using a random field element.
    ///
    /// # Arguments
    ///
    /// * `rand` - A reference to a field element used as randomness in the commitment.
    ///
    /// # Returns
    ///
    /// A result that is either the commitment as a field element or a `PoseidonError`.
    pub fn to_commitment(&self, rand: &Fr) -> Result<Fr, PoseidonError> {
        let mut inputs = vec![*rand];
        inputs.append(&mut self.to_email_addr_fields());
        poseidon_fields(&inputs)
    }

    /// Creates a commitment to the padded email address using a signature to extract randomness.
    ///
    /// # Arguments
    ///
    /// * `signature` - A byte slice representing the signature from which randomness is extracted.
    ///
    /// # Returns
    ///
    /// A result that is either the commitment as a field element or a `PoseidonError`.
    pub fn to_commitment_with_signature(&self, signature: &[u8]) -> Result<Fr, PoseidonError> {
        let cm_rand = extract_rand_from_signature(signature)?;
        poseidon_fields(&[vec![cm_rand], self.to_email_addr_fields()].concat())
    }
}

#[derive(Debug, Clone, Copy)]
/// `AccountCode` is a structure that holds a single field element representing an account code.
pub struct AccountCode(pub Fr);

impl<'de> Deserialize<'de> for AccountCode {
    /// Deserializes a string into an `AccountCode`.
    ///
    /// # Arguments
    ///
    /// * `deserializer` - The deserializer to use for converting the string into an `AccountCode`.
    ///
    /// # Returns
    ///
    /// A result that is either an `AccountCode` or a deserialization error.
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct AccountCodeVisitor;

        impl<'de> Visitor<'de> for AccountCodeVisitor {
            type Value = AccountCode;

            /// Describes what the visitor expects to receive.
            ///
            /// # Arguments
            ///
            /// * `formatter` - A formatter to write the expected type description.
            ///
            /// # Returns
            ///
            /// A `fmt::Result` indicating success or failure.
            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a valid field element for AccountCode")
            }

            /// Visits a string and attempts to convert it into an `AccountCode`.
            ///
            /// # Arguments
            ///
            /// * `value` - The string value to convert.
            ///
            /// # Returns
            ///
            /// A result that is either an `AccountCode` or a deserialization error.
            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                // Convert the string to a field element
                let fr_value = hex_to_field(value).map_err(de::Error::custom)?;
                Ok(AccountCode(fr_value))
            }
        }

        // Deserialize the string using the AccountCodeVisitor
        deserializer.deserialize_str(AccountCodeVisitor)
    }
}

impl Serialize for AccountCode {
    /// Serializes an `AccountCode` into a string.
    ///
    /// # Arguments
    ///
    /// * `serializer` - The serializer to use for converting the `AccountCode` into a string.
    ///
    /// # Returns
    ///
    /// A result that is either a serialized string or a serialization error.
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        // Convert the field element to a hexadecimal string
        let hex_value = field_to_hex(&self.0);
        // Serialize the hexadecimal string
        serializer.serialize_str(&hex_value)
    }
}

impl AccountCode {
    /// Constructs a new `AccountCode` using a random number generator.
    ///
    /// # Arguments
    ///
    /// * `rng` - An object that implements `RngCore`.
    ///
    /// # Returns
    ///
    /// A new instance of `AccountCode`.
    pub fn new<R: RngCore>(rng: R) -> Self {
        Self(Fr::random(rng))
    }

    /// Constructs a new `AccountCode` from a given field element.
    ///
    /// # Arguments
    ///
    /// * `elem` - A field element to be used as the account code.
    ///
    /// # Returns
    ///
    /// A new instance of `AccountCode`.
    pub fn from(elem: Fr) -> Self {
        Self(elem)
    }

    /// Creates a commitment to the account code using the padded email address and a hash of the relayer's randomness.
    ///
    /// # Arguments
    ///
    /// * `email_addr` - A reference to a `PaddedEmailAddr` instance.
    /// * `relayer_rand_hash` - A reference to a field element representing the hash of the relayer's randomness.
    ///
    /// # Returns
    ///
    /// A result that is either the commitment as a field element or a `PoseidonError`.
    pub fn to_commitment(
        &self,
        email_addr: &PaddedEmailAddr,
        relayer_rand_hash: &Fr,
    ) -> Result<Fr, PoseidonError> {
        let mut inputs = vec![self.0];
        inputs.append(&mut email_addr.to_email_addr_fields());
        inputs.push(*relayer_rand_hash);
        poseidon_fields(&inputs)
    }
}

#[derive(Debug, Clone, Copy)]
/// `AccountSalt` is the poseidon hash of the padded email address and account code.
pub struct AccountSalt(pub Fr);

impl Serialize for AccountSalt {
    /// Serializes an `AccountSalt` into a string.
    ///
    /// # Arguments
    ///
    /// * `serializer` - The serializer to use for converting the `AccountSalt` into a string.
    ///
    /// # Returns
    ///
    /// A result that is either a serialized string or a serialization error.
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        // Convert the field element to a hexadecimal string
        let hex_value = field_to_hex(&self.0);
        // Serialize the hexadecimal string
        serializer.serialize_str(&hex_value)
    }
}

impl AccountSalt {
    /// Creates a new `AccountSalt` using the padded email address and account code.
    ///
    /// # Arguments
    ///
    /// * `email_addr` - A reference to a `PaddedEmailAddr` instance.
    /// * `account_code` - An `AccountCode` instance representing the account code.
    ///
    /// # Returns
    ///
    /// A result that is either a new instance of `AccountSalt` or a `PoseidonError`.
    pub fn new(
        email_addr: &PaddedEmailAddr,
        account_code: AccountCode,
    ) -> Result<Self, PoseidonError> {
        let mut inputs = email_addr.to_email_addr_fields();
        inputs.push(account_code.0);
        inputs.push(Fr::zero());
        Ok(AccountSalt(poseidon_fields(&inputs)?))
    }

    /// Creates a new `AccountSalt` from a byte slice.
    ///
    /// # Arguments
    ///
    /// * `bytes` - A byte slice to be converted into a field element for the account salt.
    ///
    /// # Returns
    ///
    /// A result that is either a new instance of `AccountSalt` or a `PoseidonError`.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, PoseidonError> {
        // Convert bytes to field elements
        let fields = bytes_to_fields(bytes);

        // Add a zero field element to the inputs
        let mut inputs = fields;
        inputs.push(Fr::zero());

        // Compute the Poseidon hash
        let salt = poseidon_fields(&inputs)?;

        Ok(AccountSalt(salt))
    }
}

/// Extracts a random field element from a signature.
///
/// # Arguments
///
/// * `signature` - A byte slice representing the signature.
///
/// # Returns
///
/// A result that is either a random field element or a `PoseidonError`.
pub fn extract_rand_from_signature(signature: &[u8]) -> Result<Fr, PoseidonError> {
    let mut signature = signature.to_vec();
    signature.reverse();
    let mut inputs = bytes_chunk_fields(&signature, 121, 2, 17);
    inputs.push(Fr::one());
    let cm_rand = poseidon_fields(&inputs)?;
    Ok(cm_rand)
}

/// Computes the Poseidon hash of a public key.
///
/// # Arguments
///
/// * `public_key_n` - A byte slice representing the public key in little endian format.
///
/// # Returns
///
/// A result that is either the Poseidon hash of the public key or a `PoseidonError`.
pub fn public_key_hash(public_key_n: &[u8]) -> Result<Fr, PoseidonError> {
    let inputs = bytes_chunk_fields(public_key_n, 121, 2, 17);
    poseidon_fields(&inputs)
}

/// Computes the Poseidon hash to generate an email nullifier.
///
/// # Arguments
///
/// * `signature` - A byte slice representing the signature in little endian format.
///
/// # Returns
///
/// A result that is either the Poseidon hash of the signature or a `PoseidonError`.
pub fn email_nullifier(signature: &[u8]) -> Result<Fr, PoseidonError> {
    let inputs = bytes_chunk_fields(signature, 121, 2, 17);
    let sign_rand = poseidon_fields(&inputs)?;
    poseidon_fields(&[sign_rand])
}

/// Pads the given data to be a valid SHA-256 message block and extends it to a specified maximum length.
///
/// # Arguments
///
/// * `data` - The original data to be padded.
/// * `max_sha_bytes` - The maximum length in bytes to which the data should be extended.
///
/// # Returns
///
/// A tuple containing the padded data and the length of the original data before padding.
pub fn sha256_pad(mut data: Vec<u8>, max_sha_bytes: usize) -> (Vec<u8>, usize) {
    let length_bits = data.len() * 8; // Convert length from bytes to bits
    let length_in_bytes = int64_to_bytes(length_bits as u64);

    // Add the bit '1' to the end of the data
    data = merge_u8_arrays(data, int8_to_bytes(0x80));

    while (data.len() * 8 + length_in_bytes.len() * 8) % 512 != 0 {
        data = merge_u8_arrays(data, int8_to_bytes(0));
    }

    // Append the original length in bits at the end of the data
    data = merge_u8_arrays(data, length_in_bytes);

    // Ensure that the padding is complete
    assert!(
        (data.len() * 8) % 512 == 0,
        "Padding did not complete properly!"
    );

    let message_len = data.len();

    // Pad the data to the specified maximum length with zeros
    while data.len() < max_sha_bytes {
        data = merge_u8_arrays(data, int64_to_bytes(0));
    }

    // Ensure that the data is padded to the maximum length
    assert!(
    data.len() == max_sha_bytes,
    "Padding to max length did not complete properly! Your padded message is {} long but max is {}!",
    data.len(),
    max_sha_bytes
  );

    (data, message_len)
}

/// Computes the SHA-256 hash of a message up to a specified length.
///
/// # Arguments
///
/// * `msg` - The message to be hashed.
/// * `msg_len` - The length of the message to consider for the hash.
///
/// # Returns
///
/// A vector containing the SHA-256 hash of the message.
pub fn partial_sha(msg: &[u8], msg_len: usize) -> Vec<u8> {
    let mut hasher = hmac_sha256::Hash::new();
    hasher.update(&msg[..msg_len]);
    let result = hasher.cache_state();
    result.to_vec()
}

/// Generates a partial SHA-256 hash of a message up to the point of a selector string, if provided.
///
/// # Arguments
///
/// * `body` - The message body as a vector of bytes.
/// * `body_length` - The length of the message body to consider.
/// * `selector_regex` - An optional string which is a regex selector to find in the body to split the message.
/// * `max_remaining_body_length` - The maximum length allowed for the remaining body after the selector.
///
/// # Returns
///
/// A tuple containing the SHA-256 hash of the pre-selector part of the message, the remaining body after the selector, and its length.
/// If an error occurs, it is returned as a `Box<dyn Error>`.
pub fn generate_partial_sha(
    body: Vec<u8>,
    body_length: usize,
    selector_regex: Option<String>,
    max_remaining_body_length: usize,
) -> PartialShaResult {
    let mut selector_index = 0;

    // Check if a selector is provided
    if let Some(selector) = selector_regex {
        // Create a regex pattern from the selector
        let pattern = regex::Regex::new(&selector).unwrap();
        let body_str = {
            // Undo SHA padding
            let mut trimmed_body = body.clone();
            while !(trimmed_body.last() == Some(&10)
                && trimmed_body.get(trimmed_body.len() - 2) == Some(&13))
            {
                trimmed_body.pop();
            }

            String::from_utf8(trimmed_body).unwrap()
        };

        // Find the index of the selector in the body
        if let Some(matched) = pattern.find(&body_str) {
            selector_index = matched.start();
        } else {
            return Err(Box::new(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("Selector {} not found in the body", selector),
            )));
        }
    }

    // Calculate the cutoff index for SHA-256 block size (64 bytes)
    let sha_cutoff_index = (selector_index / 64) * 64;
    let precompute_text = &body[..sha_cutoff_index];
    let mut body_remaining = body[sha_cutoff_index..].to_vec();

    let body_remaining_length = body_length - precompute_text.len();

    // Check if the remaining body length exceeds the maximum allowed length
    if body_remaining_length > max_remaining_body_length {
        return Err(Box::new(std::io::Error::new(
            std::io::ErrorKind::Other,
            format!(
                "Remaining body {} after the selector is longer than max ({})",
                body_remaining_length, max_remaining_body_length
            ),
        )));
    }

    // Ensure the remaining body is padded correctly to 64-byte blocks
    if body_remaining.len() % 64 != 0 {
        return Err(Box::new(std::io::Error::new(
            std::io::ErrorKind::Other,
            "Remaining body was not padded correctly with int64s",
        )));
    }

    // Pad the remaining body to the maximum length with zeros
    while body_remaining.len() < max_remaining_body_length {
        body_remaining.push(0);
    }

    // Compute the SHA-256 hash of the pre-selector part of the message
    let precomputed_sha = partial_sha(precompute_text, sha_cutoff_index);
    Ok((precomputed_sha, body_remaining, body_remaining_length))
}

/// Computes the Keccak-256 hash of the given data.
///
/// # Arguments
///
/// * `data` - A byte slice representing the data to hash.
///
/// # Returns
///
/// The Keccak-256 hash as a `Bytes` object.
pub fn keccak256(data: &[u8]) -> Bytes {
    Bytes::from(ethers::utils::keccak256(data))
}

#[cfg(test)]
mod tests {
    use std::fs;

    use mailparse::parse_mail;

    use crate::field_to_hex;

    use super::*;

    #[test]
    fn test_public_key_hash() {
        let mut public_key_n = hex
      ::decode(
        "cfb0520e4ad78c4adb0deb5e605162b6469349fc1fde9269b88d596ed9f3735c00c592317c982320874b987bcc38e8556ac544bdee169b66ae8fe639828ff5afb4f199017e3d8e675a077f21cd9e5c526c1866476e7ba74cd7bb16a1c3d93bc7bb1d576aedb4307c6b948d5b8c29f79307788d7a8ebf84585bf53994827c23a5"
      )
      .unwrap();
        public_key_n.reverse();
        let hash_field = public_key_hash(&public_key_n).unwrap();
        let expected_hash = format!(
            "0x{}",
            hex::encode([
                24, 26, 185, 80, 217, 115, 238, 83, 131, 133, 50, 236, 177, 184, 177, 21, 40, 246,
                234, 122, 176, 142, 40, 104, 251, 50, 24, 70, 64, 82, 249, 83,
            ])
        );
        assert_eq!(field_to_hex(&hash_field), expected_hash);
    }

    #[tokio::test]
    async fn test_fetch_public_key() -> Result<()> {
        if std::env::var("CI").is_ok() {
            println!("Skipping test that requires confidential data in CI environment");
            return Ok(());
        }

        let fixtures_dir = "tests/fixtures/confidential_outlook";
        let mut results = Vec::new();

        // Read all .eml files from fixtures directory
        for entry in fs::read_dir(fixtures_dir)? {
            let entry = entry?;
            let path = entry.path();

            if path.extension().and_then(|s| s.to_str()) == Some("eml") {
                let filename = path.file_name().unwrap().to_string_lossy();
                let result = (async {
                    let eml = fs::read_to_string(&path)?;
                    let parsed_mail = parse_mail(eml.as_bytes())?;
                    let headers = EmailHeaders::new_from_mail(&parsed_mail);
                    fetch_public_key_and_verify(parsed_mail, headers, true).await
                    // fetch_public_keys(headers).await
                })
                .await;

                match &result {
                    Ok(_) => println!("✓ {} - Success", filename),
                    Err(e) => println!("✗ {} - Error: {}", filename, e),
                }

                results.push((filename.to_string(), result));
            }
        }

        // Generate report
        println!("\n=== Public Key Fetch Test Report ===");
        println!("{:<30} {:<10}", "File", "Status");
        println!("{}", "-".repeat(42));

        let mut passed = 0;
        let total = results.len();

        for (filename, result) in results {
            match result {
                Ok(_) => {
                    println!("{:<30} {}", filename, "✓ PASS");
                    passed += 1;
                }
                Err(e) => {
                    println!("{:<30} {} ({})", filename, "✗ FAIL", e);
                }
            }
        }

        println!("\nSummary:");
        println!(
            "Passed: {}/{} ({:.1}%)",
            passed,
            total,
            ((passed as f64) / (total as f64)) * 100.0
        );
        println!("Failed: {}/{}", total - passed, total);
        println!("==============================\n");

        // Test passes if at least one email succeeded
        assert!(
            passed > 0,
            "No email fixtures passed the public key fetch test"
        );
        Ok(())
    }
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

/// Fetches the public key from DNS records using the DKIM signature in the email headers.
///
/// # Arguments
///
/// * `email_headers` - An `EmailHeaders` object containing the headers of the email.
///
/// # Returns
///
/// A `Result` containing a vector of bytes representing the public key, or an error if the key is not found.
async fn fetch_public_keys(email_headers: EmailHeaders) -> Result<(serde_json::Value, String)> {
    // Extract From header with better error handling
    let from_headers = email_headers
        .get_header("From")
        .ok_or_else(|| anyhow::anyhow!("From header not found"))?;

    if from_headers.is_empty() {
        return Err(anyhow::anyhow!("From header is empty"));
    }

    if from_headers.len() > 1 {
        return Err(anyhow::anyhow!(
            "From header contains multiple addresses: {:?}",
            from_headers
        ));
    }

    // Extract domain from From header
    let from_domain = from_headers[0].as_str();
    let from_re = Regex::new(r"@([^>\s]+)").unwrap();
    let from_domain = from_re
        .captures(from_domain)
        .and_then(|cap| cap.get(1))
        .map(|m| m.as_str().to_string())
        .ok_or_else(|| {
            anyhow::anyhow!("Could not extract domain from From header: {}", from_domain)
        })?;

    // Extract DKIM headers
    let dkim_headers = email_headers
        .get_header("DKIM-Signature")
        .or_else(|| email_headers.get_header("Dkim-Signature"))
        .ok_or_else(|| anyhow::anyhow!("No DKIM signature found"))?;

    if dkim_headers.is_empty() {
        return Err(anyhow::anyhow!("DKIM-Signature header is empty"));
    }

    // Build domain-selector map
    let mut domain_selector_map = HashMap::<String, String>::new();
    let s_re = Regex::new(r"s=([^;]+);").unwrap();
    let d_re = Regex::new(r"d=([^;]+);").unwrap();

    for (i, header) in dkim_headers.iter().enumerate() {
        let domain = d_re
            .captures(header)
            .and_then(|cap| cap.get(1))
            .map(|m| m.as_str().to_string())
            .ok_or_else(|| {
                anyhow::anyhow!("Could not extract domain from DKIM signature #{}", i + 1)
            })?;

        let selector = s_re
            .captures(header)
            .and_then(|cap| cap.get(1))
            .map(|m| m.as_str().to_string())
            .ok_or_else(|| {
                anyhow::anyhow!("Could not extract selector from DKIM signature #{}", i + 1)
            })?;

        domain_selector_map.insert(domain, selector);
    }

    // First try direct match, then fall back to GApps domain if needed
    let result = domain_selector_map
        .iter()
        .find(|(domain, _)| {
            from_domain == **domain || domain.ends_with(&format!(".{}", from_domain))
        })
        .map(|(k, v)| (k.clone(), v.clone()))
        .or_else(|| {
            domain_selector_map
                .iter()
                .find(|(domain, _)| domain.contains(GAPPS_DOMAIN))
                .map(|(k, v)| (k.clone(), v.clone()))
        })
        .ok_or_else(|| {
            let available_domains = domain_selector_map
                .keys()
                .cloned()
                .collect::<Vec<_>>()
                .join(", ");
            anyhow::anyhow!(
                "No matching DKIM signature found for sender domain '{}'. Available domains: [{}]",
                from_domain,
                available_domains
            )
        })?;

    let (matching_domain, selector) = result;

    // Try to fetch the public key
    let url = format!(
        "{}?domain={}&selector={}",
        DKIM_API_URL, matching_domain, selector
    );

    let response = reqwest::get(&url)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to fetch DNS record from {}: {}", url, e))?;

    if !response.status().is_success() {
        return Err(anyhow::anyhow!(
            "DNS lookup failed with status {}: {}",
            response.status(),
            response.text().await.unwrap_or_default()
        ));
    }

    let data: serde_json::Value = response
        .json()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to parse DNS response as JSON: {}", e))?;

    Ok((data, from_domain))
}

/// Fetches the public key from DNS records using the DKIM signature in the email headers,
/// and verifies the public key.
///
/// # Arguments
///
/// * `parsed_email` - A `ParsedMail`.
///
/// # Returns
///
/// A `Result` containing a vector of bytes representing the valid public key, or an error if the key is not found.
pub async fn fetch_public_key_and_verify(
    parsed_email: ParsedMail<'_>,
    email_headers: EmailHeaders,
    check_body_hash: bool,
) -> Result<Vec<u8>> {
    let (data, domain) = fetch_public_keys(email_headers).await?;

    let p_values: Vec<String> = data
        .as_array()
        .ok_or_else(|| anyhow::anyhow!("API response is not an array"))?
        .iter()
        .filter_map(|record| record.get("value"))
        .filter_map(|value| value.as_str())
        .flat_map(|data| {
            data.split(';')
                .filter(|part| part.trim().starts_with("p="))
                .map(|part| part.trim()[2..].to_string())
        })
        .collect();

    if p_values.is_empty() {
        return Err(anyhow::anyhow!(
            "No public keys (p= values) found in DNS records"
        ));
    }

    let mut verification_errors = Vec::new();

    for (i, p_value) in p_values.iter().enumerate() {
        let dkim_public_key = match create_dkim_public_key(p_value) {
            Ok(key) => key,
            Err(e) => {
                verification_errors.push(format!(
                    "Key #{}: Invalid public key format: {}",
                    i + 1,
                    e
                ));
                continue;
            }
        };

        let logger = slog::Logger::root(slog::Discard, slog::o!());
        match verify_email_with_key(
            &logger,
            &domain,
            &parsed_email,
            dkim_public_key,
            check_body_hash,
        ) {
            Ok(_) => {
                let public_key_bytes = match general_purpose::STANDARD.decode(p_value) {
                    Ok(bytes) => bytes,
                    Err(e) => {
                        return Err(anyhow::anyhow!(
                            "Failed to decode verified public key: {}",
                            e
                        ));
                    }
                };

                let public_key = match rsa::RsaPublicKey::from_public_key_der(&public_key_bytes) {
                    Ok(key) => key,
                    Err(e) => {
                        return Err(anyhow::anyhow!(
                            "Failed to parse verified public key: {}",
                            e
                        ));
                    }
                };

                let modulus = public_key.n();
                let modulus_bytes: Vec<u8> = modulus.to_bytes_be();
                return Ok(modulus_bytes);
            }
            Err(e) => {
                verification_errors.push(format!("Key #{}: Verification failed: {}", i + 1, e));
            }
        }
    }

    Err(anyhow::anyhow!(
        "Failed to verify email with any public key: {}",
        verification_errors.join("; ")
    ))
}

fn create_dkim_public_key(public_key_b64: &str) -> Result<DkimPublicKey, DKIMError> {
    // Decode the base64 public key
    let public_key_der = general_purpose::STANDARD
        .decode(public_key_b64)
        .map_err(|e| DKIMError::SignatureSyntaxError(e.to_string()))?;

    // Try to parse as PKCS#8 first, fall back to PKCS#1 DER if needed
    let rsa_public_key = RsaPublicKey::from_public_key_der(&public_key_der)
        .or_else(|_| RsaPublicKey::from_pkcs1_der(&public_key_der))
        .map_err(|e| DKIMError::SignatureSyntaxError(e.to_string()))?;

    Ok(DkimPublicKey::Rsa(rsa_public_key))
}
