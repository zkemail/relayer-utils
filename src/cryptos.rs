//! Cryptographic functions.

use crate::{field_to_hex, hex_to_field};
use ethers::types::Bytes;
use halo2curves::ff::Field;
use poseidon_rs::{poseidon_bytes, poseidon_fields, Fr, PoseidonError};
use rand_core::RngCore;
use serde::{
    de::{self, Visitor},
    Deserialize, Deserializer,
};
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

#[derive(Debug, Clone)]
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
    };

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
    use crate::field_to_hex;

    use super::*;

    #[test]
    fn test_public_key_hash() {
        let mut public_key_n = hex::decode("cfb0520e4ad78c4adb0deb5e605162b6469349fc1fde9269b88d596ed9f3735c00c592317c982320874b987bcc38e8556ac544bdee169b66ae8fe639828ff5afb4f199017e3d8e675a077f21cd9e5c526c1866476e7ba74cd7bb16a1c3d93bc7bb1d576aedb4307c6b948d5b8c29f79307788d7a8ebf84585bf53994827c23a5").unwrap();
        public_key_n.reverse();
        let hash_field = public_key_hash(&public_key_n).unwrap();
        let expected_hash = format!(
            "0x{}",
            hex::encode([
                24, 26, 185, 80, 217, 115, 238, 83, 131, 133, 50, 236, 177, 184, 177, 21, 40, 246,
                234, 122, 176, 142, 40, 104, 251, 50, 24, 70, 64, 82, 249, 83
            ])
        );
        assert_eq!(field_to_hex(&hash_field), expected_hash);
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
