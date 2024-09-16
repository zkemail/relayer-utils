//! This module provides utility functions for converting between different data types and formats.

use anyhow::{anyhow, Result};
use ethers::types::U256;
use halo2curves::ff::PrimeField;
use itertools::Itertools;
use num_bigint::BigInt;
use poseidon_rs::Fr;
use std::convert::TryInto;

use crate::{CIRCOM_BIGINT_K, CIRCOM_BIGINT_N};

/// Converts a hexadecimal string to a `Fr` field element.
///
/// # Arguments
/// * `input_hex` - Hexadecimal string with "0x" prefix.
///
/// # Returns
/// `Result<Fr, anyhow::Error>` - The field element on success, or an error on failure.
pub fn hex_to_field(input_hex: &str) -> Result<Fr> {
    // Check if the input string starts with "0x", which indicates a hex string
    if &input_hex[0..2] != "0x" {
        return Err(anyhow!(format!(
            "the input string {} must be hex string with 0x prefix",
            &input_hex
        )));
    }

    // Attempt to decode the hex string, skipping the "0x" prefix
    let mut bytes = match hex::decode(&input_hex[2..]) {
        Ok(bytes) => bytes,
        Err(e) => {
            // Return an error if the string is not a valid hex
            return Err(anyhow!(format!(
                "the input string {} is invalid hex: {}",
                &input_hex, e
            )));
        }
    };

    // Reverse the bytes because Ethereum stores values in big-endian
    bytes.reverse();

    // Ensure the decoded bytes are exactly 32 bytes long
    if bytes.len() != 32 {
        return Err(anyhow!(format!(
            "the input string {} must be 32 bytes but is {} bytes",
            &input_hex,
            bytes.len()
        )));
    }

    // Convert the vector of bytes into an array of 32 bytes
    let bytes: [u8; 32] = match bytes.try_into() {
        Ok(bytes) => bytes,
        Err(e) => {
            // Return an error if the conversion fails
            return Err(anyhow!(format!("the bytes {:?} is not valid 32 bytes", e)));
        }
    };

    // Convert the array of bytes into a field element
    let field = Fr::from_bytes(&bytes).expect("fail to convert bytes to a field value");

    // Return the field element
    Ok(field)
}

/// Converts a field element to a hexadecimal string.
///
/// # Arguments
/// * `field` - A reference to the field element.
///
/// # Returns
/// A hexadecimal string representation of the field.
pub fn field_to_hex(field: &Fr) -> String {
    // Utilize the Debug trait to format the field element
    format!("{:?}", field)
}

// pub fn digits2int(input_digits: &str) -> Result<u64> {
//     Ok(input_digits.parse()?)
// }

/// Converts a byte slice into a vector of `Fr` field elements.
///
/// Each chunk of 31 bytes from the input is extended to 32 bytes and converted to an `Fr` element.
/// The conversion assumes little-endian byte order.
///
/// # Arguments
/// * `bytes` - A byte slice to convert.
///
/// # Returns
/// A vector of `Fr` field elements.
pub fn bytes_to_fields(bytes: &[u8]) -> Vec<Fr> {
    bytes
        .chunks(31)
        .map(|chunk| {
            let mut extended = [0u8; 32];
            extended[..chunk.len()].copy_from_slice(chunk);
            Fr::from_bytes(&extended).expect("fail to convert bytes to a field value")
        })
        .collect()
}

/// Converts a byte slice into a vector of `Fr` field elements, chunked by bit size.
///
/// The input bytes are first ensured to be of the maximum size by padding with zeros if necessary.
/// Then, each byte is split into bits, and chunks of bits are combined into words. These words
/// are then grouped into field elements.
///
/// # Arguments
/// * `bytes` - A byte slice to convert.
/// * `chunk_bit_size` - The size of each chunk in bits.
/// * `num_chunk_in_field` - The number of chunks to combine into a single field element.
/// * `max_chunk_size` - The maximum size of a chunk.
///
/// # Returns
/// A vector of `Fr` field elements.
pub fn bytes_chunk_fields(
    bytes: &[u8],
    chunk_bit_size: usize,
    num_chunk_in_field: usize,
    max_chunk_size: usize,
) -> Vec<Fr> {
    let max_bytes_size = max_chunk_size * chunk_bit_size / 8;
    let mut bytes = bytes.to_vec();
    // Ensure the bytes vector is of the maximum size, padding with zeros if necessary
    if bytes.len() < max_bytes_size {
        bytes.resize(max_bytes_size, 0);
    }
    // Convert bytes to bits
    let bits = bytes
        .iter()
        .flat_map(|byte| (0..8).map(move |i| (byte >> i) & 1))
        .collect_vec();

    // Combine bits into words and then into field elements
    let words = bits
        .chunks(chunk_bit_size)
        .map(|chunk| {
            chunk
                .iter()
                .enumerate()
                .fold(Fr::zero(), |mut word, (i, &bit)| {
                    if bit == 1 {
                        word += Fr::from_u128(1u128 << i);
                    }
                    word
                })
        })
        .collect_vec();

    // Group words into field elements
    words
        .chunks(num_chunk_in_field)
        .map(|chunk| {
            chunk
                .iter()
                .enumerate()
                .fold((Fr::zero(), Fr::one()), |(mut input, coeff), (_, &word)| {
                    input += coeff * word;
                    (input, coeff * Fr::from_u128(1u128 << chunk_bit_size))
                })
                .0
        })
        .collect_vec()
}

/// Converts a 64-bit integer to an array of 8 bytes in big-endian format.
///
/// # Arguments
/// * `num` - The 64-bit integer to convert.
///
/// # Returns
/// A `Vec<u8>` representing the big-endian byte order of the integer.
pub fn int64_to_bytes(num: u64) -> Vec<u8> {
    num.to_be_bytes().to_vec()
}

/// Converts an 8-bit integer to a `Vec<u8>` with a single element.
///
/// # Arguments
/// * `num` - The 8-bit integer to convert.
///
/// # Returns
/// A `Vec<u8>` containing the input byte.
pub fn int8_to_bytes(num: u8) -> Vec<u8> {
    vec![num]
}

/// Merges two `Vec<u8>` into a single `Vec<u8>`.
///
/// # Arguments
/// * `a` - The first vector of bytes to merge.
/// * `b` - The second vector of bytes to merge.
///
/// # Returns
/// A `Vec<u8>` containing all the elements of `a` followed by all the elements of `b`.
pub fn merge_u8_arrays(a: Vec<u8>, b: Vec<u8>) -> Vec<u8> {
    [a, b].concat()
}

/// Divides a `BigInt` into chunks and converts to decimal strings.
///
/// # Arguments
/// * `num` - The `BigInt` to be divided.
/// * `bits_per_chunk` - Size of each chunk in bits.
/// * `num_chunks` - Number of chunks required.
///
/// # Returns
/// Vector of decimal strings representing each chunk.
fn big_int_to_chunked_bytes(num: BigInt, bits_per_chunk: usize, num_chunks: usize) -> Vec<String> {
    let mut chunks = Vec::new();
    let mut remainder = num;
    let chunk_size = BigInt::from(2).pow(bits_per_chunk as u32); // Calculate chunk size

    for _ in 0..num_chunks {
        let chunk = &remainder % &chunk_size; // Extract chunk
        remainder >>= bits_per_chunk; // Shift for next chunk
        chunks.push(chunk.to_string()); // Convert to string and push to vector
    }

    chunks
}

/// Converts a `BigInt` to a vector of strings formatted for Circom compatibility.
///
/// This function uses predefined constants for chunk size and number of chunks.
///
/// # Arguments
/// * `num` - The `BigInt` to convert.
///
/// # Returns
/// A vector of strings, each representing a chunk of the `BigInt`.
pub fn to_circom_bigint_bytes(num: BigInt) -> Vec<String> {
    big_int_to_chunked_bytes(num, CIRCOM_BIGINT_N, CIRCOM_BIGINT_K)
}

/// Converts a vector of u8 to a `BigInt`.
///
/// # Arguments
/// * `bytes` - The vector of u8 to convert.
///
/// # Returns
/// A `BigInt` representation of the input bytes.
pub fn vec_u8_to_bigint(bytes: Vec<u8>) -> BigInt {
    bytes
        .iter()
        .fold(BigInt::from(0), |acc, &b| (acc << 8) | BigInt::from(b))
}

/// Converts a `U256` to a 32-byte array in big-endian format.
///
/// # Arguments
/// * `x` - The `U256` value to convert.
///
/// # Returns
/// A 32-byte array representing the `U256` value.
pub fn u256_to_bytes32(x: &U256) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    x.to_big_endian(&mut bytes);
    bytes
}

/// Converts a `U256` to a hexadecimal string with "0x" prefix.
///
/// # Arguments
/// * `x` - The `U256` value to convert.
///
/// # Returns
/// A hexadecimal string representing the `U256` value.
pub fn u256_to_hex(x: &U256) -> String {
    "0x".to_string() + &hex::encode(u256_to_bytes32(x))
}

/// Converts a hexadecimal string to a `U256`.
///
/// # Arguments
/// * `hex` - The hexadecimal string to convert, with "0x" prefix.
///
/// # Returns
/// `Result<U256, hex::FromHexError>` - The `U256` on success, or an error on failure.
pub fn hex_to_u256(hex: &str) -> Result<U256, hex::FromHexError> {
    let bytes: Vec<u8> = hex::decode(&hex[2..])?;
    let mut array = [0u8; 32];
    array.copy_from_slice(&bytes);
    Ok(U256::from_big_endian(&array))
}

/// Converts a field element `Fr` to a 32-byte array.
///
/// # Arguments
/// * `fr` - A reference to the field element.
///
/// # Returns
/// `Result<[u8; 32], hex::FromHexError>` - The 32-byte array on success, or an error on failure.
pub fn fr_to_bytes32(fr: &Fr) -> Result<[u8; 32], hex::FromHexError> {
    let hex = field_to_hex(fr);
    let bytes = hex::decode(&hex[2..])?;
    let mut result = [0u8; 32];
    result.copy_from_slice(&bytes);
    Ok(result)
}

/// Converts a 32-byte array to a field element `Fr`.
///
/// # Arguments
/// * `bytes32` - A reference to the 32-byte array.
///
/// # Returns
/// `Result<Fr, hex::FromHexError>` - The field element on success, or an error on failure.
pub fn bytes32_to_fr(bytes32: &[u8; 32]) -> Result<Fr, hex::FromHexError> {
    let hex: String = "0x".to_string() + &hex::encode(bytes32);
    hex_to_field(&hex).map_err(|_e| hex::FromHexError::InvalidStringLength)
}

/// Converts a 64-bit integer to a 32-byte array.
///
/// # Arguments
/// * `value` - The 64-bit integer.
///
/// # Returns
/// A 32-byte array with the integer in big-endian format.
pub fn u64_to_u8_array_32(value: u64) -> [u8; 32] {
    let mut array = [0u8; 32];
    array[..8].copy_from_slice(&value.to_be_bytes());
    array
}

/// Converts a 32-byte array to a hexadecimal string with "0x" prefix.
///
/// # Arguments
/// * `bytes` - A reference to the 32-byte array.
///
/// # Returns
/// A hexadecimal string representing the bytes.
pub fn bytes32_to_hex(bytes: &[u8; 32]) -> String {
    "0x".to_string() + &hex::encode(bytes)
}

/// Converts a `U256` to a 32-byte array in little-endian format.
///
/// # Arguments
/// * `x` - A reference to the `U256` value.
///
/// # Returns
/// A 32-byte array representing the `U256` value in little-endian format.
pub fn u256_to_bytes32_little(x: &U256) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    x.to_little_endian(&mut bytes);
    bytes
}
