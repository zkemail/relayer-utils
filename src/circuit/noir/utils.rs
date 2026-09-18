use anyhow::{anyhow, Ok, Result};
use num_bigint::BigInt;
use num_traits::Num;
use regex::Regex;

use super::structs::Sequence;

/// Computes the Barrett reduction parameter used in Barrett reduction.
///
/// # Arguments
///
/// * `input` - The input big integer as a reference
/// * `num_bits` - Optional number of bits in the input
///
/// # Returns
///
/// The Barrett reduction parameter as a BigInt
pub fn compute_barrett_reduction_parameter(input: &BigInt, num_bits: Option<usize>) -> BigInt {
    // Determine the bit length if not provided
    let bits = match num_bits {
        Some(bits) => {
            let actual_bits = input.bits() as usize;
            if actual_bits > bits {
                panic!("Given bits for bignum limbs is too small");
            }
            bits
        }
        None => input.bits() as usize,
    };

    // Compute overflow bits
    let overflow_bits = 4;

    // multiplicand = 2^(2 * k + overflow_bits)
    let multiplicand = BigInt::from(1) << (2 * bits + overflow_bits);

    // Compute the Barrett reduction parameter
    multiplicand / input
}

/// Splits a BigInt into an array of 120-bit slices.
///
/// # Arguments
///
/// * `input` - The input big integer to be split
/// * `num_bits` - The number of bits in the input
///
/// # Returns
///
/// A vector of BigInt, each representing a 120-bit slice
pub fn split_into_120bit_limbs(mut input: BigInt, num_bits: usize) -> Vec<BigInt> {
    const LIMB_BITS: usize = 120;
    let num_limbs = (num_bits + LIMB_BITS - 1) / LIMB_BITS; // ceiling division
    let mask = (BigInt::from(1) << LIMB_BITS) - 1;

    let mut limbs = Vec::with_capacity(num_limbs);
    for _ in 0..num_limbs {
        let slice = &input & &mask;
        input >>= LIMB_BITS;
        limbs.push(slice);
    }

    limbs
}

/// Converts a hex string to a BigInt.
///
/// # Arguments
///
/// * `hex_str` - A hex string, with or without '0x' prefix
///
/// # Returns
///
/// A Result containing the BigInt or an error
fn hex_to_bigint(hex_str: &str) -> Result<BigInt> {
    let clean_hex = if hex_str.to_lowercase().starts_with("0x") {
        &hex_str[2..]
    } else {
        hex_str
    };

    // Validate hex string
    if !clean_hex.chars().all(|c| c.is_digit(16)) {
        return Err(anyhow::anyhow!("Invalid hexadecimal string"));
    }

    BigInt::from_str_radix(clean_hex, 16)
        .map_err(|e| anyhow::anyhow!("Failed to parse hex string: {}", e))
}

/// Converts a BigInt to a vector of hexadecimal strings, each representing a 120-bit limb.
///
/// # Arguments
///
/// * `input` - The input as either a BigInt reference or a hex string
/// * `num_bits` - Optional number of bits in the input
///
/// # Returns
///
/// A Result containing a vector of strings, each representing a 120-bit limb in "0x..." format
pub fn bn_to_limb_str_array(input: &BigInt, num_bits: Option<usize>) -> Vec<String> {
    // Determine the bit length if not provided
    let bits = match num_bits {
        Some(bits) => {
            let actual_bits = input.bits() as usize;
            if actual_bits > bits {
                panic!("Given bits for bignum limbs is too small");
            }
            bits
        }
        None => input.bits() as usize,
    };

    // Split into 120-bit limbs
    let limbs = split_into_120bit_limbs(input.clone(), bits);

    // Convert each limb to a "0x..." hexadecimal string
    limbs
        .into_iter()
        .map(|limb| {
            // Get the hex representation without the "0x" prefix
            let hex_string = format!("{:x}", limb);

            // Ensure even length for the hex string
            let padded_hex = if hex_string.len() % 2 != 0 {
                format!("0{}", hex_string)
            } else {
                hex_string
            };

            format!("0x{}", padded_hex)
        })
        .collect()
}

/// Converts a hex string to a BigInt and then to limb strings.
///
/// # Arguments
///
/// * `hex_str` - A hex string
/// * `num_bits` - Optional number of bits
///
/// # Returns
///
/// A Result containing a vector of limb strings
pub fn hex_str_to_limb_str_array(hex_str: &str, num_bits: Option<usize>) -> Result<Vec<String>> {
    let bn = hex_to_bigint(hex_str)?;
    Ok(bn_to_limb_str_array(&bn, num_bits))
}

/// Compute the Barrett reduction parameter and convert it to an array of 120-bit limbs.
///
/// # Arguments
///
/// * `input` - The input as either a BigInt reference
/// * `num_bits` - Optional number of bits in the input
///
/// # Returns
///
/// A vector of strings, each representing a 120-bit limb in "0x..." format
pub fn bn_to_redc_limb_str_array(input: &BigInt, num_bits: Option<usize>) -> Vec<String> {
    let redc = compute_barrett_reduction_parameter(input, num_bits);
    bn_to_limb_str_array(&redc, None)
}

/// Compute the Barrett reduction parameter from hex string and convert it to limb strings.
///
/// # Arguments
///
/// * `hex_str` - A hex string
/// * `num_bits` - Optional number of bits
///
/// # Returns
///
/// A Result containing a vector of limb strings for the reduction parameter
pub fn hex_str_to_redc_limb_str_array(
    hex_str: &str,
    num_bits: Option<usize>,
) -> Result<Vec<String>> {
    let bn = hex_to_bigint(hex_str)?;
    let limbs = bn_to_redc_limb_str_array(&bn, num_bits);
    Ok(limbs)
}

/// Get the index and length of a header field.
///
/// # Arguments
///
/// * `header` - The header bytes to search for the field in
/// * `header_field` - The field name to search for
///
/// # Returns
///
/// A Sequence containing the index and length of the field
pub fn get_header_sequence(header: &[u8], header_field: &str) -> Result<Sequence> {
    // Convert header to string
    let header_str =
        std::str::from_utf8(header).map_err(|e| anyhow!("Invalid UTF-8 in header: {}", e))?;

    // Create regex pattern matching the TS implementation
    let first_char = header_field
        .chars()
        .next()
        .ok_or_else(|| anyhow!("Empty header field name"))?;

    let first_upper = first_char.to_uppercase().collect::<String>();
    let first_lower = first_char.to_lowercase().collect::<String>();

    let pattern = format!(
        r"[{}{}]{}:.*(?:\r?\n)?",
        first_upper,
        first_lower,
        &header_field[first_char.len_utf8()..].to_lowercase()
    );

    let regex = Regex::new(&pattern).map_err(|e| anyhow!("Invalid regex pattern: {}", e))?;

    // Find the match
    let captures = regex
        .find(header_str)
        .ok_or_else(|| anyhow!("Field \"{}\" not found in header", header_field))?;

    // Return the index and length matching TS implementation
    Ok(Sequence {
        index: captures.start(),
        length: captures.end() - captures.start(),
    })
}

/// Gets the index and length of both a header field and the email address within it.
///
/// This function extracts sequence information for email header fields (like 'From', 'To')
/// and the email address contained within them.
///
/// # Arguments
/// * `header` - The header bytes to search
/// * `header_field` - The field name to search for (e.g., "from", "to")
///
/// # Returns
/// * A Result containing an array of two Sequence structs:
///   - First element: header field position information
///   - Second element: email address position information
///
/// # Errors
/// * If the header field is not found
/// * If no email address is found in the field
/// * If the header contains invalid UTF-8
pub fn get_address_header_sequence(header: &[u8], header_field: &str) -> Result<[Sequence; 2]> {
    // Convert header to string
    let header_str =
        std::str::from_utf8(header).map_err(|e| anyhow!("Invalid UTF-8 in header: {}", e))?;

    // Create case-insensitive regex pattern for the header field and email address
    let regex_prefix = regex::escape(header_field);
    let pattern = format!(
        r"(?i){}:.*?<([^>]+)>|(?i){}:.*?([a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{{2,}})",
        regex_prefix, regex_prefix
    );

    let regex = Regex::new(&pattern).map_err(|e| anyhow!("Invalid regex pattern: {}", e))?;

    // Find the match
    let captures = regex
        .captures(header_str)
        .ok_or_else(|| anyhow!("Field \"{}\" not found in header", header_field))?;

    // Get the overall match
    let full_match = captures
        .get(0)
        .ok_or_else(|| anyhow!("Unexpected regex match structure"))?;

    // Get the email address from either the first or second capture group
    let address = captures
        .get(1)
        .or_else(|| captures.get(2))
        .ok_or_else(|| anyhow!("Address not found in \"{}\" field", header_field))?;

    // Create the return value
    let field_sequence = Sequence {
        index: full_match.start(),
        length: full_match.end() - full_match.start(),
    };

    let address_sequence = Sequence {
        index: address.start(),
        length: address.end() - address.start(),
    };

    Ok([field_sequence, address_sequence])
}

/// Transforms a u8 array to a u32 array in big-endian format.
///
/// This function takes a slice of bytes and converts them to a vector of u32 values,
/// where each u32 is constructed from 4 bytes in big-endian format.
///
/// # Arguments
///
/// * `input` - A slice of bytes to convert
///
/// # Returns
///
/// A Result containing either a vector of u32 values or an error
pub fn u8_to_u32(input: &[u8]) -> Result<Vec<u32>> {
    if input.len() % 4 != 0 {
        return Err(anyhow!("Input length must be a multiple of 4"));
    }

    let mut output = Vec::with_capacity(input.len() / 4);

    for chunk in input.chunks(4) {
        let value = u32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
        output.push(value);
    }

    Ok(output)
}

pub fn trim_sha256_padding(data: &[u8]) -> &[u8] {
    // SHA256 padding starts with 0x80 byte followed by zeros
    // Find the last 0x80 byte (padding marker)
    if let Some(padding_start) = data.iter().rposition(|&b| b == 0x80) {
        // Check if everything after 0x80 is zeros or length encoding
        let after_padding = &data[padding_start + 1..];

        // If we find 0x80 and it's followed by zeros/length, return data before padding
        if after_padding.iter().rev().take(8).all(|&b| b != 0x80) {
            return &data[..padding_start];
        }
    }

    // Fallback: find the last non-zero byte that isn't part of length encoding
    // SHA256 padding ends with 8-byte length, so check if last 8 bytes look like length
    if data.len() >= 8 {
        let (content, potential_length) = data.split_at(data.len() - 8);
        // If last 8 bytes represent a reasonable length, trim from there
        if let Some(last_nonzero) = content.iter().rposition(|&b| b != 0) {
            if content[last_nonzero] == 0x80 {
                return &content[..last_nonzero];
            }
        }
    }

    // Ultimate fallback: trim trailing zeros
    if let Some(last_nonzero) = data.iter().rposition(|&b| b != 0) {
        &data[..=last_nonzero]
    } else {
        data
    }
}
