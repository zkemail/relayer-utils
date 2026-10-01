use anyhow::{anyhow, Ok, Result};
use num_bigint::BigInt;
use num_traits::Num;
use regex::Regex;

use super::structs::Sequence;
use crate::dkim::header_field_spans;

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
/// The field name must start a header field (ASCII case-insensitive). For "dkim-signature"
/// the LAST such field is used, since the signature being verified is appended last to the
/// canonicalized header; for other fields the first. The sequence covers the field up to, not
/// including, its terminating CRLF, which is what zkemail.nr's `constrain_header_field`
/// checks (the byte at the end index must be CR unless the field ends the header).
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
    let header_str =
        std::str::from_utf8(header).map_err(|e| anyhow!("Invalid UTF-8 in header: {}", e))?;
    if header_field.is_empty() {
        return Err(anyhow!("Empty header field name"));
    }
    let spans = header_field_spans(header_str, header_field);
    let span = if header_field.eq_ignore_ascii_case("dkim-signature") {
        spans.last()
    } else {
        spans.first()
    }
    .ok_or_else(|| anyhow!("Field \"{}\" not found in header", header_field))?;
    Ok(Sequence {
        index: span.start,
        length: span.end - span.start,
    })
}

/// Gets the index and length of both a header field and the email address within it.
///
/// The field must start a header field (so "to" does not match "in-reply-to:"). The address
/// is the content of the LAST `<...>` in the field, matching zkemail.nr, which locates the
/// address after the last '<'; without angle brackets, the first address-like token.
///
/// # Arguments
/// * `header` - The header bytes to search
/// * `header_field` - The field name to search for (e.g., "from", "to")
///
/// # Returns
/// * A Result containing an array of two Sequence structs:
///   - First element: header field position information (up to, not including, its CRLF)
///   - Second element: email address position information
///
/// # Errors
/// * If the header field is not found
/// * If no email address is found in the field
/// * If the header contains invalid UTF-8
pub fn get_address_header_sequence(header: &[u8], header_field: &str) -> Result<[Sequence; 2]> {
    let header_str =
        std::str::from_utf8(header).map_err(|e| anyhow!("Invalid UTF-8 in header: {}", e))?;
    let span = *header_field_spans(header_str, header_field)
        .first()
        .ok_or_else(|| anyhow!("Field \"{}\" not found in header", header_field))?;
    let value = &header_str[span.value_start..span.end];

    let (addr_start, addr_len) = match value.rfind('<') {
        Some(lt) => {
            let rest = &value[lt + 1..];
            let gt = rest
                .find('>')
                .ok_or_else(|| anyhow!("Address not found in \"{}\" field", header_field))?;
            (span.value_start + lt + 1, gt)
        }
        None => {
            let re = Regex::new(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}")
                .map_err(|e| anyhow!("Invalid regex pattern: {}", e))?;
            let m = re
                .find(value)
                .ok_or_else(|| anyhow!("Address not found in \"{}\" field", header_field))?;
            (span.value_start + m.start(), m.end() - m.start())
        }
    };
    if addr_len == 0 {
        return Err(anyhow!("Address not found in \"{}\" field", header_field));
    }

    Ok([
        Sequence {
            index: span.start,
            length: span.end - span.start,
        },
        Sequence {
            index: addr_start,
            length: addr_len,
        },
    ])
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

#[cfg(test)]
mod tests {
    use super::*;

    const HEADER: &str = "in-reply-to:<id@mail.example>\r\nfrom:\"x@esp.example\" <alice@bank.example>\r\nsubject:dkim-signature: from: to: bh=1;\r\nto:Bob <bob@c.example>\r\ndkim-signature:v=1; d=bank.example; s=s1; bh=AAA=; b=";

    fn text(seq: &Sequence) -> &'static str {
        &HEADER[seq.index..seq.index + seq.length]
    }

    #[test]
    fn dkim_signature_sequence_is_the_last_field_start() {
        let seq = get_header_sequence(HEADER.as_bytes(), "dkim-signature").unwrap();
        assert!(text(&seq).starts_with("dkim-signature:v=1; d=bank.example"));
        assert_eq!(seq.index + seq.length, HEADER.len());
        // c=simple keeps the original case of the name
        let simple = HEADER.replace("\r\ndkim-signature:", "\r\nDKIM-Signature:");
        let simple_seq = get_header_sequence(simple.as_bytes(), "dkim-signature").unwrap();
        assert_eq!((simple_seq.index, simple_seq.length), (seq.index, seq.length));
    }

    #[test]
    fn field_sequence_excludes_crlf_and_address_is_last_angle_addr() {
        let [field, addr] = get_address_header_sequence(HEADER.as_bytes(), "from").unwrap();
        assert_eq!(text(&field), "from:\"x@esp.example\" <alice@bank.example>");
        assert_eq!(&HEADER[field.index + field.length..][..2], "\r\n");
        assert_eq!(text(&addr), "alice@bank.example");

        // "to" must not match in-reply-to: or text inside the subject
        let [field, addr] = get_address_header_sequence(HEADER.as_bytes(), "to").unwrap();
        assert_eq!(text(&field), "to:Bob <bob@c.example>");
        assert_eq!(text(&addr), "bob@c.example");

        let bare = "from:alice@bank.example\r\nsubject:x";
        let [field, addr] = get_address_header_sequence(bare.as_bytes(), "from").unwrap();
        assert_eq!(&bare[field.index..field.index + field.length], "from:alice@bank.example");
        assert_eq!(&bare[addr.index..addr.index + addr.length], "alice@bank.example");
    }
}
