#![allow(clippy::upper_case_acronyms)]

use anyhow::{anyhow, Result};
use ethers::abi::{self, Token};
use ethers::types::{Address, Bytes, I256, U256};
use regex::Regex;
use serde::{Deserialize, Serialize};

const STRING_REGEX: &str = r"\S+";
const UINT_REGEX: &str = r"\d+";
const INT_REGEX: &str = r"-?\d+";
const ETH_ADDR_REGEX: &str = r"0x[a-fA-F0-9]{40}";
const DECIMALS_REGEX: &str = r"\d+\.\d+";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TemplateValue {
    String(String),
    Uint(U256),
    Int(I256),
    Decimals(String),
    EthAddr(Address),
    Fixed(String),
}

impl TemplateValue {
    pub fn abi_encode(&self, decimal_size: Option<u8>) -> Result<Bytes> {
        match self {
            Self::String(string) => Ok(Bytes::from(abi::encode(&[Token::String(string.clone())]))),
            Self::Uint(uint) => Ok(Bytes::from(abi::encode(&[Token::Uint(*uint)]))),
            Self::Int(int) => Ok(Bytes::from(abi::encode(&[Token::Int(int.into_raw())]))),
            Self::Decimals(string) => Ok(Bytes::from(abi::encode(&[Token::Uint(
                Self::decimals_str_to_uint(string, decimal_size.unwrap_or(18)),
            )]))),
            Self::EthAddr(address) => Ok(Bytes::from(abi::encode(&[Token::Address(*address)]))),
            Self::Fixed(_) => Err(anyhow!("Fixed value must not be passed to abi_encode")),
        }
    }

    pub fn decimals_str_to_uint(str: &str, decimal_size: u8) -> U256 {
        let decimal_size = decimal_size as usize;
        let dot = Regex::new("\\.").unwrap().find(str);
        let (before_dot_str, mut after_dot_str) = match dot {
            Some(dot_match) => (
                str[0..dot_match.start()].to_string(),
                str[dot_match.end()..].to_string(),
            ),
            None => (str.to_string(), "".to_string()),
        };
        assert!(after_dot_str.len() <= decimal_size);
        let num_leading_zeros = decimal_size - after_dot_str.len();
        after_dot_str.push_str(&"0".repeat(num_leading_zeros));
        U256::from_dec_str(&(before_dot_str + &after_dot_str))
            .expect("composed amount string is not valid decimal")
    }
}

pub fn extract_template_vals_from_command(
    input: &str,
    templates: Vec<String>,
) -> Result<Vec<TemplateValue>, anyhow::Error> {
    // Convert the template to a regex pattern, escaping necessary characters and replacing placeholders
    let pattern = templates
        .iter()
        .map(|template| match template.as_str() {
            "{string}" => STRING_REGEX.to_string(),
            "{uint}" => UINT_REGEX.to_string(),
            "{int}" => INT_REGEX.to_string(),
            "{decimals}" => DECIMALS_REGEX.to_string(),
            "{ethAddr}" => ETH_ADDR_REGEX.to_string(),
            _ => regex::escape(template),
        })
        .collect::<Vec<String>>()
        .join("\\s+");

    let regex = Regex::new(&pattern).map_err(|e| anyhow!("Regex compilation failed: {}", e))?;

    // Attempt to find the pattern in the input
    if let Some(matched) = regex.find(input) {
        // Calculate the number of bytes to skip before the match
        let skipped_bytes = matched.start();

        // Extract the values based on the matched pattern
        let current_input = &input[skipped_bytes..];
        extract_template_vals(current_input, templates)
    } else {
        // If there's no match, return an error indicating no match was found
        Err(anyhow!("Unable to match templates with input"))
    }
}

pub fn extract_template_vals(input: &str, templates: Vec<String>) -> Result<Vec<TemplateValue>> {
    let input_decomposed: Vec<&str> = input.split_whitespace().collect();
    let mut template_vals = Vec::new();

    for (input_idx, template) in templates.iter().enumerate() {
        match template.as_str() {
            "{string}" => {
                let string_match = Regex::new(STRING_REGEX)
                    .unwrap()
                    .find(input_decomposed[input_idx])
                    .ok_or(anyhow!("No string found"))?;
                if string_match.start() != 0 {
                    return Err(anyhow!("String must be the whole word"));
                }
                let mut string = string_match.as_str().to_string();
                if string.contains("</div>") {
                    string = string.split("</div>").collect::<Vec<&str>>()[0].to_string();
                }
                template_vals.push(TemplateValue::String(string));
            }
            "{uint}" => {
                let uint_match = Regex::new(UINT_REGEX)
                    .unwrap()
                    .find(input_decomposed[input_idx])
                    .ok_or(anyhow!("No uint found"))?;
                if uint_match.start() != 0 || uint_match.end() != input_decomposed[input_idx].len()
                {
                    return Err(anyhow!("Uint must be the whole word"));
                }
                let mut uint_match = uint_match.as_str();
                if uint_match.contains("</div>") {
                    uint_match = uint_match.split("</div>").collect::<Vec<&str>>()[0];
                }
                let uint = U256::from_dec_str(uint_match).unwrap();
                template_vals.push(TemplateValue::Uint(uint));
            }
            "{int}" => {
                let int_match = Regex::new(INT_REGEX)
                    .unwrap()
                    .find(input_decomposed[input_idx])
                    .ok_or(anyhow!("No int found"))?;
                if int_match.start() != 0 || int_match.end() != input_decomposed[input_idx].len() {
                    return Err(anyhow!("Int must be the whole word"));
                }
                let mut int_match = int_match.as_str();
                if int_match.contains("</div>") {
                    int_match = int_match.split("</div>").collect::<Vec<&str>>()[0];
                }
                let int = I256::from_dec_str(int_match).unwrap();
                template_vals.push(TemplateValue::Int(int));
            }
            "{decimals}" => {
                let decimals_match = Regex::new(DECIMALS_REGEX)
                    .unwrap()
                    .find(input_decomposed[input_idx])
                    .ok_or(anyhow!("No decimals found"))?;
                if decimals_match.start() != 0
                    || decimals_match.end() != input_decomposed[input_idx].len()
                {
                    return Err(anyhow!("Decimals must be the whole word"));
                }
                let mut decimals = decimals_match.as_str().to_string();
                if decimals.contains("</div>") {
                    decimals = decimals.split("</div>").collect::<Vec<&str>>()[0].to_string();
                }
                template_vals.push(TemplateValue::Decimals(decimals));
            }
            "{ethAddr}" => {
                let address_match = Regex::new(ETH_ADDR_REGEX)
                    .unwrap()
                    .find(input_decomposed[input_idx])
                    .ok_or(anyhow!("No address found"))?;
                if address_match.start() != 0 {
                    return Err(anyhow!("Address must be the whole word"));
                }
                let address = address_match.as_str().parse::<Address>().unwrap();
                template_vals.push(TemplateValue::EthAddr(address));
            }
            _ => {} // Skip unknown placeholders
        }
    }

    Ok(template_vals)
}

// Generated by Github Copilot!
pub fn uint_to_decimal_string(uint: u128, decimal: usize) -> String {
    // Convert amount to string in wei format (no decimals)
    let uint_str = uint.to_string();
    let uint_length = uint_str.len();

    // Create result vector with max length
    // If less than 18 decimals, then 2 extra for "0.", otherwise one extra for "."
    let mut result = vec![
        '0';
        if uint_length > decimal {
            uint_length + 1
        } else {
            decimal + 2
        }
    ];
    let result_length = result.len();

    // Difference between result and amount array index when copying
    // If more than 18, then 1 index diff for ".", otherwise actual diff in length
    let mut delta = if uint_length > decimal {
        1
    } else {
        result_length - uint_length
    };

    // Boolean to indicate if we found a non-zero digit when scanning from last to first index
    let mut found_non_zero_decimal = false;

    let mut actual_result_len = 0;

    // In each iteration we fill one index of result array (starting from end)
    for i in (0..result_length).rev() {
        // Check if we have reached the index where we need to add decimal point
        if i == result_length - decimal - 1 {
            // No need to add "." if there was no value in decimal places
            if found_non_zero_decimal {
                result[i] = '.';
                actual_result_len += 1;
            }
            // Set delta to 0, as we have already added decimal point (only for amount_length > 18)
            delta = 0;
        }
        // If amountLength < 18 and we have copied everything, fill zeros
        else if uint_length <= decimal && i < result_length - uint_length {
            result[i] = '0';
            actual_result_len += 1;
        }
        // If non-zero decimal is found, or decimal point inserted (delta == 0), copy from amount array
        else if found_non_zero_decimal || delta == 0 {
            result[i] = uint_str.chars().nth(i - delta).unwrap();
            actual_result_len += 1;
        }
        // If we find non-zero decimal for the first time (trailing zeros are skipped)
        else if uint_str.chars().nth(i - delta).unwrap() != '0' {
            result[i] = uint_str.chars().nth(i - delta).unwrap();
            actual_result_len += 1;
            found_non_zero_decimal = true;
        }
    }

    // Create final result string with correct length
    let compact_result: String = result.into_iter().take(actual_result_len).collect();

    compact_result
}
