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

/// Represents different types of template values.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TemplateValue {
    /// A string value.
    String(String),
    /// An unsigned integer value.
    Uint(U256),
    /// A signed integer value.
    Int(I256),
    /// A decimal value represented as a string.
    Decimals(String),
    /// An Ethereum address.
    EthAddr(Address),
    /// A fixed value represented as a string.
    Fixed(String),
}

impl TemplateValue {
    /// Encodes the template value into ABI format.
    ///
    /// # Arguments
    ///
    /// * `decimal_size` - An optional value specifying the number of decimal places for Decimals type.
    ///
    /// # Returns
    ///
    /// A `Result` containing the encoded bytes or an error.
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

    /// Converts a decimal string to a U256 integer.
    ///
    /// # Arguments
    ///
    /// * `str` - The decimal string to convert.
    /// * `decimal_size` - The number of decimal places.
    ///
    /// # Returns
    ///
    /// A `U256` representing the decimal value.
    fn decimals_str_to_uint(str: &str, decimal_size: u8) -> U256 {
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

/// Extracts template values from a command input string.
///
/// # Arguments
///
/// * `input` - The input string to extract values from.
/// * `templates` - A vector of template strings.
///
/// # Returns
///
/// A `Result` containing a vector of `TemplateValue`s or an error.
pub fn extract_template_vals_from_command(
    mut input: &mut str,
    templates: Vec<String>,
) -> Result<Vec<TemplateValue>, anyhow::Error> {
    // Skip to text/html part
    let re = Regex::new(r"(?s)Content-Type:\s*text/html;").unwrap();
    if let Some(matched) = re.find(input) {
        let text_html_idx = matched.end();
        input = &mut input[text_html_idx..];
    }

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

/// Extracts template values from an input string.
///
/// # Arguments
///
/// * `input` - The input string to extract values from.
/// * `templates` - A vector of template strings.
///
/// # Returns
///
/// A `Result` containing a vector of `TemplateValue`s or an error.
fn extract_template_vals(input: &str, templates: Vec<String>) -> Result<Vec<TemplateValue>> {
    let input_decomposed: Vec<&str> = input.split_whitespace().collect();
    let mut template_vals = Vec::new();

    for (input_idx, template) in templates.iter().enumerate() {
        match template.as_str() {
            "{string}" => {
                // Extract and validate string value
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
                // Extract and validate unsigned integer value
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
                // Extract and validate signed integer value
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
                // Extract and validate decimal value
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
                // Extract and validate Ethereum address
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
