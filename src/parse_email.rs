//! This module contains the `ParsedEmail` struct and its implementation.

use std::collections::HashMap;

#[cfg(target_arch = "wasm32")]
use crate::cryptos::fetch_public_key;
use anyhow::{anyhow, Result};
use cfdkim::canonicalize_signed_email;
#[cfg(not(target_arch = "wasm32"))]
use cfdkim::resolve_public_key;
use hex;
use itertools::Itertools;
use mailparse::{parse_mail, ParsedMail};
#[cfg(target_arch = "wasm32")]
use regex::Regex;
use rsa::traits::PublicKeyParts;
use serde::{Deserialize, Serialize};
use zk_regex_apis::extract_substrs::{
    extract_body_hash_idxes, extract_email_addr_idxes, extract_email_domain_idxes,
    extract_from_addr_idxes, extract_message_id_idxes, extract_subject_all_idxes,
    extract_substr_idxes, extract_timestamp_idxes, extract_to_addr_idxes,
};

/// `ParsedEmail` holds the canonicalized parts of an email along with its signature and public key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParsedEmail {
    /// The canonicalized email header.
    pub canonicalized_header: String,
    /// The canonicalized email body.
    pub canonicalized_body: String,
    /// The email signature bytes.
    pub signature: Vec<u8>,
    /// The public key bytes associated with the email.
    pub public_key: Vec<u8>,
    /// The cleaned email body.
    pub cleaned_body: String,
    /// The email headers.
    pub headers: EmailHeaders,
}

impl ParsedEmail {
    /// Creates a new `ParsedEmail` from a raw email string.
    ///
    /// This function parses the raw email, extracts and canonicalizes the header and body,
    /// and retrieves the signature and public key.
    ///
    /// # Arguments
    ///
    /// * `raw_email` - A string slice representing the raw email to be parsed.
    ///
    /// # Returns
    ///
    /// A `Result` which is either a `ParsedEmail` instance or an error if parsing fails.
    pub async fn new_from_raw_email(raw_email: &str) -> Result<Self> {
        // Initialize a logger for the function scope.
        let logger = slog::Logger::root(slog::Discard, slog::o!());

        // Extract all headers
        let parsed_mail = parse_mail(raw_email.as_bytes())?;
        let headers: EmailHeaders = EmailHeaders::new_from_mail(&parsed_mail);

        // Resolve the public key from the raw email bytes.
        #[cfg(not(target_arch = "wasm32"))]
        let public_key = match resolve_public_key(&logger, raw_email.as_bytes()).await? {
            cfdkim::DkimPublicKey::Rsa(pk) => Ok(pk.n().to_bytes_be()),
            _ => Err(anyhow!("Unsupported public key type.")),
        }?;

        #[cfg(target_arch = "wasm32")]
        let public_key = fetch_public_key(headers.clone()).await?;

        // Canonicalize the signed email to separate the header, body, and signature.
        let (canonicalized_header, canonicalized_body, signature_bytes) =
            canonicalize_signed_email(raw_email.as_bytes())?;

        // Construct the `ParsedEmail` instance.
        let parsed_email = ParsedEmail {
            canonicalized_header: String::from_utf8(canonicalized_header)?, // Convert bytes to string, may return an error if not valid UTF-8.
            canonicalized_body: String::from_utf8(canonicalized_body.clone())?, // Convert bytes to string, may return an error if not valid UTF-8.
            signature: signature_bytes.into_iter().collect_vec(), // Collect the signature bytes into a vector.
            public_key,
            cleaned_body: String::from_utf8(remove_quoted_printable_soft_breaks(
                canonicalized_body,
            ))?, // Remove quoted-printable soft breaks from the canonicalized body.
            headers,
        };

        Ok(parsed_email)
    }

    /// Converts the signature bytes to a hex string with a "0x" prefix.
    pub fn signature_string(&self) -> String {
        "0x".to_string() + hex::encode(&self.signature).as_str()
    }

    /// Converts the public key bytes to a hex string with a "0x" prefix.
    pub fn public_key_string(&self) -> String {
        "0x".to_string() + hex::encode(&self.public_key).as_str()
    }

    /// Extracts the 'From' address from the canonicalized email header.
    pub fn get_from_addr(&self) -> Result<String> {
        let idxes = extract_from_addr_idxes(&self.canonicalized_header)?[0];
        Ok(self.canonicalized_header[idxes.0..idxes.1].to_string())
    }

    /// Retrieves the index range of the 'From' address within the canonicalized email header.
    pub fn get_from_addr_idxes(&self) -> Result<(usize, usize)> {
        let idxes = extract_from_addr_idxes(&self.canonicalized_header)?[0];
        Ok(idxes)
    }

    /// Extracts the 'To' address from the canonicalized email header.
    pub fn get_to_addr(&self) -> Result<String> {
        let idxes = extract_to_addr_idxes(&self.canonicalized_header)?[0];
        let str = self.canonicalized_header[idxes.0..idxes.1].to_string();
        Ok(str)
    }

    /// Extracts the email domain from the 'From' address in the canonicalized email header.
    pub fn get_email_domain(&self) -> Result<String> {
        let idxes = extract_from_addr_idxes(&self.canonicalized_header)?[0];
        let from_addr = self.canonicalized_header[idxes.0..idxes.1].to_string();
        let idxes = extract_email_domain_idxes(&from_addr)?[0];
        let str = from_addr[idxes.0..idxes.1].to_string();
        Ok(str)
    }

    /// Retrieves the index range of the email domain within the 'From' address.
    pub fn get_email_domain_idxes(&self) -> Result<(usize, usize)> {
        let idxes = extract_from_addr_idxes(&self.canonicalized_header)?[0];
        let str = self.canonicalized_header[idxes.0..idxes.1].to_string();
        let idxes = extract_email_domain_idxes(&str)?[0];
        Ok(idxes)
    }

    /// Extracts the entire subject line from the canonicalized email header.
    pub fn get_subject_all(&self) -> Result<String> {
        let idxes = extract_subject_all_idxes(&self.canonicalized_header)?[0];
        let str = self.canonicalized_header[idxes.0..idxes.1].to_string();
        Ok(str)
    }

    /// Retrieves the index range of the entire subject line within the canonicalized email header.
    pub fn get_subject_all_idxes(&self) -> Result<(usize, usize)> {
        let idxes = extract_subject_all_idxes(&self.canonicalized_header)?[0];
        Ok(idxes)
    }

    /// Retrieves the index range of the body hash within the canonicalized email header.
    pub fn get_body_hash_idxes(&self) -> Result<(usize, usize)> {
        let idxes = extract_body_hash_idxes(&self.canonicalized_header)?[0];
        Ok(idxes)
    }

    /// Returns the canonicalized email body as a string.
    pub fn get_body(&self) -> Result<String> {
        Ok(self.canonicalized_body.clone())
    }

    /// Returns the cleaned email body as a string.
    pub fn get_cleaned_body(&self) -> Result<String> {
        Ok(self.cleaned_body.clone())
    }

    /// Extracts the timestamp from the canonicalized email header.
    pub fn get_timestamp(&self) -> Result<u64> {
        let idxes = extract_timestamp_idxes(&self.canonicalized_header)?[0];
        let str = &self.canonicalized_header[idxes.0..idxes.1];
        Ok(str.parse()?)
    }

    /// Retrieves the index range of the timestamp within the canonicalized email header.
    pub fn get_timestamp_idxes(&self) -> Result<(usize, usize)> {
        let idxes = extract_timestamp_idxes(&self.canonicalized_header)?[0];
        Ok(idxes)
    }

    /// Extracts the invitation code from the canonicalized email body.
    pub fn get_invitation_code(&self, ignore_body_hash_check: bool) -> Result<String> {
        let regex_config = serde_json::from_str(include_str!("../regexes/invitation_code.json"))?;
        if ignore_body_hash_check {
            let idxes = extract_substr_idxes(&self.canonicalized_header, &regex_config)?[0];
            let str = self.canonicalized_header[idxes.0..idxes.1].to_string();
            Ok(str)
        } else {
            let idxes = extract_substr_idxes(&self.cleaned_body, &regex_config)?[0];
            let str = self.cleaned_body[idxes.0..idxes.1].to_string();
            Ok(str)
        }
    }

    /// Retrieves the index range of the invitation code within the canonicalized email body.
    pub fn get_invitation_code_idxes(
        &self,
        ignore_body_hash_check: bool,
    ) -> Result<(usize, usize)> {
        let regex_config = serde_json::from_str(include_str!("../regexes/invitation_code.json"))?;
        if ignore_body_hash_check {
            let idxes = extract_substr_idxes(&self.canonicalized_header, &regex_config)?[0];
            Ok(idxes)
        } else {
            let idxes = extract_substr_idxes(&self.cleaned_body, &regex_config)?[0];
            Ok(idxes)
        }
    }

    /// Extracts the email address from the subject line of the canonicalized email header.
    pub fn get_email_addr_in_subject(&self) -> Result<String> {
        let idxes = extract_subject_all_idxes(&self.canonicalized_header)?[0];
        let subject = self.canonicalized_header[idxes.0..idxes.1].to_string();
        let idxes = extract_email_addr_idxes(&subject)?[0];
        let str = subject[idxes.0..idxes.1].to_string();
        Ok(str)
    }

    /// Retrieves the index range of the email address within the subject line of the canonicalized email header.
    pub fn get_email_addr_in_subject_idxes(&self) -> Result<(usize, usize)> {
        let idxes = extract_subject_all_idxes(&self.canonicalized_header)?[0];
        let subject = self.canonicalized_header[idxes.0..idxes.1].to_string();
        let idxes = extract_email_addr_idxes(&subject)?[0];
        Ok(idxes)
    }

    /// Extracts the message ID from the canonicalized email header.
    pub fn get_message_id(&self) -> Result<String> {
        let idxes = extract_message_id_idxes(&self.canonicalized_header)?[0];
        let str = self.canonicalized_header[idxes.0..idxes.1].to_string();
        Ok(str)
    }

    /// Extracts the command from the canonicalized email header or body.
    pub fn get_command(&self, ignore_body_hash_check: bool) -> Result<String> {
        let regex_config = serde_json::from_str(include_str!("../regexes/command.json"))?;
        if ignore_body_hash_check {
            Ok("".to_string())
        } else {
            match extract_substr_idxes(&self.canonicalized_body, &regex_config) {
                Ok(idxes) => {
                    let str = self.canonicalized_body[idxes[0].0..idxes[0].1].to_string();
                    Ok(str.replace("=\r\n", ""))
                }
                Err(_) => match extract_substr_idxes(&self.cleaned_body, &regex_config) {
                    Ok(idxes) => {
                        let str = self.cleaned_body[idxes[0].0..idxes[0].1].to_string();
                        Ok(str)
                    }
                    _ => Ok("".to_string()),
                },
            }
        }
    }

    /// Retrieves the index range of the command within the canonicalized email header or body.
    pub fn get_command_idxes(&self, ignore_body_hash_check: bool) -> Result<(usize, usize)> {
        let regex_config = serde_json::from_str(include_str!("../regexes/command.json"))?;
        if ignore_body_hash_check {
            Ok((0, 0))
        } else {
            let idxes = extract_substr_idxes(&self.cleaned_body, &regex_config)?[0];
            Ok(idxes)
        }
    }

    /// Returns the cleaned email body with quoted-printable soft line breaks removed.
    pub fn get_body_with_soft_line_breaks(&self) -> Result<String> {
        Ok(self.cleaned_body.clone())
    }
}

/// Removes quoted-printable soft line breaks from an email body.
///
/// Quoted-printable encoding uses `=` followed by `\r\n` to indicate a soft line break.
/// This function removes such sequences from the input `Vec<u8>`.
///
/// # Arguments
///
/// * `body` - A `Vec<u8>` representing the email body to be cleaned.
///
/// # Returns
///
/// A `Vec<u8>` with all quoted-printable soft line breaks removed.
pub(crate) fn remove_quoted_printable_soft_breaks(body: Vec<u8>) -> Vec<u8> {
    let mut result = Vec::with_capacity(body.len());
    let mut iter = body.iter().enumerate();

    while let Some((i, &byte)) = iter.next() {
        if byte == b'=' && body.get(i + 1..i + 3) == Some(&[b'\r', b'\n']) {
            // Skip the next two bytes (soft line break)
            iter.nth(1);
        } else {
            result.push(byte);
        }
    }

    // Resize the result to match the original body length
    result.resize(body.len(), 0);
    result
}

/// Finds the index of the first occurrence of a pattern in the given body.
///
/// This function searches for the pattern within the body and returns the index of its first occurrence.
/// If the pattern is not found or is empty, the function returns 0.
///
/// # Arguments
///
/// * `body` - An `Option` wrapping a reference to a `Vec<u8>` representing the email body.
/// * `pattern` - A string slice representing the pattern to search for.
///
/// # Returns
///
/// The index of the first occurrence of the pattern within the body as `usize`.
pub(crate) fn find_index_in_body(body: Option<&Vec<u8>>, pattern: &str) -> usize {
    body.and_then(|body_bytes| {
        if !pattern.is_empty() {
            // Search for the pattern in the body
            body_bytes
                .windows(pattern.len())
                .position(|w| w == pattern.as_bytes())
        } else {
            None
        }
    })
    .unwrap_or(0) // Default to 0 if not found or pattern is empty
}

/// Represents the email headers as a collection of key-value pairs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmailHeaders(HashMap<String, Vec<String>>);

impl EmailHeaders {
    /// Creates a new `EmailHeaders` instance from a parsed email.
    ///
    /// # Arguments
    ///
    /// * `parsed_mail` - A reference to a `ParsedMail` instance.
    ///
    /// # Returns
    ///
    /// A new `EmailHeaders` instance containing the headers from the parsed email.
    pub fn new_from_mail(parsed_mail: &ParsedMail) -> Self {
        let mut headers = HashMap::new();
        for header in &parsed_mail.headers {
            let key = header.get_key().to_string();
            let value = header.get_value();
            headers.entry(key).or_insert_with(Vec::new).push(value);
        }
        Self(headers)
    }

    /// Retrieves the value(s) of a specific header.
    ///
    /// # Arguments
    ///
    /// * `name` - The name of the header to retrieve.
    ///
    /// # Returns
    ///
    /// An `Option` containing a `Vec<String>` of header values if the header exists, or `None` if it doesn't.
    pub fn get_header(&self, name: &str) -> Option<Vec<String>> {
        self.0.get(name).cloned()
    }
}
