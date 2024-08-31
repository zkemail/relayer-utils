//! This module contains the `ParsedEmail` struct and its implementation.

use anyhow::Result;
use cfdkim::{canonicalize_signed_email, resolve_public_key};
use hex;
use itertools::Itertools;
use rsa::traits::PublicKeyParts;
use serde::{Deserialize, Serialize};
use zk_regex_apis::extract_substrs::{
    extract_body_hash_idxes, extract_email_addr_idxes, extract_email_domain_idxes,
    extract_from_addr_idxes, extract_message_id_idxes, extract_subject_all_idxes,
    extract_substr_idxes, extract_timestamp_idxes, extract_to_addr_idxes,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
/// `ParsedEmail` holds the canonicalized parts of an email along with its signature and public key.
pub struct ParsedEmail {
    pub canonicalized_header: String, // The canonicalized email header.
    pub canonicalized_body: String,   // The canonicalized email body.
    pub signature: Vec<u8>,           // The email signature bytes.
    pub public_key: Vec<u8>,          // The public key bytes associated with the email.
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

        // Resolve the public key from the raw email bytes.
        let public_key = resolve_public_key(&logger, raw_email.as_bytes()).await?;
        let public_key = match public_key {
            cfdkim::DkimPublicKey::Rsa(pk) => pk,
            _ => panic!("Unsupported public key type."), // Panics if the public key type is not RSA.
        };

        // Canonicalize the signed email to separate the header, body, and signature.
        let (canonicalized_header, canonicalized_body, signature_bytes) =
            canonicalize_signed_email(raw_email.as_bytes())?;

        // Construct the `ParsedEmail` instance.
        let parsed_email = ParsedEmail {
            canonicalized_header: String::from_utf8(canonicalized_header)?, // Convert bytes to string, may return an error if not valid UTF-8.
            canonicalized_body: String::from_utf8(canonicalized_body)?, // Convert bytes to string, may return an error if not valid UTF-8.
            signature: signature_bytes.into_iter().collect_vec(), // Collect the signature bytes into a vector.
            public_key: public_key.n().to_bytes_be(), // Convert the public key to big-endian bytes.
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
    pub fn get_invitation_code(&self) -> Result<String> {
        let regex_config = serde_json::from_str(include_str!("../regexes/invitation_code.json"))?;
        let idxes = extract_substr_idxes(&self.canonicalized_body, &regex_config)?[0];
        let str = self.canonicalized_body[idxes.0..idxes.1].to_string();
        Ok(str)
    }

    /// Retrieves the index range of the invitation code within the canonicalized email body.
    pub fn get_invitation_code_idxes(&self) -> Result<(usize, usize)> {
        let regex_config = serde_json::from_str(include_str!("../regexes/invitation_code.json"))?;
        let idxes = extract_substr_idxes(&self.canonicalized_body, &regex_config)?[0];
        Ok(idxes)
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

    pub fn get_command_idxes(&self) -> Result<(usize, usize)> {
        let regex_config = serde_json::from_str(include_str!("../regexes/command.json"))?;
        let idxes = extract_substr_idxes(&self.canonicalized_body, &regex_config)?[0];
        Ok(idxes)
    }
}
