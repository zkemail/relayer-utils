use std::convert::TryInto;

use itertools::Itertools;

// use cfdkim::*;
// use mail_auth::common::verify::VerifySignature;
// use mail_auth::trust_dns_resolver::proto::rr::dnssec::public_key;
// use trust_dns_resolver::error::ResolveError;
// use mail_auth::Error;
use crate::statics::*;
use anyhow::Result;
use hex;
// use mail_auth::{AuthenticatedMessage, DkimOutput, DkimResult, Resolver};

use cfdkim::{canonicalize_signed_email, resolve_public_key};
use neon::prelude::*;
use rsa::traits::PublicKeyParts;

use serde::{Deserialize, Serialize};
use zk_regex_apis::extract_substrs::*;
// use trust_dns_resolver::config::{ResolverConfig, ResolverOpts};
// use trust_dns_resolver::proto::rr::{RData, RecordType};
// use trust_dns_resolver::AsyncResolver;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParsedEmail {
    pub canonicalized_header: String,
    pub canonicalized_body: String,
    pub signature: Vec<u8>,
    pub public_key: Vec<u8>,
}

impl ParsedEmail {
    pub async fn new_from_raw_email(raw_email: &str) -> Result<Self> {
        let logger = slog::Logger::root(slog::Discard, slog::o!());
        let public_key = resolve_public_key(&logger, raw_email.as_bytes())
            .await
            .unwrap();
        let public_key = match public_key {
            cfdkim::DkimPublicKey::Rsa(pk) => pk,
            _ => panic!("not supportted public key type."),
        };
        let (canonicalized_header, canonicalized_body, signature_bytes) =
            canonicalize_signed_email(raw_email.as_bytes()).unwrap();
        let parsed_email = ParsedEmail {
            canonicalized_header: String::from_utf8(canonicalized_header)?,
            canonicalized_body: String::from_utf8(canonicalized_body)?,
            signature: signature_bytes.into_iter().collect_vec(),
            public_key: public_key.n().to_bytes_be(),
        };
        Ok(parsed_email)
    }

    pub fn signature_string(&self) -> String {
        "0x".to_string() + hex::encode(&self.signature).as_str()
    }

    pub fn public_key_string(&self) -> String {
        "0x".to_string() + hex::encode(&self.public_key).as_str()
    }

    pub fn get_from_addr(&self) -> Result<String> {
        let idxes = extract_from_addr_idxes(&self.canonicalized_header)?[0];
        let str = self.canonicalized_header[idxes.0..idxes.1].to_string();
        Ok(str)
    }

    pub fn get_from_addr_idxes(&self) -> Result<(usize, usize)> {
        let idxes = extract_from_addr_idxes(&self.canonicalized_header)?[0];
        Ok(idxes)
    }

    pub fn get_to_addr(&self) -> Result<String> {
        let idxes = extract_to_addr_idxes(&self.canonicalized_header)?[0];
        let str = self.canonicalized_header[idxes.0..idxes.1].to_string();
        Ok(str)
    }

    pub fn get_email_domain(&self) -> Result<String> {
        let idxes = extract_from_addr_idxes(&self.canonicalized_header)?[0];
        let from_addr = self.canonicalized_header[idxes.0..idxes.1].to_string();
        let idxes = extract_email_domain_idxes(&from_addr)?[0];
        let str = from_addr[idxes.0..idxes.1].to_string();
        Ok(str)
    }

    pub fn get_email_domain_idxes(&self) -> Result<(usize, usize)> {
        let idxes = extract_from_addr_idxes(&self.canonicalized_header)?[0];
        let str = self.canonicalized_header[idxes.0..idxes.1].to_string();
        let idxes = extract_email_domain_idxes(&str)?[0];
        Ok(idxes)
    }

    pub fn get_subject_all(&self) -> Result<String> {
        let idxes = extract_subject_all_idxes(&self.canonicalized_header)?[0];
        let str = self.canonicalized_header[idxes.0..idxes.1].to_string();
        Ok(str)
    }

    pub fn get_subject_all_idxes(&self) -> Result<(usize, usize)> {
        let idxes = extract_subject_all_idxes(&self.canonicalized_header)?[0];
        Ok(idxes)
    }

    pub fn get_timestamp(&self) -> Result<u64> {
        let idxes = extract_timestamp_idxes(&self.canonicalized_header)?[0];
        let str = &self.canonicalized_header[idxes.0..idxes.1];
        Ok(str.parse()?)
    }

    pub fn get_timestamp_idxes(&self) -> Result<(usize, usize)> {
        let idxes = extract_timestamp_idxes(&self.canonicalized_header)?[0];
        Ok(idxes)
    }

    pub fn get_invitation_code(&self) -> Result<String> {
        let regex_config =
            serde_json::from_str(include_str!("../regexes/invitation_code.json")).unwrap();
        let idxes = extract_substr_idxes(&self.canonicalized_header, &regex_config, false)?[0];
        let str = self.canonicalized_header[idxes.0..idxes.1].to_string();
        Ok(str)
    }

    pub fn get_invitation_code_idxes(&self) -> Result<(usize, usize)> {
        let regex_config =
            serde_json::from_str(include_str!("../regexes/invitation_code.json")).unwrap();
        let idxes = extract_substr_idxes(&self.canonicalized_header, &regex_config, false)?[0];
        Ok(idxes)
    }

    pub fn get_email_addr_in_subject(&self) -> Result<String> {
        let idxes = extract_subject_all_idxes(&self.canonicalized_header)?[0];
        let subject = self.canonicalized_header[idxes.0..idxes.1].to_string();
        let idxes = extract_email_addr_idxes(&subject)?[0];
        let str = subject[idxes.0..idxes.1].to_string();
        Ok(str)
    }

    pub fn get_email_addr_in_subject_idxes(&self) -> Result<(usize, usize)> {
        let idxes = extract_subject_all_idxes(&self.canonicalized_header)?[0];
        let subject = self.canonicalized_header[idxes.0..idxes.1].to_string();
        let idxes = extract_email_addr_idxes(&subject)?[0];
        Ok(idxes)
    }

    pub fn get_message_id(&self) -> Result<String> {
        let idxes = extract_message_id_idxes(&self.canonicalized_header)?[0];
        let str = self.canonicalized_header[idxes.0..idxes.1].to_string();
        Ok(str)
    }
}

pub fn parse_email_node(mut cx: FunctionContext) -> JsResult<JsPromise> {
    let raw_email = cx.argument::<JsString>(0)?.value(&mut cx);
    let channel = cx.channel();
    let (deferred, promise) = cx.promise();
    let rt = runtime(&mut cx)?;

    rt.spawn(async move {
        let parsed_email = ParsedEmail::new_from_raw_email(&raw_email).await;
        deferred.settle_with(&channel, move |mut cx| {
            match parsed_email {
                // Resolve the promise with the release date
                Ok(parsed_email) => {
                    let signature_str = parsed_email.signature_string();
                    let public_key_str = parsed_email.public_key_string();
                    let obj = cx.empty_object();
                    let canonicalized_header = cx.string(parsed_email.canonicalized_header);
                    obj.set(&mut cx, "canonicalizedHeader", canonicalized_header)?;
                    // let signed_header = cx.string(
                    //     "0x".to_string() + hex::encode(parsed_email.signed_header).as_str(),
                    // );
                    // obj.set(&mut cx, "signedHeader", signed_header)?;
                    let signature = cx.string(&signature_str);
                    obj.set(&mut cx, "signature", signature)?;

                    let public_key = cx.string(&public_key_str);
                    obj.set(&mut cx, "publicKey", public_key)?;
                    // let dkim_domain = cx.string(&parsed_email.dkim_domain);
                    // obj.set(&mut cx, "dkimDomain", dkim_domain)?;
                    Ok(obj)
                }

                // Reject the `Promise` if the version could not be found
                Err(err) => cx.throw_error(format!("Could not parse the raw email: {}", err)),
            }
        });
    });

    Ok(promise)
}

pub fn extract_invitation_code_idxes_node(mut cx: FunctionContext) -> JsResult<JsArray> {
    let input_str = cx.argument::<JsString>(0)?.value(&mut cx);
    let regex_config =
        serde_json::from_str(include_str!("../regexes/invitation_code.json")).unwrap();
    let substr_idxes = match extract_substr_idxes(&input_str, &regex_config, false) {
        Ok(substr_idxes) => substr_idxes,
        Err(e) => return cx.throw_error(e.to_string()),
    };
    let js_array = JsArray::new(&mut cx, substr_idxes.len() as u32);
    for (i, (start_idx, end_idx)) in substr_idxes.iter().enumerate() {
        let start_end_array = JsArray::new(&mut cx, 2u32);
        let start_idx = cx.number(*start_idx as f64);
        start_end_array.set(&mut cx, 0, start_idx)?;
        let end_idx = cx.number(*end_idx as f64);
        start_end_array.set(&mut cx, 1, end_idx)?;
        js_array.set(&mut cx, i as u32, start_end_array)?;
    }
    Ok(js_array)
}

pub fn extract_timestamp_int_node(mut cx: FunctionContext) -> JsResult<JsNumber> {
    let input_str = cx.argument::<JsString>(0)?.value(&mut cx);
    let substr_idxes = match extract_timestamp_idxes(&input_str) {
        Ok(substr_idxes) => substr_idxes,
        Err(e) => return cx.throw_error(e.to_string()),
    };
    let timestamp_str = &input_str[substr_idxes[0].0..substr_idxes[0].1];
    let timestamp_int = match timestamp_str.parse::<u64>() {
        Ok(timestamp_int) => timestamp_int,
        Err(e) => return cx.throw_error(e.to_string()),
    };
    let timestamp_int = cx.number(timestamp_int as f64);
    Ok(timestamp_int)
}

pub fn extract_invitation_code_with_prefix_idxes_node(
    mut cx: FunctionContext,
) -> JsResult<JsArray> {
    let input_str = cx.argument::<JsString>(0)?.value(&mut cx);
    let regex_config =
        serde_json::from_str(include_str!("../regexes/invitation_code_with_prefix.json")).unwrap();
    let substr_idxes = match extract_substr_idxes(&input_str, &regex_config, false) {
        Ok(substr_idxes) => substr_idxes,
        Err(e) => return cx.throw_error(e.to_string()),
    };
    let js_array = JsArray::new(&mut cx, substr_idxes.len().try_into().unwrap());
    for (i, (start_idx, end_idx)) in substr_idxes.iter().enumerate() {
        let start_end_array = JsArray::new(&mut cx, 2u32);
        let start_idx = cx.number(*start_idx as f64);
        start_end_array.set(&mut cx, 0, start_idx)?;
        let end_idx = cx.number(*end_idx as f64);
        start_end_array.set(&mut cx, 1, end_idx)?;
        js_array.set(&mut cx, i as u32, start_end_array)?;
    }
    Ok(js_array)
}
