use std::error::Error;

use crate::converters::*;

use ethers::types::Bytes;
use halo2curves::ff::Field;
use neon::prelude::*;
use poseidon_rs::*;
use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};
pub use zk_regex_apis::padding::pad_string;

pub const MAX_EMAIL_ADDR_BYTES: usize = 256;

#[derive(Debug, Clone, Copy)]
pub struct RelayerRand(pub Fr);

impl RelayerRand {
    pub fn new<R: RngCore>(mut r: R) -> Self {
        Self(Fr::random(&mut r))
    }

    pub fn new_from_seed(seed: &[u8]) -> Result<Self, PoseidonError> {
        let value = poseidon_bytes(seed)?;
        Ok(Self(value))
    }

    pub fn hash(&self) -> Result<Fr, PoseidonError> {
        poseidon_fields(&[self.0])
    }
}

#[derive(Debug, Clone)]
pub struct PaddedEmailAddr {
    pub padded_bytes: Vec<u8>,
    pub email_addr_len: usize,
}

impl PaddedEmailAddr {
    pub fn from_email_addr(email_addr: &str) -> Self {
        let email_addr_len = email_addr.as_bytes().len();
        // let mut padded_bytes = email_addr.as_bytes().to_vec();
        // padded_bytes.append(&mut vec![0; MAX_EMAIL_ADDR_BYTES - email_addr_len]);
        let padded_bytes = pad_string(email_addr, MAX_EMAIL_ADDR_BYTES);
        Self {
            padded_bytes,
            email_addr_len,
        }
    }

    pub fn to_email_addr_fields(&self) -> Vec<Fr> {
        bytes2fields(&self.padded_bytes)
    }

    // pub fn to_pointer(&self, relayer_rand: &RelayerRand) -> Result<Fr, PoseidonError> {
    //     self.to_commitment(&relayer_rand.0)
    // }

    pub fn to_commitment(&self, rand: &Fr) -> Result<Fr, PoseidonError> {
        let mut inputs = vec![*rand];
        inputs.append(&mut self.to_email_addr_fields());
        poseidon_fields(&inputs)
    }

    pub fn to_commitment_with_signature(&self, signature: &[u8]) -> Result<Fr, PoseidonError> {
        let cm_rand = extract_rand_from_signature(signature)?;
        poseidon_fields(&[vec![cm_rand], self.to_email_addr_fields()].concat())
    }
}

pub fn extract_rand_from_signature(signature: &[u8]) -> Result<Fr, PoseidonError> {
    let mut signature = signature.to_vec();
    signature.reverse();
    let mut inputs = bytes_chunk_fields(&signature, 121, 2, 17);
    inputs.push(Fr::one());
    let cm_rand = poseidon_fields(&inputs)?;
    Ok(cm_rand)
}

#[derive(Debug, Clone, Copy)]
pub struct AccountCode(pub Fr);

impl AccountCode {
    pub fn new<R: RngCore>(rng: R) -> Self {
        Self(Fr::random(rng))
    }

    pub fn from(elem: Fr) -> Self {
        Self(elem)
    }

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
pub struct AccountSalt(pub Fr);

impl AccountSalt {
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

/// `public_key_n` is little endian.
pub fn public_key_hash(public_key_n: &[u8]) -> Result<Fr, PoseidonError> {
    let inputs = bytes_chunk_fields(public_key_n, 121, 2, 17);
    poseidon_fields(&inputs)
}

/// `signature` is little endian.
pub fn email_nullifier(signature: &[u8]) -> Result<Fr, PoseidonError> {
    let inputs = bytes_chunk_fields(signature, 121, 2, 17);
    let sign_rand = poseidon_fields(&inputs)?;
    poseidon_fields(&[sign_rand])
}

pub fn gen_relayer_rand_node(mut cx: FunctionContext) -> JsResult<JsString> {
    let mut rng = OsRng;
    let relayer_rand = RelayerRand::new(&mut rng);
    let relayer_rand_str = field2hex(&relayer_rand.0);
    Ok(cx.string(relayer_rand_str))
}

// pub fn relayer_rand_hash_node(mut cx: FunctionContext) -> JsResult<JsString> {
//     let relayer_rand = cx.argument::<JsString>(0)?.value(&mut cx);
//     let relayer_rand = hex2field_node(&mut cx, &relayer_rand)?;
//     let relayer_rand_hash = match RelayerRand(relayer_rand).hash() {
//         Ok(fr) => fr,
//         Err(e) => return cx.throw_error(&format!("RelayerRand hash failed: {}", e)),
//     };
//     let relayer_rand_hash_str = field2hex(&relayer_rand_hash);
//     Ok(cx.string(relayer_rand_hash_str))
// }

// pub fn pad_string_node(mut cx: FunctionContext) -> JsResult<JsArray> {
//     let string = cx.argument::<JsString>(0)?.value(&mut cx);
//     let padded_bytes_size = cx.argument::<JsNumber>(1)?.value(&mut cx) as usize;
//     let padded_bytes = JsArray::new(&mut cx, padded_bytes_size as u32);
//     for (idx, byte) in string.as_bytes().into_iter().enumerate() {
//         let js_byte = cx.number(*byte);
//         padded_bytes.set(&mut cx, idx as u32, js_byte)?;
//     }
//     for idx in string.len()..padded_bytes_size {
//         let js_byte = cx.number(0);
//         padded_bytes.set(&mut cx, idx as u32, js_byte)?;
//     }
//     Ok(padded_bytes)
// }

pub fn pad_email_addr_node(mut cx: FunctionContext) -> JsResult<JsArray> {
    let email_addr = cx.argument::<JsString>(0)?.value(&mut cx);
    let padded_email_addr = PaddedEmailAddr::from_email_addr(&email_addr);
    let padded_email_addr_bytes =
        JsArray::new(&mut cx, padded_email_addr.padded_bytes.len() as u32);
    for (idx, byte) in padded_email_addr.padded_bytes.into_iter().enumerate() {
        let js_byte = cx.number(byte);
        padded_email_addr_bytes.set(&mut cx, idx as u32, js_byte)?;
    }
    Ok(padded_email_addr_bytes)
}

// pub fn email_addr_pointer_node(mut cx: FunctionContext) -> JsResult<JsString> {
//     let email_addr = cx.argument::<JsString>(0)?.value(&mut cx);
//     let relayer_rand = cx.argument::<JsString>(1)?.value(&mut cx);
//     let relayer_rand = hex2field_node(&mut cx, &relayer_rand)?;
//     let padded_email_addr = PaddedEmailAddr::from_email_addr(&email_addr);
//     let email_addr_pointer = match padded_email_addr.to_pointer(&RelayerRand(relayer_rand)) {
//         Ok(fr) => fr,
//         Err(e) => return cx.throw_error(&format!("EmailAddrPointer failed: {}", e)),
//     };
//     let email_addr_pointer_str = field2hex(&email_addr_pointer);
//     Ok(cx.string(email_addr_pointer_str))
// }

pub fn email_addr_commit_rand_node(mut cx: FunctionContext) -> JsResult<JsString> {
    let mut rng = OsRng;
    let commit_rand = Fr::random(&mut rng);
    let commit_rand_str = field2hex(&commit_rand);
    Ok(cx.string(commit_rand_str))
}

pub fn email_addr_commit_node(mut cx: FunctionContext) -> JsResult<JsString> {
    let email_addr = cx.argument::<JsString>(0)?.value(&mut cx);
    let rand = cx.argument::<JsString>(1)?.value(&mut cx);
    let rand = hex2field_node(&mut cx, &rand)?;
    let padded_email_addr = PaddedEmailAddr::from_email_addr(&email_addr);
    let email_addr_commit = match padded_email_addr.to_commitment(&rand) {
        Ok(fr) => fr,
        Err(e) => return cx.throw_error(&format!("EmailAddrCommit failed: {}", e)),
    };
    let email_addr_commit_str = field2hex(&email_addr_commit);
    Ok(cx.string(email_addr_commit_str))
}

pub fn email_addr_commit_with_signature_node(mut cx: FunctionContext) -> JsResult<JsString> {
    let email_addr = cx.argument::<JsString>(0)?.value(&mut cx);
    let signature = cx.argument::<JsString>(1)?.value(&mut cx);
    let signature = match hex::decode(&signature[2..]) {
        Ok(bytes) => bytes,
        Err(e) => return cx.throw_error(&format!("signature is an invalid hex string: {}", e)),
    };
    // signature.reverse();
    let padded_email_addr = PaddedEmailAddr::from_email_addr(&email_addr);
    let email_addr_commit = match padded_email_addr.to_commitment_with_signature(&signature) {
        Ok(fr) => fr,
        Err(e) => return cx.throw_error(&format!("EmailAddrCommit failed: {}", e)),
    };
    let email_addr_commit_str = field2hex(&email_addr_commit);
    Ok(cx.string(email_addr_commit_str))
}

pub fn extract_rand_from_signature_node(mut cx: FunctionContext) -> JsResult<JsString> {
    let signature = cx.argument::<JsString>(0)?.value(&mut cx);
    let signature = match hex::decode(&signature[2..]) {
        Ok(bytes) => bytes,
        Err(e) => return cx.throw_error(&format!("signature is an invalid hex string: {}", e)),
    };
    // signature.reverse();
    let rand = match extract_rand_from_signature(&signature) {
        Ok(fr) => fr,
        Err(e) => return cx.throw_error(&format!("extract_rand_from_signature failed: {}", e)),
    };
    let rand_str = field2hex(&rand);
    Ok(cx.string(rand_str))
}

pub fn gen_account_code_node(mut cx: FunctionContext) -> JsResult<JsString> {
    let mut rng = OsRng;
    let account_code = AccountCode::new(&mut rng);
    let account_code_str = field2hex(&account_code.0);
    Ok(cx.string(account_code_str))
}

pub fn public_key_hash_node(mut cx: FunctionContext) -> JsResult<JsString> {
    let public_key_n = cx.argument::<JsString>(0)?.value(&mut cx);
    let mut public_key_n = match hex::decode(&public_key_n[2..]) {
        Ok(bytes) => bytes,
        Err(e) => return cx.throw_error(&format!("public_key_n is an invalid hex string: {}", e)),
    };
    public_key_n.reverse();
    let hash_field = match public_key_hash(&public_key_n) {
        Ok(hash_field) => hash_field,
        Err(e) => return cx.throw_error(&format!("public_key_hash failed: {}", e)),
    };
    let hash_str = field2hex(&hash_field);
    Ok(cx.string(hash_str))
}

pub fn email_nullifier_node(mut cx: FunctionContext) -> JsResult<JsString> {
    let signature = cx.argument::<JsString>(0)?.value(&mut cx);
    let mut signature = match hex::decode(&signature[2..]) {
        Ok(bytes) => bytes,
        Err(e) => return cx.throw_error(&format!("signature is an invalid hex string: {}", e)),
    };
    signature.reverse();
    let nullifier = match email_nullifier(&signature) {
        Ok(nullifier) => nullifier,
        Err(e) => return cx.throw_error(&format!("email_nullifier failed: {}", e)),
    };
    let nullifier_str = field2hex(&nullifier);
    Ok(cx.string(nullifier_str))
}

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

    assert!(
        (data.len() * 8) % 512 == 0,
        "Padding did not complete properly!"
    );

    let message_len = data.len();

    // Pad the data to the specified maximum length with zeros
    while data.len() < max_sha_bytes {
        data = merge_u8_arrays(data, int64_to_bytes(0));
    }

    assert!(
        data.len() == max_sha_bytes,
        "Padding to max length did not complete properly! Your padded message is {} long but max is {}!",
        data.len(),
        max_sha_bytes
    );

    (data, message_len)
}

pub fn partial_sha(msg: &[u8], msg_len: usize) -> Vec<u8> {
    let mut hasher = Sha256::new();
    // Assuming msg_len is used to specify how much of msg to hash.
    // This example simply hashes the entire msg for simplicity.
    hasher.update(&msg[..msg_len]);
    let result = hasher.finalize();
    result.to_vec()
}

pub fn generate_partial_sha(
    body: Vec<u8>,
    body_length: usize,
    selector_string: Option<String>,
    max_remaining_body_length: usize,
) -> Result<(Vec<u8>, Vec<u8>, usize), Box<dyn Error>> {
    let selector_index = 0;

    if let Some(selector_str) = selector_string {
        let selector = selector_str.as_bytes();
        // Find selector in body and return the starting index
        let body_slice = &body[..body_length];
        let _selector_index = match body_slice
            .windows(selector.len())
            .position(|window| window == selector)
        {
            Some(index) => index,
            None => return Err("Selector not found in body".into()),
        };
    }

    let sha_cutoff_index = (selector_index / 64) * 64;
    let precompute_text = &body[..sha_cutoff_index];
    let mut body_remaining = body[sha_cutoff_index..].to_vec();

    let body_remaining_length = body_length - precompute_text.len();

    if body_remaining_length > max_remaining_body_length {
        return Err(Box::new(std::io::Error::new(
            std::io::ErrorKind::Other,
            format!(
                "Remaining body {} after the selector is longer than max ({})",
                body_remaining_length, max_remaining_body_length
            ),
        )));
    }

    if body_remaining.len() % 64 != 0 {
        return Err(Box::new(std::io::Error::new(
            std::io::ErrorKind::Other,
            "Remaining body was not padded correctly with int64s",
        )));
    }

    while body_remaining.len() < max_remaining_body_length {
        body_remaining.push(0);
    }

    let precomputed_sha = partial_sha(precompute_text, sha_cutoff_index);
    Ok((precomputed_sha, body_remaining, body_remaining_length))
}

pub fn keccak256(data: &[u8]) -> Bytes {
    Bytes::from(ethers::utils::keccak256(data))
}

pub fn account_code_commit_node(mut cx: FunctionContext) -> JsResult<JsString> {
    let account_code = cx.argument::<JsString>(0)?.value(&mut cx);
    let email_addr = cx.argument::<JsString>(1)?.value(&mut cx);
    let relayer_rand_hash = cx.argument::<JsString>(2)?.value(&mut cx);
    let account_code = hex2field_node(&mut cx, &account_code)?;
    let padded_email_addr = PaddedEmailAddr::from_email_addr(&email_addr);
    let relayer_rand_hash = hex2field_node(&mut cx, &relayer_rand_hash)?;
    let account_code_commit =
        match AccountCode(account_code).to_commitment(&padded_email_addr, &relayer_rand_hash) {
            Ok(fr) => fr,
            Err(e) => return cx.throw_error(&format!("AccountCodeCommit failed: {}", e)),
        };
    let account_code_commit_str = field2hex(&account_code_commit);
    Ok(cx.string(account_code_commit_str))
}

pub fn relayer_rand_hash_node(mut cx: FunctionContext) -> JsResult<JsString> {
    let relayer_rand = cx.argument::<JsString>(0)?.value(&mut cx);
    let relayer_rand = hex2field_node(&mut cx, &relayer_rand)?;
    let relayer_rand_hash = match RelayerRand(relayer_rand).hash() {
        Ok(fr) => fr,
        Err(e) => return cx.throw_error(&format!("RelayerRand hash failed: {}", e)),
    };
    let relayer_rand_hash_str = field2hex(&relayer_rand_hash);
    Ok(cx.string(relayer_rand_hash_str))
}

pub fn account_salt_node(mut cx: FunctionContext) -> JsResult<JsString> {
    let email_addr = cx.argument::<JsString>(0)?.value(&mut cx);
    let padded_email_addr = PaddedEmailAddr::from_email_addr(&email_addr);
    let account_code_str = cx.argument::<JsString>(1)?.value(&mut cx);
    let account_code = hex2field_node(&mut cx, &account_code_str)?;
    let account_salt = match AccountSalt::new(&padded_email_addr, AccountCode(account_code)) {
        Ok(account_salt) => account_salt,
        Err(e) => return cx.throw_error(&format!("AccountSalt failed: {}", e)),
    };
    let account_salt_str = field2hex(&account_salt.0);
    Ok(cx.string(account_salt_str))
}

#[cfg(test)]
mod tests {
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
        assert_eq!(field2hex(&hash_field), expected_hash);
    }
}
