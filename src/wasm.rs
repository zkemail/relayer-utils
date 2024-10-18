use js_sys::Promise;
use rand::rngs::OsRng;
use serde_wasm_bindgen::to_value;
use wasm_bindgen::prelude::*;

use crate::{hex_to_field, AccountCode, AccountSalt, PaddedEmailAddr, ParsedEmail};

#[wasm_bindgen]
#[allow(non_snake_case)]
pub async fn parseEmail(raw_email: String) -> Promise {
    let parsed_email = ParsedEmail::new_from_raw_email(&raw_email)
        .await
        .expect("Failed to parse email");
    let parsed_email = to_value(&parsed_email).expect("Failed to serialize ParsedEmail");
    Promise::resolve(&parsed_email)
}

#[wasm_bindgen]
#[allow(non_snake_case)]
pub async fn generateAccountCode() -> JsValue {
    to_value(&AccountCode::new(OsRng)).expect("Failed to serialize AccountCode")
}

#[wasm_bindgen]
#[allow(non_snake_case)]
pub async fn generateAccountSalt(email_addr: String, account_code: String) -> JsValue {
    let email_addr = PaddedEmailAddr::from_email_addr(&email_addr);
    let account_code =
        AccountCode::from(hex_to_field(&account_code).expect("Failed to parse AccountCode"));
    let account_salt =
        AccountSalt::new(&email_addr, account_code).expect("Failed to generate AccountSalt");
    to_value(&account_salt).expect("Failed to serialize AccountSalt")
}

#[wasm_bindgen]
#[allow(non_snake_case)]
pub async fn padEmailAddr(email_addr: String) -> JsValue {
    let padded_email_addr = PaddedEmailAddr::from_email_addr(&email_addr);
    to_value(&padded_email_addr).expect("Failed to serialize padded_email_addr")
}
