pub mod circuit;
pub mod constants;
pub mod converters;
pub mod cryptos;
pub mod logger;
pub mod node;
pub mod parse_email;

pub use circuit::*;
pub(crate) use constants::*;
pub use converters::*;
pub use cryptos::*;
pub use logger::*;
pub(crate) use node::*;
pub use parse_email::*;

pub use neon::{context::ModuleContext, result::NeonResult};
pub use zk_regex_apis::extract_substrs::*;
pub use zk_regex_apis::padding::*;

#[neon::main]
fn main(mut cx: ModuleContext) -> NeonResult<()> {
    cx.export_function("parseEmail", parse_email_node)?;
    cx.export_function("padString", pad_string_node)?;
    cx.export_function("bytes2Fields", bytes_to_fields_node)?;
    cx.export_function("extractSubstrIdxes", extract_substr_idxes_node)?;
    cx.export_function("extractEmailAddrIdxes", extract_email_addr_idxes_node)?;
    cx.export_function("extractEmailDomainIdxes", extract_email_domain_idxes_node)?;
    cx.export_function(
        "extractEmailAddrWithNameIdxes",
        extract_email_addr_with_name_idxes_node,
    )?;
    cx.export_function("extractFromAllIdxes", extract_from_all_idxes_node)?;
    cx.export_function("extractFromAddrIdxes", extract_from_addr_idxes_node)?;
    cx.export_function("extractSubjectAllIdxes", extract_subject_all_idxes_node)?;
    cx.export_function("extractBodyHashIdxes", extract_body_hash_idxes_node)?;
    cx.export_function("extractTimestampIdxes", extract_timestamp_idxes_node)?;
    cx.export_function("extractTimestampInt", extract_timestamp_int_node)?;
    cx.export_function("extractMessageIdIdxes", extract_message_id_idxes_node)?;
    cx.export_function(
        "extractInvitationCodeIdxes",
        extract_invitation_code_idxes_node,
    )?;
    cx.export_function(
        "extractInvitationCodeWithPrefixIdxes",
        extract_invitation_code_with_prefix_idxes_node,
    )?;
    cx.export_function("genRelayerRand", gen_relayer_rand_node)?;
    cx.export_function("relayerRandHash", relayer_rand_hash_node)?;
    cx.export_function("padEmailAddr", pad_email_addr_node)?;
    cx.export_function("emailAddrCommitRand", email_addr_commit_rand_node)?;
    cx.export_function("emailAddrCommit", email_addr_commit_node)?;
    cx.export_function(
        "emailAddrCommitWithSignature",
        email_addr_commit_with_signature_node,
    )?;
    cx.export_function("genAccountCode", gen_account_code_node)?;
    cx.export_function("genEmailCircuitInput", generate_email_circuit_input_node)?;
    cx.export_function("extractRandFromSignature", extract_rand_from_signature_node)?;
    cx.export_function("accountCodeCommit", account_code_commit_node)?;
    cx.export_function("accountSalt", account_salt_node)?;
    cx.export_function("publicKeyHash", public_key_hash_node)?;
    cx.export_function("emailNullifier", email_nullifier_node)?;
    Ok(())
}
