use serde::{Deserialize, Serialize};
use zk_regex_compiler::ProvingFramework;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BoundedVec {
    pub storage: Vec<u8>,
    pub len: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Pubkey {
    pub modulus: Vec<String>,
    pub redc: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Sequence {
    pub index: usize,
    pub length: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NoirCircuitInputs {
    pub header: BoundedVec,
    pub pubkey: Pubkey,
    pub signature: Vec<String>,
    pub dkim_header_sequence: Sequence,
    pub body: Option<BoundedVec>,
    pub body_hash_index: Option<usize>,
    pub partial_body_real_length: Option<usize>,
    pub partial_body_hash: Option<Vec<u32>>,
    pub header_mask: Option<Vec<u8>>,
    pub body_mask: Option<Vec<u8>>,
    pub decoded_body: Option<BoundedVec>,
    pub from_header_sequence: Option<Sequence>,
    pub from_address_sequence: Option<Sequence>,
    pub to_header_sequence: Option<Sequence>,
    pub to_address_sequence: Option<Sequence>,
}

#[derive(Default, Clone, Debug, Serialize, Deserialize)]
pub struct NoirInputGenerationArgs {
    pub ignore_body_hash_check: Option<bool>,
    pub sha_precompute_selector: Option<String>,
    pub max_headers_length: Option<usize>,
    pub max_body_length: Option<usize>,
    pub remove_soft_line_breaks: Option<bool>,
    pub header_mask: Option<Vec<u8>>,
    pub body_mask: Option<Vec<u8>>,
    pub extract_from: Option<bool>,
    pub extract_to: Option<bool>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RegexInput {
    pub name: String,
    pub regex_graph_json: String,
    pub haystack: String,
    pub max_haystack_length: usize,
    pub max_match_length: usize,
    pub proving_framework: ProvingFramework,
}
