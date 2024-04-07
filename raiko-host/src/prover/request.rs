use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use serde_with::{serde_as, DisplayFromStr};
use zeth_primitives::{Address, B256};

#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "proofType")]
#[serde(rename_all = "camelCase")]
#[allow(clippy::large_enum_variant)]
pub enum ProofRequest {
    Sgx(SgxRequest),
    PseZk(PseZkRequest),
}

#[serde_as]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SgxParam {
    pub setup: bool,
    pub bootstrap: bool,
    pub prove: bool,
    pub input_path: Option<PathBuf>,
}

#[serde_as]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SgxRequest {
    /// the block number
    pub block_number: u64,
    /// node for get block by number
    pub rpc: String,
    /// l1 node for signal root verify and get txlist info from proposed transaction.
    pub l1_rpc: String,
    /// beacon node for data blobs
    pub beacon_rpc: String,
    // graffiti
    pub graffiti: B256,
    /// the protocol instance data
    #[serde_as(as = "DisplayFromStr")]
    pub prover: Address,
    // Generic proof parameters which has to match with the type
    pub proof_param: SgxParam,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct PseZkRequest {}

#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum ProofResponse {
    Sgx(SgxResponse),
    PseZk(PseZkResponse),
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SgxResponse {
    /// proof format: 4b(id)+20b(pubkey)+65b(signature)
    pub proof: String,
    pub quote: String,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct PseZkResponse {}
