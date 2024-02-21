// Copyright 2023 RISC Zero, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use std::collections::BTreeSet;

use anyhow::{anyhow, Result};
use ethers_core::types::{Block, Bytes, EIP1186ProofResponse, Transaction, H160, H256, U256};
use serde::{Deserialize, Serialize};
#[cfg(feature = "taiko")]
use zeth_primitives::taiko::BlockProposed;

pub mod cached_rpc_provider;
pub mod file_provider;
pub mod rpc_provider;

// Blob data from the beacon chain
// type Sidecar struct {
// Index                    string                   `json:"index"`
// Blob                     string                   `json:"blob"`
// SignedBeaconBlockHeader  *SignedBeaconBlockHeader `json:"signed_block_header"`
// KzgCommitment            string                   `json:"kzg_commitment"`
// KzgProof                 string                   `json:"kzg_proof"`
// CommitmentInclusionProof []string
// `json:"kzg_commitment_inclusion_proof"` }
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct GetBlobData {
    pub index: String,
    pub blob: String,
    // pub signed_block_header: SignedBeaconBlockHeader, // ignore for now
    pub kzg_commitment: String,
    pub kzg_proof: String,
    pub kzg_commitment_inclusion_proof: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct GetBlobsResponse {
    pub data: Vec<GetBlobData>,
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct AccountQuery {
    pub block_no: u64,
    pub address: H160,
}

#[derive(Clone, Debug, Deserialize, PartialOrd, Ord, Eq, Hash, PartialEq, Serialize)]
pub struct BlockQuery {
    pub block_no: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct ProofQuery {
    pub block_no: u64,
    pub address: H160,
    pub indices: BTreeSet<H256>,
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct StorageQuery {
    pub block_no: u64,
    pub address: H160,
    pub index: H256,
}

#[cfg(feature = "taiko")]
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct ProposeQuery {
    pub l1_contract: H160,
    pub l1_block_no: u64,
    pub l2_block_no: u64,
}

pub trait Provider: Send {
    fn save(&self) -> Result<()>;

    fn get_full_block(&mut self, query: &BlockQuery) -> Result<Block<Transaction>>;
    fn get_partial_block(&mut self, query: &BlockQuery) -> Result<Block<H256>>;
    fn get_proof(&mut self, query: &ProofQuery) -> Result<EIP1186ProofResponse>;
    fn get_transaction_count(&mut self, query: &AccountQuery) -> Result<U256>;
    fn get_balance(&mut self, query: &AccountQuery) -> Result<U256>;
    fn get_code(&mut self, query: &AccountQuery) -> Result<Bytes>;
    fn get_storage(&mut self, query: &StorageQuery) -> Result<H256>;

    #[cfg(feature = "taiko")]
    fn get_propose(&mut self, query: &ProposeQuery) -> Result<(Transaction, BlockProposed)>;
    #[cfg(feature = "taiko")]
    /// get 256 blocks one time to reduce the fetch time cost
    fn batch_get_partial_blocks(&mut self, query: &BlockQuery) -> Result<Vec<Block<H256>>>;
    #[cfg(feature = "taiko")]
    fn get_blob_data(&mut self, block_id: u64) -> Result<GetBlobsResponse>;
}

pub trait MutProvider: Provider {
    fn insert_full_block(&mut self, query: BlockQuery, val: Block<Transaction>);
    fn insert_partial_block(&mut self, query: BlockQuery, val: Block<H256>);
    fn insert_proof(&mut self, query: ProofQuery, val: EIP1186ProofResponse);
    fn insert_transaction_count(&mut self, query: AccountQuery, val: U256);
    fn insert_balance(&mut self, query: AccountQuery, val: U256);
    fn insert_code(&mut self, query: AccountQuery, val: Bytes);
    fn insert_storage(&mut self, query: StorageQuery, val: H256);

    #[cfg(feature = "taiko")]
    fn insert_propose(&mut self, query: ProposeQuery, val: (Transaction, BlockProposed));
    #[cfg(feature = "taiko")]
    fn insert_blob(&mut self, block_id: u64, val: GetBlobsResponse);
}

pub fn new_file_provider(file_path: String) -> Result<Box<dyn Provider>> {
    let provider = file_provider::FileProvider::read_from_file(file_path)?;

    Ok(Box::new(provider))
}

pub fn new_rpc_provider(
    rpc_url: String,
    beacon_rpc_url: Option<String>,
) -> Result<Box<dyn Provider>> {
    let provider = rpc_provider::RpcProvider::new(rpc_url, beacon_rpc_url)?;

    Ok(Box::new(provider))
}

pub fn new_cached_rpc_provider(
    cache_path: String,
    rpc_url: String,
    beacon_rpc_url: Option<String>,
) -> Result<Box<dyn Provider>> {
    let provider =
        cached_rpc_provider::CachedRpcProvider::new(cache_path, rpc_url, beacon_rpc_url)?;

    Ok(Box::new(provider))
}

pub fn new_provider(
    cache_path: Option<String>,
    rpc_url: Option<String>,
    beacon_rpc_url: Option<String>,
) -> Result<Box<dyn Provider>> {
    match (cache_path, rpc_url) {
        (Some(cache_path), Some(rpc_url)) => {
            new_cached_rpc_provider(cache_path, rpc_url, beacon_rpc_url)
        }
        (Some(cache_path), None) => new_file_provider(cache_path),
        (None, Some(rpc_url)) => new_rpc_provider(rpc_url, beacon_rpc_url),
        (None, None) => Err(anyhow!("No cache_path or rpc_url given")),
    }
}
