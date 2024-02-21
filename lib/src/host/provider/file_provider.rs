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

use std::{
    collections::{BTreeMap, HashMap},
    fs::File,
    io::{Read, Write},
};

use anyhow::{anyhow, Result};
use ethers_core::types::{Block, Bytes, EIP1186ProofResponse, Transaction, H256, U256};
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
#[cfg(feature = "taiko")]
use zeth_primitives::taiko::BlockProposed;

use super::{
    AccountQuery, BlockQuery, GetBlobsResponse, MutProvider, ProofQuery, Provider, StorageQuery,
};

#[serde_as]
#[derive(Deserialize, Serialize)]
pub struct FileProvider {
    #[serde(skip)]
    file_path: String,
    #[serde(skip)]
    dirty: bool,
    #[serde_as(as = "Vec<(_, _)>")]
    full_blocks: HashMap<BlockQuery, Block<Transaction>>,
    #[serde_as(as = "Vec<(_, _)>")]
    partial_blocks: BTreeMap<BlockQuery, Block<H256>>,
    #[serde_as(as = "Vec<(_, _)>")]
    proofs: HashMap<ProofQuery, EIP1186ProofResponse>,
    #[serde_as(as = "Vec<(_, _)>")]
    transaction_count: HashMap<AccountQuery, U256>,
    #[serde_as(as = "Vec<(_, _)>")]
    balance: HashMap<AccountQuery, U256>,
    #[serde_as(as = "Vec<(_, _)>")]
    code: HashMap<AccountQuery, Bytes>,
    #[serde_as(as = "Vec<(_, _)>")]
    storage: HashMap<StorageQuery, H256>,
    #[cfg(feature = "taiko")]
    propose: Option<(Transaction, BlockProposed)>,
    #[cfg(feature = "taiko")]
    blobs: HashMap<u64, GetBlobsResponse>,
}

impl FileProvider {
    pub fn empty(file_path: String) -> Self {
        FileProvider {
            file_path,
            dirty: false,
            full_blocks: HashMap::new(),
            partial_blocks: BTreeMap::new(),
            proofs: HashMap::new(),
            transaction_count: HashMap::new(),
            balance: HashMap::new(),
            code: HashMap::new(),
            storage: HashMap::new(),
            #[cfg(feature = "taiko")]
            propose: Default::default(),
            #[cfg(feature = "taiko")]
            blobs: HashMap::new(),
        }
    }

    pub fn read_from_file(file_path: String) -> Result<Self> {
        let mut buf = vec![];
        let mut decoder = flate2::read::GzDecoder::new(File::open(&file_path)?);
        decoder.read_to_end(&mut buf)?;

        let mut out: Self = serde_json::from_slice(&buf[..])?;

        out.file_path = file_path;
        out.dirty = false;
        Ok(out)
    }

    pub fn save_to_file(&self, file_path: &String) -> Result<()> {
        if self.dirty {
            let mut encoder = flate2::write::GzEncoder::new(
                File::create(file_path)?,
                flate2::Compression::best(),
            );
            encoder.write_all(&serde_json::to_vec(self)?)?;
            encoder.finish()?;
        }

        Ok(())
    }
}

impl Provider for FileProvider {
    fn save(&self) -> Result<()> {
        self.save_to_file(&self.file_path)
    }

    fn get_full_block(&mut self, query: &BlockQuery) -> Result<Block<Transaction>> {
        match self.full_blocks.get(query) {
            Some(val) => Ok(val.clone()),
            None => Err(anyhow!("No data for {:?}", query)),
        }
    }

    fn get_partial_block(&mut self, query: &BlockQuery) -> Result<Block<H256>> {
        match self.partial_blocks.get(query) {
            Some(val) => Ok(val.clone()),
            None => Err(anyhow!("No data for {:?}", query)),
        }
    }

    fn get_proof(&mut self, query: &ProofQuery) -> Result<EIP1186ProofResponse> {
        match self.proofs.get(query) {
            Some(val) => Ok(val.clone()),
            None => Err(anyhow!("No data for {:?}", query)),
        }
    }

    fn get_transaction_count(&mut self, query: &AccountQuery) -> Result<U256> {
        match self.transaction_count.get(query) {
            Some(val) => Ok(*val),
            None => Err(anyhow!("No data for {:?}", query)),
        }
    }

    fn get_balance(&mut self, query: &AccountQuery) -> Result<U256> {
        match self.balance.get(query) {
            Some(val) => Ok(*val),
            None => Err(anyhow!("No data for {:?}", query)),
        }
    }

    fn get_code(&mut self, query: &AccountQuery) -> Result<Bytes> {
        match self.code.get(query) {
            Some(val) => Ok(val.clone()),
            None => Err(anyhow!("No data for {:?}", query)),
        }
    }

    fn get_storage(&mut self, query: &StorageQuery) -> Result<H256> {
        match self.storage.get(query) {
            Some(val) => Ok(*val),
            None => Err(anyhow!("No data for {:?}", query)),
        }
    }

    #[cfg(feature = "taiko")]
    fn get_propose(&mut self, query: &super::ProposeQuery) -> Result<(Transaction, BlockProposed)> {
        match self.propose {
            Some(ref val) => Ok(val.clone()),
            None => Err(anyhow!("No data for {:?}", query)),
        }
    }

    #[cfg(feature = "taiko")]
    fn batch_get_partial_blocks(&mut self, _: &BlockQuery) -> Result<Vec<Block<H256>>> {
        if self.partial_blocks.is_empty() {
            Err(anyhow!("No data for partial blocks"))
        } else {
            Ok(self.partial_blocks.values().cloned().collect())
        }
    }

    #[cfg(feature = "taiko")]
    fn get_blob_data(&mut self, block_id: u64) -> Result<GetBlobsResponse> {
        match self.blobs.get(&block_id) {
            Some(val) => Ok(val.clone()),
            None => Err(anyhow!("No data for block id: {:?}", block_id)),
        }
    }
}

impl MutProvider for FileProvider {
    fn insert_full_block(&mut self, query: BlockQuery, val: Block<Transaction>) {
        self.full_blocks.insert(query, val);
        self.dirty = true;
    }

    fn insert_partial_block(&mut self, query: BlockQuery, val: Block<H256>) {
        self.partial_blocks.insert(query, val);
        self.dirty = true;
    }

    fn insert_proof(&mut self, query: ProofQuery, val: EIP1186ProofResponse) {
        self.proofs.insert(query, val);
        self.dirty = true;
    }

    fn insert_transaction_count(&mut self, query: AccountQuery, val: U256) {
        self.transaction_count.insert(query, val);
        self.dirty = true;
    }

    fn insert_balance(&mut self, query: AccountQuery, val: U256) {
        self.balance.insert(query, val);
        self.dirty = true;
    }

    fn insert_code(&mut self, query: AccountQuery, val: Bytes) {
        self.code.insert(query, val);
        self.dirty = true;
    }

    fn insert_storage(&mut self, query: StorageQuery, val: H256) {
        self.storage.insert(query, val);
        self.dirty = true;
    }

    #[cfg(feature = "taiko")]
    fn insert_propose(&mut self, _query: super::ProposeQuery, val: (Transaction, BlockProposed)) {
        self.propose = Some(val);
        self.dirty = true;
    }

    #[cfg(feature = "taiko")]
    fn insert_blob(&mut self, block_id: u64, val: GetBlobsResponse) {
        self.blobs.insert(block_id, val);
        self.dirty = true;
    }
}
