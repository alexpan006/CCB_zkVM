use alloy_sol_types::sol;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::error::Error;
sol! {
    /// The public values encoded as a struct that can be easily deserialized inside Solidity.
    struct ZkpMintPublicValuesStruct {
        bytes32 tx_id;  // Record txid prevent re-entry.
        address depositer_address; // Address to send money.
        uint256 amount; // Amount to mint.
        bool is_valid;
    }
}
sol! {
    /// The public values encoded as a struct that can be easily deserialized inside Solidity.
    struct ZkpBurnPublicValuesStruct {
        string burner_btc_address; // Address to send money.
        uint256 amount; // Amount to mint.
        bool is_valid;
    }
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct Chain {
    pub blocks: Vec<Block>, // Blocks from B_start to B_end
}
#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct Block {
    pub block_hash: String,
    pub version: u32,        // Block version number
    pub parent_hash: String, // Hash of the previous block
    pub merkle_root: String, // Merkle root of transactions
    pub timestamp: u32,      // Block creation time
    pub difficulty: u32,     // Difficulty target
    pub nonce: u32,          // Proof-of-work nonce
}
#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
/// Represents a Merkle proof for a transaction in a Bitcoin block.
pub struct MerkleProof {
    pub siblings: Vec<String>,
    /// 0-based position of the transaction in the block.
    pub pos: u32,
}

// Data that retrieved by Bitcoin trx fetch module
#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct BitcoinTrxInfoStruct {
    pub raw_tx_hex: String, // The amount of related vout
}
// Request Info
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct RequestInfoStruct {
    pub depositer_bit_address: String, // Indicate the bitcoin address of swap requester.
    pub target_deposit_address: String, //This is the unique deposit address that the client needed to send bitcoin to.
    pub depositer_eth_address: String, // Storing in this type for later convert to Solidity compatible type(address).
    pub amount: u64,
}
// Bundle two data into one.
#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct BundleInfoStruct {
    pub merkle_proof: MerkleProof,
    pub chains: Chain,
    pub bit_tx_info: BitcoinTrxInfoStruct,
    pub burner_btc_address: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
// Fixture
pub struct ZkpProofFixture {
    pub vkey: String,
    pub public_value: String,
    pub proof: String,
}

/// Helper function to convert a hex string to a 32-byte array.
pub fn hex_to_bytes(hex_str: &str) -> Result<[u8; 32], Box<dyn Error>> {
    let bytes = hex::decode(hex_str)?;
    if bytes.len() != 32 {
        return Err("Hash must be 32 bytes".into());
    }
    let mut array = [0u8; 32];
    array.copy_from_slice(&bytes);
    Ok(array)
}

/// Helper function to compute double SHA-256 of input data.
pub fn double_sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let first_hash = hasher.finalize();
    let mut hasher = Sha256::new();
    hasher.update(first_hash);
    let second_hash = hasher.finalize();
    second_hash.into()
}

/// Helper function to reverse the byte order of a 32-byte hash.
pub fn reverse_hash(hash: [u8; 32]) -> [u8; 32] {
    let mut reversed = [0u8; 32];
    for i in 0..32 {
        reversed[i] = hash[31 - i];
    }
    reversed
}
