#![no_main]
sp1_zkvm::entrypoint!(main);
use alloy_primitives::U256;
use alloy_sol_types::sol_data::String as SolString;
// use alloy_sol_types::SolType;
use alloy_sol_types::SolType;
use bitcoin::block::{Header, Version};
use bitcoin::consensus::deserialize;
use bitcoin::hash_types::{BlockHash, TxMerkleNode, Txid};
use bitcoin::hashes::hex::FromHex;
use bitcoin::hashes::{sha256d, Hash};
use bitcoin::network::Network;
use bitcoin::Amount;
use bitcoin::Transaction;
use bitcoin::{Address as BitcoinAddress, CompactTarget};
use lib_struct::{BundleInfoStruct, Chain, MerkleProof, ZkpBurnPublicValuesStruct};
use std::error::Error;
use std::str::FromStr;

/// The Bitcoin network type (Testnet in this example).
const NETWORK_TYPE: Network = Network::Testnet;

/// Computes the Merkle root from a transaction ID and its Merkle proof.
/// Returns the computed Merkle root as a TxMerkleNode.
fn compute_merkle_root_with_crate(
    tx_id_str: &str,
    merkle_proof: &MerkleProof,
) -> Result<TxMerkleNode, Box<dyn Error>> {
    let txid = Txid::from_str(tx_id_str)?;
    let mut current_hash_bytes: [u8; 32] = *txid.as_byte_array();
    let mut pos = merkle_proof.pos;

    for sibling_hex in &merkle_proof.siblings {
        let sibling_node = TxMerkleNode::from_str(sibling_hex)?;
        let sibling_bytes: [u8; 32] = *sibling_node.as_byte_array();

        let (left, right) = if pos % 2 == 0 {
            (current_hash_bytes, sibling_bytes)
        } else {
            (sibling_bytes, current_hash_bytes)
        };

        let mut concat = [0u8; 64];
        concat[..32].copy_from_slice(&left);
        concat[32..].copy_from_slice(&right);

        let combined_hash: sha256d::Hash = sha256d::Hash::hash(&concat);
        current_hash_bytes = *combined_hash.as_byte_array();
        pos >>= 1;
    }

    Ok(TxMerkleNode::from_byte_array(current_hash_bytes))
}

/// Verifies that a transaction is included in a block by comparing the computed Merkle root
/// (from the transaction ID and Merkle proof) to the block's Merkle root.
pub fn verify_tx_inclusion_str(
    tx_id_str: &str,
    merkle_proof: &MerkleProof,
    target_root_str: &str,
) -> Result<bool, Box<dyn Error>> {
    let computed_root: TxMerkleNode = compute_merkle_root_with_crate(tx_id_str, merkle_proof)?;
    let target_root: TxMerkleNode = TxMerkleNode::from_str(target_root_str)?;
    Ok(computed_root == target_root)
}

/// Sums the value sent to a specific Bitcoin address in a transaction's outputs.
fn sum_outputs_to_address(
    raw_hex: &str,
    target_address_str: &str,
    network: Network,
) -> Result<u64, Box<dyn Error>> {
    let tx_bytes =
        Vec::<u8>::from_hex(raw_hex).map_err(|e| format!("Failed to decode raw hex: {}", e))?;
    let tx: Transaction = deserialize(&tx_bytes)?;

    let target_address = BitcoinAddress::from_str(target_address_str)
        .unwrap()
        .require_network(network)
        .unwrap();

    let mut total_value: u64 = 0;

    for output in &tx.output {
        if let Ok(derived_address) = BitcoinAddress::from_script(&output.script_pubkey, network) {
            if derived_address == target_address {
                total_value = total_value.saturating_add(Amount::to_sat(output.value));
            }
        }
    }

    Ok(total_value)
}

/// Verifies the integrity and linkage of a chain of blocks.
/// Checks block hash correctness and parent linkage.
pub fn verify_chain_with_crate(chain: &Chain) -> Result<(), Box<dyn Error>> {
    if chain.blocks.len() != 6 {
        return Err(format!(
            "Chain validation failed: Expected exactly 7 blocks, found {}",
            chain.blocks.len()
        )
        .into());
    }

    let mut computed_hashes: Vec<BlockHash> = Vec::with_capacity(6);

    for (i, user_block) in chain.blocks.iter().enumerate() {
        let expected_block_hash = BlockHash::from_str(&user_block.block_hash)?;
        let prev_blockhash = BlockHash::from_str(&user_block.parent_hash)?;
        let merkle_root = TxMerkleNode::from_str(&user_block.merkle_root)?;

        let current_header = Header {
            version: Version::from_consensus(user_block.version as i32),
            prev_blockhash,
            merkle_root,
            time: user_block.timestamp,
            bits: CompactTarget::from_consensus(user_block.difficulty),
            nonce: user_block.nonce,
        };

        let computed_block_hash = current_header.block_hash();
        if computed_block_hash != expected_block_hash {
            return Err(format!(
                "Chain validation failed at block index {}: Computed hash {} does not match provided block_hash {}",
                i, computed_block_hash, expected_block_hash
            ).into());
        }

        computed_hashes.push(computed_block_hash);

        if i > 0 {
            let prev_computed_hash = computed_hashes[i - 1];
            if current_header.prev_blockhash != prev_computed_hash {
                return Err(format!(
                    "Chain validation failed at block index {}: Parent hash {} does not match previous block's computed hash {}",
                    i, current_header.prev_blockhash, prev_computed_hash
                ).into());
            }
        }
    }

    Ok(())
}

/// Manually ABI-encodes the tuple (string burner_btc_address, uint256 amount, bool is_valid)
/// according to Solidity's ABI spec.
///
/// # Layout:
/// head (3 slots):
///   [0] offset to start of string data = 3 * 32 = 96
///   [1] amount (uint256)
///   [2] is_valid (bool as uint256)
/// tail:
///   [3] string length (uint256)
///   [4+] string bytes (padded to 32-byte boundary)
///
/// # Parameters
/// - `burner_btc_address`: the UTF-8 Bitcoin address string
/// - `amount`: the amount to encode (u64)
/// - `is_valid`: whether the proof is valid (bool)
pub fn abi_encode_zkp_burn(burner_btc_address: &str, amount: u64, is_valid: bool) -> Vec<u8> {
    let mut encoded = Vec::new();

    // 1) Head slot 0: offset to dynamic string = 3 * 32 = 96
    let offset_bytes: [u8; 32] = U256::from(96u64).to_be_bytes();
    encoded.extend_from_slice(&offset_bytes);

    // 2) Head slot 1: amount as uint256
    let amount_bytes: [u8; 32] = U256::from(amount).to_be_bytes();
    encoded.extend_from_slice(&amount_bytes);

    // 3) Head slot 2: is_valid as 0 or 1 in uint256
    let valid_u256 = if is_valid { U256::ONE } else { U256::ZERO };
    let valid_bytes: [u8; 32] = valid_u256.to_be_bytes();
    encoded.extend_from_slice(&valid_bytes);

    // Tail: dynamic string data
    let s_bytes = burner_btc_address.as_bytes();

    // 4) Length prefix
    let len_bytes: [u8; 32] = U256::from(s_bytes.len() as u64).to_be_bytes();
    encoded.extend_from_slice(&len_bytes);

    // 5) Actual string bytes
    encoded.extend_from_slice(s_bytes);

    // 6) Padding for string data to 32-byte boundary
    let rem = s_bytes.len() % 32;
    if rem != 0 {
        let pad_len = 32 - rem;
        encoded.extend(std::iter::repeat(0u8).take(pad_len));
    }

    encoded
}
/// zkVM entrypoint: verifies a Bitcoin burn and prepares public values for proof.
///
/// This circuit proves, in zero-knowledge, that a Bitcoin transaction sent funds to a
/// specific burner address, is included in a valid chain of blocks, and the burned amount
/// is correctly extracted and committed as a public value.
pub fn main() {
    // Read input bundle from zkVM host
    let bundle: BundleInfoStruct = sp1_zkvm::io::read();

    // Extract the burner BTC address from the bundle
    let burner_btc_address = &bundle
        .burner_btc_address
        .as_ref()
        .expect("Burner BTC address must be provided");

    // Parse the Bitcoin transaction from raw hex
    let tx_bytes = hex::decode(&bundle.bit_tx_info.raw_tx_hex).unwrap();
    let tx: Transaction = deserialize(&tx_bytes).unwrap();
    let txid = tx.compute_txid();
    println!("Transaction ID: {}", txid);

    // Sum the total amount sent to the burner address
    let total_sats_to_burner = sum_outputs_to_address(
        &bundle.bit_tx_info.raw_tx_hex,
        burner_btc_address,
        NETWORK_TYPE,
    )
    .unwrap();

    println!(
        "Total satoshis sent to burner address {}: {}",
        burner_btc_address, total_sats_to_burner
    );

    // Verify transaction inclusion in the block's Merkle root
    match verify_tx_inclusion_str(
        txid.to_string().as_str(),
        &bundle.merkle_proof,
        &bundle.chains.blocks[0].merkle_root,
    ) {
        Ok(true) => println!("Transaction inclusion verified successfully"),
        Ok(false) => panic!("Merkle root mismatch"),
        Err(e) => panic!("Verification failed: {}", e),
    }

    // Verify the chain of blocks
    match verify_chain_with_crate(&bundle.chains) {
        Ok(_) => println!("Chain verified successfully"),
        Err(e) => panic!("Chain verification failed: {}", e),
    }

    // // Prepare and commit public values for the zk proof
    // let bytes = ZkpBurnPublicValuesStruct::abi_encode(&ZkpBurnPublicValuesStruct {
    //     burner_btc_address: burner_btc_address.to_string(),
    //     amount: U256::from(total_sats_to_burner),
    //     is_valid: true,
    // });
    let payload = abi_encode_zkp_burn(burner_btc_address, total_sats_to_burner, true);
    println!("Encoded public values: {}", hex::encode(&payload));
    sp1_zkvm::io::commit_slice(&payload);
}
