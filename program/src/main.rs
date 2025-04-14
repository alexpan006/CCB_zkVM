#![no_main]
sp1_zkvm::entrypoint!(main);
use alloy_primitives::{address, fixed_bytes, Address, FixedBytes, I256, U256};
use alloy_sol_types::{sol, SolType};
use bitcoin::block::{Header, Version}; // Import Header and Version
use bitcoin::blockdata::script::Script;
use bitcoin::hash_types::Txid; // Use specific hash types
use bitcoin::hash_types::{BlockHash, TxMerkleNode}; // Import specific hash types
use bitcoin::hashes::{sha256d, Hash, HashEngine, Hmac, HmacEngine}; // Import necessary hash traits/types
use bitcoin::Amount;
use bitcoin::Network;
use bitcoin::{consensus::deserialize, Transaction};
use bitcoin::{Address as BitcoinAddress, CompactTarget};
use lib_struct::{
    double_sha256, hex_to_bytes, reverse_hash, BitcoinTrxInfoStruct, Block, BundleInfoStruct,
    Chain, ETHPublicValuesStruct, MerkleProof, RequestInfoStruct,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::error::Error; // For error handling
use std::str::FromStr; // To parse strings into hash types

// Define a struct to hold output information
#[derive(Debug)]
struct OutputInfo {
    address: Option<BitcoinAddress>, // None if address cannot be derived from script
    amount: Amount,                  // Amount in satoshis
}

// Mock struct for Bitcoin transaction data (simplified PoC)

/// Computes the Merkle root from a transaction ID string and its Merkle proof (with string siblings).
/// Uses bitcoin crate types for hashing and byte order.
///
/// # Arguments
/// - `tx_id_str`: The transaction ID as a hexadecimal string (big-endian).
/// - `merkle_proof`: The Merkle proof containing sibling hashes (big-endian hex strings) and position.
///
/// # Returns
/// - `Result<TxMerkleNode, Box<dyn Error>>`: The computed Merkle root as a TxMerkleNode.
fn compute_merkle_root_with_crate(
    tx_id_str: &str,
    merkle_proof: &MerkleProof,
) -> Result<TxMerkleNode, Box<dyn Error>> {
    // 1. Parse the big-endian hex tx_id string into a Txid type.
    // Txid internally stores the hash in the correct little-endian byte order.
    let txid = Txid::from_str(tx_id_str)?;

    // 2. Get the initial hash bytes (correct little-endian order from Txid).
    // Use as_byte_array() which provides direct access to the inner [u8; 32]
    let mut current_hash_bytes: [u8; 32] = *txid.as_byte_array();

    let mut pos = merkle_proof.pos;

    // 3. Iterate through siblings
    for sibling_hex in &merkle_proof.siblings {
        // 4. Parse the big-endian hex sibling string into a TxMerkleNode type.
        // TxMerkleNode also stores the hash in little-endian byte order.
        let sibling_node = TxMerkleNode::from_str(sibling_hex)?;
        let sibling_bytes: [u8; 32] = *sibling_node.as_byte_array();

        // 5. Determine concatenation order based on position
        let (left, right) = if pos % 2 == 0 {
            // Current is left sibling
            (current_hash_bytes, sibling_bytes)
        } else {
            // Current is right sibling
            (sibling_bytes, current_hash_bytes)
        };

        // 6. Concatenate the two 32-byte hashes (already in correct LE order)
        let mut concat = [0u8; 64];
        concat[..32].copy_from_slice(&left);
        concat[32..].copy_from_slice(&right);

        // 7. Compute double SHA-256 using the bitcoin::hashes::sha256d hasher
        // sha256d::Hash::hash performs the double-hash automatically.
        let combined_hash: sha256d::Hash = sha256d::Hash::hash(&concat);

        // 8. Update current hash with the result (still LE)
        current_hash_bytes = *combined_hash.as_byte_array();

        // 9. Move up the tree
        pos >>= 1;
    }

    // 10. Construct the final TxMerkleNode from the resulting bytes
    Ok(TxMerkleNode::from_byte_array(current_hash_bytes))
}

/// Verifies transaction inclusion by computing the Merkle root and comparing it to a target root string.
///
/// # Arguments
/// - `tx_id_str`: The transaction ID as a hexadecimal string (big-endian).
/// - `merkle_proof`: The Merkle proof object.
/// - `target_root_str`: The expected Merkle root as a hexadecimal string (big-endian).
///
/// # Returns
/// - `Result<bool, Box<dyn Error>>`: Ok(true) if the computed root matches the target, Ok(false) otherwise, or Err on failure.
pub fn verify_tx_inclusion_str(
    tx_id_str: &str,
    merkle_proof: &MerkleProof,
    target_root_str: &str,
) -> Result<bool, Box<dyn Error>> {
    // Compute the Merkle root using the refactored function
    let computed_root: TxMerkleNode = compute_merkle_root_with_crate(tx_id_str, merkle_proof)?;

    // Parse the target Merkle root string (big-endian hex) into TxMerkleNode
    let target_root: TxMerkleNode = TxMerkleNode::from_str(target_root_str)?;
    // Compare the computed root with the target root.
    // The comparison is done correctly based on the internal byte representation.
    Ok(computed_root == target_root)
}

// Function to extract recipients and amounts from a transaction
fn get_recipients_and_amounts(tx: &Transaction) -> Vec<OutputInfo> {
    tx.output
        .iter()
        .map(|output| {
            let amount = output.value; // Amount in satoshis
            let address = BitcoinAddress::from_script(&output.script_pubkey, Network::Testnet).ok();
            OutputInfo { address, amount }
        })
        .collect()
}

// Function to check for a matching output
fn has_matching_output(tx: &Transaction, req_info: &RequestInfoStruct) -> bool {
    let outputs = get_recipients_and_amounts(tx);

    // Parse the target address once
    let target_addr = BitcoinAddress::from_str(&req_info.target_deposit_address)
        .unwrap()
        .require_network(Network::Testnet)
        .unwrap();

    // Compare each output to the target address and amount
    for output in outputs {
        // println!("Output Address: {:?}", output.address);
        // println!("Output Amount: {:?}", output.amount);
        // println!("Target Address: {:?}", target_addr);
        // println!("Target Amount: {:?}", req_info.amount);
        // println!("-----------------------------------");
        if let Some(addr) = &output.address {
            if *addr == target_addr && output.amount == Amount::from_sat(req_info.amount) {
                return true; // Match found
            }
        }
    }
    false // No match found
}

/// Verifies the integrity and linkage of a chain of exactly 7 blocks using bitcoin crate types.
pub fn verify_chain_with_crate(chain: &Chain) -> Result<(), Box<dyn Error>> {
    // Rule 1: Check for exactly 7 blocks
    if chain.blocks.len() != 7 {
        return Err(format!(
            "Chain validation failed: Expected exactly 7 blocks, found {}",
            chain.blocks.len()
        )
        .into());
    }

    let mut computed_hashes: Vec<BlockHash> = Vec::with_capacity(7);

    for (i, user_block) in chain.blocks.iter().enumerate() {
        // Parse string hashes into Bitcoin crate types
        let expected_block_hash = BlockHash::from_str(&user_block.block_hash)?;
        let prev_blockhash = BlockHash::from_str(&user_block.parent_hash)?;
        let merkle_root = TxMerkleNode::from_str(&user_block.merkle_root)?;

        // Construct the bitcoin::block::Header from the user's Block struct fields
        // Note: bitcoin::block::Version takes an i32. Casting u32->i32 is usually safe for version numbers.
        let current_header = Header {
            version: Version::from_consensus(user_block.version as i32), // Correct construction
            prev_blockhash,
            merkle_root,
            time: user_block.timestamp,
            bits: CompactTarget::from_consensus(user_block.difficulty), // Maps to 'bits' field in Header
            nonce: user_block.nonce,
        };
        // Rule 2a: Verify block hash integrity
        let computed_block_hash = current_header.block_hash(); // Computes double-sha256
        if computed_block_hash != expected_block_hash {
            return Err(format!(
                "Chain validation failed at block index {}: Computed hash {} does not match provided block_hash {}",
                i, computed_block_hash, expected_block_hash
            ).into());
        }

        // Store the computed hash for the next iteration's linkage check
        computed_hashes.push(computed_block_hash);

        // Rule 2b: Verify chain linkage (skip for the first block)
        if i > 0 {
            let prev_computed_hash = computed_hashes[i - 1]; // Get the previously computed hash

            // Compare the previous block's computed hash with the current block's parent_hash field
            // We use current_header.prev_blockhash which was parsed from user_block.parent_hash
            if current_header.prev_blockhash != prev_computed_hash {
                return Err(format!(
                    "Chain validation failed at block index {}: Parent hash {} does not match previous block's computed hash {}",
                    i, current_header.prev_blockhash, prev_computed_hash
                ).into());
            }
        }
        // Note: Add specific genesis block validation here if needed (e.g., check parent hash is all zeros)
    }

    // If all checks passed for all 7 blocks
    Ok(())
}
pub fn main() {
    let bundle: BundleInfoStruct = sp1_zkvm::io::read();

    // Extract the transaction detail from raw hex
    let tx_bytes = hex::decode(&bundle.bit_tx_info.raw_tx_hex).unwrap();
    // Step 2: Parse the bytes into a Bitcoin Transaction
    let tx: Transaction = deserialize(&tx_bytes).unwrap();
    // Step 3: Check if the output index is valid
    let txid = tx.compute_txid();
    println!("Transaction ID: {}", txid);

    // First, verify transaction against the request info
    match has_matching_output(&tx, &bundle.req_info) {
        true => println!("Transaction matches the request info"),
        false => panic!("Transaction does not match the request info"),
    }

    // Verify the tx is included in the merkle proof
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

    // parse_and_check_amount(&bundle.bit_tx_info.raw_tx_hex, 0, 0).unwrap();

    // // Verify the transaction
    // let result = verify_bitcoin_tx(&bundle.bit_info, &bundle.req_info);
    let bytes = ETHPublicValuesStruct::abi_encode(&ETHPublicValuesStruct {
        tx_id: txid.to_string().as_str().parse::<FixedBytes<32>>().unwrap(),
        depositer_address: Address::parse_checksummed(bundle.req_info.depositer_eth_address, None)
            .unwrap(),
        amount: U256::from(bundle.req_info.amount),
        is_valid: true,
    });
    // // println!("The total bytes:{:?}", &bytes);
    // // Commit the public values for zkSync verification
    sp1_zkvm::io::commit_slice(&bytes);
}
