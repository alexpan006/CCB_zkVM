#![no_main]
sp1_zkvm::entrypoint!(main);

use alloy_primitives::{Address, FixedBytes, U256};
use alloy_sol_types::SolType;
use bitcoin::block::{Header, Version};
use bitcoin::consensus::deserialize;
use bitcoin::hash_types::{BlockHash, TxMerkleNode, Txid};
use bitcoin::hashes::hex::FromHex;
use bitcoin::hashes::{sha256d, Hash};
use bitcoin::network::Network;
use bitcoin::opcodes;
use bitcoin::script::Instruction;
use bitcoin::Amount;
use bitcoin::Transaction;
use bitcoin::TxOut;
use bitcoin::{Address as BitcoinAddress, CompactTarget};
use lib_struct::{BundleInfoStruct, Chain, MerkleProof, ZkpMintPublicValuesStruct};
use std::error::Error;
use std::str::FromStr;

/// The deposit address that the bridge monitors for incoming funds.
const BRIDGE_ADDRESS: &str = "tb1qzfqwyxc70pmlw7l7vmx9nmhmqtgh5z3lp3j9hf";
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

/// Processes transaction outputs to:
/// - Sum the value sent to a specific address.
/// - Extract the first OP_RETURN memo (if present).
fn process_transaction_outputs(
    raw_hex: &str,
    my_address_str: &str,
    network: Network,
) -> Result<(u64, Option<Vec<u8>>), Box<dyn Error>> {
    let tx_bytes =
        Vec::<u8>::from_hex(raw_hex).map_err(|e| format!("Failed to decode raw hex: {}", e))?;
    let tx: Transaction = deserialize(&tx_bytes)?;

    let my_address = BitcoinAddress::from_str(my_address_str)
        .unwrap()
        .require_network(network)
        .unwrap();

    let mut total_value_to_me: u64 = 0;
    let mut op_return_data: Option<Vec<u8>> = None;

    for output in &tx.output {
        // Extract OP_RETURN memo if present (only the first one)
        if output.script_pubkey.is_op_return() {
            if op_return_data.is_none() {
                let mut instructions = output.script_pubkey.instructions();
                if let Some(Ok(Instruction::Op(opcodes::all::OP_RETURN))) = instructions.next() {
                    if let Some(Ok(Instruction::PushBytes(data))) = instructions.next() {
                        op_return_data = Some(data.as_bytes().to_vec());
                    }
                }
            }
            continue;
        }

        // Sum value sent to the monitored address
        if let Ok(derived_address) = BitcoinAddress::from_script(&output.script_pubkey, network) {
            if derived_address == my_address {
                total_value_to_me = total_value_to_me.saturating_add(Amount::to_sat(output.value));
            }
        }
    }

    Ok((total_value_to_me, op_return_data))
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

        // Check block hash correctness
        let computed_block_hash = current_header.block_hash();
        if computed_block_hash != expected_block_hash {
            return Err(format!(
                "Chain validation failed at block index {}: Computed hash {} does not match provided block_hash {}",
                i, computed_block_hash, expected_block_hash
            ).into());
        }

        computed_hashes.push(computed_block_hash);

        // Check parent linkage (skip for the first block)
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

/// zkVM entrypoint: verifies a Bitcoin deposit and prepares public values for minting.
pub fn main() {
    // Read input bundle from zkVM host
    let bundle: BundleInfoStruct = sp1_zkvm::io::read();

    // Parse the Bitcoin transaction from raw hex
    let tx_bytes = hex::decode(&bundle.bit_tx_info.raw_tx_hex).unwrap();
    let tx: Transaction = deserialize(&tx_bytes).unwrap();
    let txid = tx.compute_txid();
    println!("Transaction ID: {}", txid);

    // Extract total deposited amount and OP_RETURN memo (Ethereum address)
    let (total_sats_to_me, memo_bytes) =
        process_transaction_outputs(&bundle.bit_tx_info.raw_tx_hex, BRIDGE_ADDRESS, NETWORK_TYPE)
            .unwrap();

    println!(
        "Total satoshis sent to {}: {}",
        BRIDGE_ADDRESS, total_sats_to_me
    );

    // Parse the OP_RETURN memo as the depositor's Ethereum address
    let deposit_eth_address: String = if let Some(bytes) = memo_bytes {
        match String::from_utf8(bytes.clone()) {
            Ok(memo_str) => {
                println!("Found OP_RETURN memo (UTF-8): {}", memo_str);
                memo_str
            }
            Err(_) => {
                println!("Found OP_RETURN memo (Hex): {}", hex::encode(bytes));
                panic!("Memo is not valid UTF-8");
            }
        }
    } else {
        println!("No valid OP_RETURN memo found in this transaction.");
        panic!("No OP_RETURN memo found");
    };

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

    // Prepare and commit public values for the zk proof
    let bytes = ZkpMintPublicValuesStruct::abi_encode(&ZkpMintPublicValuesStruct {
        tx_id: txid.to_string().as_str().parse::<FixedBytes<32>>().unwrap(),
        depositer_address: Address::parse_checksummed(deposit_eth_address, None).unwrap(),
        amount: U256::from(total_sats_to_me),
        is_valid: true,
    });

    sp1_zkvm::io::commit_slice(&bytes);
}
