#![no_main]
sp1_zkvm::entrypoint!(main);
use alloy_primitives::{Address, FixedBytes, U256};
use alloy_sol_types::SolType;
use bitcoin::block::{Header, Version}; // Import Header and Version
use bitcoin::consensus::deserialize;
use bitcoin::hash_types::Txid; // Use specific hash types
use bitcoin::hash_types::{BlockHash, TxMerkleNode}; // Import specific hash types
use bitcoin::hashes::hex::FromHex; // For hex decoding
use bitcoin::hashes::{sha256d, Hash}; // Import necessary hash traits/types
use bitcoin::network::Network;
use bitcoin::opcodes; // For OP_RETURN opcode check
use bitcoin::script::Instruction; // For script parsing
use bitcoin::Amount;
use bitcoin::Transaction;
use bitcoin::TxOut;
use bitcoin::{Address as BitcoinAddress, CompactTarget};
use lib_struct::{BundleInfoStruct, Chain, MerkleProof, ZkpMintPublicValuesStruct};

use std::error::Error; // For error handling
use std::str::FromStr; // To parse strings into hash types
                       // Define a struct to hold output information

const BRIDGE_ADDRESS: &str = "tb1qzfqwyxc70pmlw7l7vmx9nmhmqtgh5z3lp3j9hf"; // Example deposit address
const NETWORK_TYPE: Network = Network::Testnet; // Example network type
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

/// Processes transaction outputs to sum value sent to a specific address
/// and extract data from the first OP_RETURN output found.
///
/// # Arguments
/// - `raw_hex`: The raw transaction hexadecimal string.
/// - `my_address_str`: The recipient Bitcoin address to track (as a string).
/// - `network`: The Bitcoin network (e.g., Testnet, Bitcoin).
///
/// # Returns
/// - `Result<(u64, Option<Vec<u8>>), Box<dyn Error>>`: A tuple containing:
///   - The total value (in satoshis) sent to `my_address_str`.
///   - An `Option<Vec<u8>>` containing the raw bytes from the first OP_RETURN data push, if found.
fn process_transaction_outputs(
    raw_hex: &str,
    my_address_str: &str,
    network: Network,
) -> Result<(u64, Option<Vec<u8>>), Box<dyn Error>> {
    // 1. Decode hex and deserialize transaction
    // Use Vec::from_hex which comes from bitcoin::hashes::hex::FromHex trait
    let tx_bytes =
        Vec::<u8>::from_hex(raw_hex).map_err(|e| format!("Failed to decode raw hex: {}", e))?;
    let tx: Transaction = deserialize(&tx_bytes)?;

    // 2. Parse the target "my" address string into an Address type once
    // This will error out if the address string is invalid for the network.
    // let my_address = Address::from_str(my_address_str)?.require_network(network)?; // Ensure address matches the specified network

    let my_address = BitcoinAddress::from_str(my_address_str)
        .unwrap()
        .require_network(network)
        .unwrap();

    // 3. Initialize accumulators
    let mut total_value_to_me: u64 = 0;
    let mut op_return_data: Option<Vec<u8>> = None; // Store bytes of first OP_RETURN

    // 4. Iterate through all transaction outputs
    for output in &tx.output {
        // 5. Check for OP_RETURN output (Objective 1)
        // script_pubkey typically starts with 0x6a for OP_RETURN
        if output.script_pubkey.is_op_return() {
            // Only attempt to extract data if we haven't found an OP_RETURN memo yet
            if op_return_data.is_none() {
                // Use the script instruction iterator for robust parsing
                let mut instructions = output.script_pubkey.instructions();
                // The first instruction should be OP_RETURN itself
                if let Some(Ok(Instruction::Op(opcodes::all::OP_RETURN))) = instructions.next() {
                    // The *next* instruction should be the data push
                    if let Some(Ok(Instruction::PushBytes(data))) = instructions.next() {
                        // data is bitcoin::script::PushBytes, get raw bytes using .as_bytes()
                        op_return_data = Some(data.as_bytes().to_vec());
                    }
                    // If there's no data push after OP_RETURN, op_return_data remains None
                }
                // Handle potential errors from instructions.next() if needed
            }
            // Once identified as OP_RETURN, skip to the next output
            // (we don't check address/value for OP_RETURN)
            continue;
        }

        // 6. Check if the output is addressed to "my address" (Objective 2)
        // Try to derive an address from the scriptPubKey.
        // Address::from_script handles P2PKH, P2SH, P2WPKH, P2WSH, P2TR etc.
        // It will return Err for non-standard scripts (like OP_RETURN, handled above)
        // or scripts it cannot parse into a standard address form.
        if let Ok(derived_address) = BitcoinAddress::from_script(&output.script_pubkey, network) {
            // Compare the derived address with "my" address
            if derived_address == my_address {
                // If it matches, add the output's value to the total
                // Use saturating_add to prevent overflow panic, though unlikely with u64
                total_value_to_me = total_value_to_me.saturating_add(Amount::to_sat(output.value));
            }
        }
        // Ignore outputs that couldn't be parsed into a standard address or don't match
    }

    // 7. Return the total accumulated value and any found OP_RETURN data
    Ok((total_value_to_me, op_return_data))
}

/// Finds and extracts the data bytes from the first valid OP_RETURN output in a slice.
/// A valid OP_RETURN output per standardness rules consists of OP_RETURN
/// followed immediately by a single data push opcode (OP_PUSHBYTES_N or OP_PUSHDATA{1,2,4}).
///
/// # Arguments
/// - `outputs`: A slice of transaction outputs (`&[TxOut]`).
///
/// # Returns
/// - `Option<Vec<u8>>`: The raw data bytes from the first valid OP_RETURN data push, or None.
fn find_op_return_memo(outputs: &[TxOut]) -> Option<Vec<u8>> {
    for output in outputs {
        // Use the efficient check provided by the script module
        if output.script_pubkey.is_op_return() {
            // If it might be OP_RETURN, parse instructions to confirm structure and extract data
            let mut instructions = output.script_pubkey.instructions();
            // Expect OP_RETURN opcode first
            if let Some(Ok(Instruction::Op(opcodes::all::OP_RETURN))) = instructions.next() {
                // Expect *only* a data push next
                if let Some(Ok(Instruction::PushBytes(data))) = instructions.next() {
                    // Check that there are NO more instructions after the data push
                    if instructions.next().is_none() {
                        // Found a standard, valid OP_RETURN output with data. Return it.
                        return Some(data.as_bytes().to_vec());
                    }
                }
                // If the structure wasn't OP_RETURN + single data push + END,
                // it's not a standard/valid OP_RETURN for our purposes.
                // We typically only care about the first one found.
                // If the first one is malformed, we return None.
                return None;
            }
            // If parsing fails or structure is wrong after is_op_return() was true,
            // treat it as non-standard/malformed.
            return None; // Or continue the loop if multiple OP_RETURNS could exist (non-standard)
                         // Sticking to finding the first one and checking its validity.
        }
    }
    // No output started with OP_RETURN or the first one found was malformed
    None
}

/// Verifies the integrity and linkage of a chain of exactly 7 blocks using bitcoin crate types.
pub fn verify_chain_with_crate(chain: &Chain) -> Result<(), Box<dyn Error>> {
    // Rule 1: Check for exactly 7 blocks
    if chain.blocks.len() != 6 {
        return Err(format!(
            "Chain validation failed: Expected exactly 7 blocks, found {}",
            chain.blocks.len()
        )
        .into());
    }

    let mut computed_hashes: Vec<BlockHash> = Vec::with_capacity(6);

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

    // Verify the transaction given the raw hex. Extract the total amount deposited to the DEPOSIT_ADDRESS, and extract the memo.
    let (total_sats_to_me, memo_bytes) =
        process_transaction_outputs(&bundle.bit_tx_info.raw_tx_hex, BRIDGE_ADDRESS, NETWORK_TYPE)
            .unwrap();

    // --- Output Results ---
    println!(
        "Total satoshis sent to {}: {}",
        BRIDGE_ADDRESS, total_sats_to_me
    );
    let deposit_eth_address: String;
    // Handle displaying the memo
    if let Some(bytes) = memo_bytes {
        match String::from_utf8(bytes.clone()) {
            // Clone bytes for UTF-8 check
            Ok(memo_str) => {
                println!("Found OP_RETURN memo (UTF-8): {}", memo_str);
                deposit_eth_address = memo_str;
            }
            Err(_) => {
                println!("Found OP_RETURN memo (Hex): {}", hex::encode(bytes));
                panic!("Memo is not valid UTF-8");
            } // Display as hex if not UTF-8
        }
    } else {
        println!("No valid OP_RETURN memo found in this transaction.");
        panic!("No OP_RETURN memo found");
    }
    // --- End Output Results ---

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
    let bytes = ZkpMintPublicValuesStruct::abi_encode(&ZkpMintPublicValuesStruct {
        tx_id: txid.to_string().as_str().parse::<FixedBytes<32>>().unwrap(),
        depositer_address: Address::parse_checksummed(deposit_eth_address, None).unwrap(),
        amount: U256::from(total_sats_to_me),
        is_valid: true,
    });
    // // println!("The total bytes:{:?}", &bytes);
    // // Commit the public values for zkSync verification
    sp1_zkvm::io::commit_slice(&bytes);
}
