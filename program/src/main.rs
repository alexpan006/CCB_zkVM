#![no_main]
sp1_zkvm::entrypoint!(main);
use alloy_primitives::{address, fixed_bytes, Address, FixedBytes, I256, U256};
use alloy_sol_types::{sol, SolType};
use lib_struct::{
    BitcoinTrxInfoStruct, BundleInfoStruct, ETHPublicValuesStruct, RequestInfoStruct,
};
use serde::{Deserialize, Serialize};

// Mock struct for Bitcoin transaction data (simplified PoC)
#[derive(Deserialize, Serialize, Debug)]
struct BitcoinTx {
    tx_id: [u8; 32],
    amount: u64,
    address: String, // Add destination address for verification
    signatures: Vec<String>,
    confirmations: u32,
    sequence: u32, // Add for RBF check
}

// Verify a Bitcoin transaction (mocked for PoC)
fn verify_bitcoin_tx(tx_info: &BitcoinTrxInfoStruct, tx_req: &RequestInfoStruct) -> bool {
    // Check 1: Amount Check
    print!("The amount is{} and {}", tx_info.amount, tx_req.amount);
    if tx_info.amount != tx_req.amount {
        return false;
    }
    // Check 2: Aaddress Check if the vout is our bitcoin address.
    if tx_info.to_address != tx_req.target_deposit_address {
        return false;
    }
    // Check 3: confirmations needs to be at least 6
    if tx_info.confirmations < 6 {
        return false;
    }
    true
}

pub fn main() {
    // Read Bitcoin transaction as bytes and deserialize (PoC assumes struct input)
    // let tx_bytes = sp1_zkvm::io::read_vec();
    // let tx: BitcoinTx = deserialize(&tx_bytes).expect("Failed to deserialize tx");

    // let (tx_data, req_data): (BitcoinTrxInfoStruct, RequestInfoStruct) = sp1_zkvm::io::read();
    let bundle: BundleInfoStruct = sp1_zkvm::io::read();
    println!("Hello from the VM:{:?}", bundle);

    // Verify the transaction
    let result = verify_bitcoin_tx(&bundle.bit_info, &bundle.req_info);
    println!("The result is :{:?}", result);
    // let tx_id_fixed = FixedBytes::from(&tx_data.tx_id);
    // Prepare public values
    // let public_values = MyPublicValuesStruct {
    //     tx_id: tx_id_fixed,
    //     is_valid: result,
    // };

    // // Encode the public values of the program.
    let bytes = ETHPublicValuesStruct::abi_encode(&ETHPublicValuesStruct {
        tx_id: bundle.bit_info.tx_id.parse::<FixedBytes<32>>().unwrap(),
        depositer_address: Address::parse_checksummed(bundle.req_info.depositer_eth_address, None)
            .unwrap(),
        amount: U256::from(bundle.req_info.amount),
        is_valid: result,
    });
    // Commit the public values for zkSync verification
    sp1_zkvm::io::commit(&bytes);
}
