use alloy_sol_types::sol;

use serde::{Deserialize, Serialize};
sol! {
    /// The public values encoded as a struct that can be easily deserialized inside Solidity.
    struct ETHPublicValuesStruct {
        bytes32 tx_id;  // Record txid prevent re-entry.
        address depositer_address; // Address to send money.
        uint256 amount; // Amount to mint.
        bool is_valid;
    }
}
// Data that retrieved by Bitcoin trx fetch module
#[derive(Serialize, Deserialize, Debug)]
pub struct BitcoinTrxInfoStruct {
    pub tx_id: String,
    pub amount: u64,        // The amount of related vout
    pub to_address: String, // In previous program, we will only store the vout address that related to my account.
    pub confirmations: u32, // Confirmation status
}
// Request Info
#[derive(Serialize, Deserialize, Debug)]
pub struct RequestInfoStruct {
    pub depositer_bit_address: String, // Indicate the bitcoin address of swap requester.
    pub target_deposit_address: String, //This is the unique deposit address that the client needed to send bitcoin to.
    pub depositer_eth_address: String, // Storing in this type for later convert to Solidity compatible type(address).
    pub amount: u64,
}
// Bundle two data into one.
#[derive(Serialize, Deserialize, Debug)]
pub struct BundleInfoStruct {
    pub bit_info: BitcoinTrxInfoStruct,
    pub req_info: RequestInfoStruct,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
// Fixture
pub struct EthProofFixture {
    pub vkey: String,
    pub public_value: String,
    pub proof: String,
}
