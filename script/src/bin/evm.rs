//! An end-to-end example of using the SP1 SDK to generate a proof of a program that can have an
//! EVM-Compatible proof generated which can be verified on-chain.
//!
//! You can run this script using the following command:
//! ```shell
//! RUST_LOG=info cargo run --release --bin evm -- --system groth16
//! ```
//! or
//! ```shell
//! RUST_LOG=info cargo run --release --bin evm -- --system plonk
//! ```
use lib_struct::{BitcoinTrxInfoStruct, BundleInfoStruct, EthProofFixture, RequestInfoStruct};
// ELF file for the Bitcoin transaction verification zkVM program (assumes compiled from your zkVM code)
pub const BITCOIN_VERIFY_ELF: &[u8] = include_elf!("bitcoin_verify_program");

use clap::{Parser, ValueEnum};
use sp1_sdk::{
    include_elf, HashableKey, ProverClient, SP1ProofWithPublicValues, SP1Stdin, SP1VerifyingKey,
};
use std::path::PathBuf;

/// The arguments for the EVM command.
#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct EVMArgs {
    #[clap(long, default_value = "20")]
    n: u32,
    #[clap(long, value_enum, default_value = "groth16")]
    system: ProofSystem,
}

/// Enum representing the available proof systems
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum, Debug)]
enum ProofSystem {
    Plonk,
    Groth16,
}

fn main() {
    // Setup the logger.
    sp1_sdk::utils::setup_logger();

    // Parse the command line arguments.
    let args = EVMArgs::parse();

    // Setup the prover client.
    let client = ProverClient::from_env();

    // Setup the program.
    let (pk, vk) = client.setup(BITCOIN_VERIFY_ELF);

    // Mock Bitcoin transaction input (replace with real Testnet data in practice)
    let mock_tx = BitcoinTrxInfoStruct {
        tx_id: "ea33a83a4121fd47ccba8ed634ffe6c850d95f9a0d37c4613780c2679f816455".into(), // Placeholder txID
        amount: 10000,
        to_address: "tb1qn05lrx8q5tajvnc6lc30sa8fzasjmey6fnl3p0".into(), // 1000 satoshis (0.00001 BTC)
        confirmations: 8,                                                // 6 confirmations
    };
    // Mock Bitcoin transaction input (replace with real Testnet data in practice)
    let mock_req = RequestInfoStruct {
        depositer_bit_address: "ea33a83a4121fd47ccba8ed634ffe6c850d95f9a0d37c4613780c2679f816455"
            .into(), // Placeholder txID
        target_deposit_address: "tb1qn05lrx8q5tajvnc6lc30sa8fzasjmey6fnl3p0".into(), // 1000 satoshis (0.00001 BTC)
        depositer_eth_address: "0xa86Ed347B8D1043533fe30c07Fc47f3E3b849a42".to_string(), // 6 confirmations
        amount: 10000,
    };

    let mut stdin = SP1Stdin::new();
    let bundle_data = BundleInfoStruct {
        bit_info: mock_tx,
        req_info: mock_req,
    };
    stdin.write(&bundle_data);

    println!("Proof System: {:?}", args.system);

    // Generate the proof based on the selected proof system.
    let proof = match args.system {
        ProofSystem::Plonk => client.prove(&pk, &stdin).plonk().run(),
        ProofSystem::Groth16 => client.prove(&pk, &stdin).groth16().run(),
    }
    .expect("failed to generate proof");

    create_proof_fixture(&proof, &vk, args.system);
}

/// Create a fixture for the given proof.
fn create_proof_fixture(
    proof: &SP1ProofWithPublicValues,
    vk: &SP1VerifyingKey,
    system: ProofSystem,
) {
    let bytes = proof.public_values.as_slice();
    // let decoded = ETHPublicValuesStruct::abi_decode(bytes, false).unwrap();

    let fixture = EthProofFixture {
        vkey: vk.bytes32().to_string(),
        public_value: format!("0x{}", hex::encode(bytes)),
        proof: format!("0x{}", hex::encode(proof.bytes())),
    };

    // The verification key is used to verify that the proof corresponds to the execution of the
    // program on the given input.
    //
    // Note that the verification key stays the same regardless of the input.
    println!("Verification Key: {}", fixture.vkey);

    // The public values are the values which are publicly committed to by the zkVM.
    //
    // If you need to expose the inputs or outputs of your program, you should commit them in
    // the public values.
    println!("Public Values: {}", fixture.public_value);

    // The proof proves to the verifier that the program was executed with some inputs that led to
    // the give public values.
    println!("Proof Bytes: {}", fixture.proof);

    // Save the fixture to a file.
    let fixture_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../contracts/src/fixtures");
    std::fs::create_dir_all(&fixture_path).expect("failed to create fixture path");
    std::fs::write(
        fixture_path.join(format!("{:?}-fixture.json", system).to_lowercase()),
        serde_json::to_string_pretty(&fixture).unwrap(),
    )
    .expect("failed to write fixture");
}
