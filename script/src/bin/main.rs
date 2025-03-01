//! Script to execute or prove Bitcoin transaction verification using SP1 zkVM for the cross-chain bridge.
//! Run with:
//! - Execution: `RUST_LOG=info cargo run --release -- --execute`
//! - Proving: `RUST_LOG=info cargo run --release -- --prove`

use clap::Parser;
use sp1_sdk::{include_elf, ProverClient, SP1Stdin};

// ELF file for the Bitcoin transaction verification zkVM program (assumes compiled from your zkVM code)
pub const BITCOIN_VERIFY_ELF: &[u8] = include_elf!("bitcoin_verify");

// Structs for Bitcoin transaction data and public values (mirroring zkVM pseudocode)
#[derive(bincode::Encode, bincode::Decode, Debug)]
struct BitcoinTx {
    tx_id: [u8; 32],          // Transaction ID (32 bytes)
    amount: u64,              // BTC amount in satoshis
    signatures: Vec<Vec<u8>>, // 2-of-3 multi-sig signatures (mocked)
    confirmations: u32,       // Number of confirmations
}

#[derive(bincode::Encode, bincode::Decode, Debug)]
struct PublicValues {
    tx_id: [u8; 32], // Transaction ID
    is_valid: bool,  // Validity flag
}

/// CLI arguments
#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    #[clap(long)]
    execute: bool,

    #[clap(long)]
    prove: bool,
}

fn main() {
    // Setup logging
    sp1_sdk::utils::setup_logger();
    dotenv::dotenv().ok();

    // Parse CLI arguments
    let args = Args::parse();

    if args.execute == args.prove {
        eprintln!("Error: Specify either --execute or --prove, not both or neither");
        std::process::exit(1);
    }

    // Setup the prover client
    let client = ProverClient::from_env();

    // Mock Bitcoin transaction input (replace with real Testnet data in practice)
    let mock_tx = BitcoinTx {
        tx_id: [0u8; 32],                           // Placeholder txID
        amount: 1000,                               // 1000 satoshis (0.00001 BTC)
        signatures: vec![vec![1; 64], vec![2; 64]], // Mock 2 signatures
        confirmations: 6,                           // 6 confirmations
    };

    // Setup inputs
    let mut stdin = SP1Stdin::new();
    let tx_bytes = bincode::serialize(&mock_tx).expect("Failed to serialize mock_tx");
    stdin.write_vec(tx_bytes);

    println!("Mock BitcoinTx: {:?}", mock_tx);

    if args.execute {
        // Execute the program
        let (output, report) = client.execute(BITCOIN_VERIFY_ELF, &stdin).run().unwrap();
        println!("Program executed successfully.");

        // Deserialize and read the output
        let decoded: PublicValues =
            bincode::deserialize(&output.as_slice()).expect("Failed to deserialize output");
        println!(
            "Output: tx_id={:?}, is_valid={}",
            decoded.tx_id, decoded.is_valid
        );

        // Basic validation (for PoC)
        assert_eq!(
            decoded.is_valid, true,
            "Verification failed for mock transaction"
        );
        println!("Verification result is correct!");

        // Report cycles
        println!("Number of cycles: {}", report.total_instruction_count());
    } else {
        // Setup for proving
        let (pk, vk) = client.setup(BITCOIN_VERIFY_ELF);

        // Generate the proof (using PLONK for zkSync compatibility)
        let proof = client
            .prove(&pk, &stdin)
            .plonk()
            .run()
            .expect("Failed to generate proof");

        println!("Successfully generated proof!");

        // Verify the proof
        client.verify(&proof, &vk).expect("Failed to verify proof");
        println!("Successfully verified proof!");
    }
}
