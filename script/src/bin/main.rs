//! Script to execute or prove Bitcoin transaction verification using SP1 zkVM for the cross-chain bridge.
//! Run with:
//! - Execution: `RUST_LOG=info cargo run --release -- --execute`
//! - Proving: `RUST_LOG=info cargo run --release -- --prove`
use alloy_sol_types::SolType;
use clap::Parser;
use lib_struct::{
    BitcoinTrxInfoStruct, BundleInfoStruct, ETHPublicValuesStruct, RequestInfoStruct,
};
use sp1_sdk::{include_elf, ProverClient, SP1Stdin};
// ELF file for the Bitcoin transaction verification zkVM program (assumes compiled from your zkVM code)
pub const BITCOIN_VERIFY_ELF: &[u8] = include_elf!("bitcoin_verify_program");
// Structs for Bitcoin transaction data and public values (mirroring zkVM pseudocode)
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

    // RUST_LOG=info cargo run --release -- --execute

    // Setup the inputs.
    let mut stdin = SP1Stdin::new();
    let bundle_data = BundleInfoStruct {
        bit_info: mock_tx,
        req_info: mock_req,
    };
    stdin.write(&bundle_data);

    if args.execute {
        // Execute the program
        let (output, report) = client.execute(BITCOIN_VERIFY_ELF, &stdin).run().unwrap();
        // let decode_output = ;
        println!("Program executed successfully");

        // -------------------------------------
        // let decode_output = ;
        // Read the output.
        let decoded = ETHPublicValuesStruct::abi_decode(output.as_slice(), false).unwrap();

        println!("Result is ");

        let ETHPublicValuesStruct {
            tx_id,
            depositer_address,
            amount,
            is_valid,
        } = decoded;

        println!("-------------------------------------------");
        println!("tx_id: {}", tx_id);
        println!("depositer eth address: {}", depositer_address);
        println!("amount: {}", amount);
        println!("is valid or not: {}", is_valid);
        println!("Number of cycles: {}", report.total_instruction_count());
    } else {
        // Setup the program for proving.
        let (pk, vk) = client.setup(BITCOIN_VERIFY_ELF);

        // Generate the proof
        let proof = client
            .prove(&pk, &stdin)
            .run()
            .expect("failed to generate proof");

        println!("Successfully generated proof!");

        // Verify the proof.
        client.verify(&proof, &vk).expect("failed to verify proof");
        println!("Successfully verified proof!");
    }
    println!("Finish");
}
