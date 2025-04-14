//! Script to execute or prove Bitcoin transaction verification using SP1 zkVM for the cross-chain bridge.
//! Run with:
//! - Execution: `RUST_LOG=info cargo run --release -- --execute`
//! - Proving: `RUST_LOG=info cargo run --release -- --prove`
use alloy_sol_types::SolType;
use clap::Parser;
use lib_struct::{
    BitcoinTrxInfoStruct, Block, BundleInfoStruct, Chain, ETHPublicValuesStruct, MerkleProof,
    RequestInfoStruct,
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
        raw_tx_hex: "02000000000101421c10cda02eab4c0674ab4ee43f092106cb276a932532f40ddacf8800dd10d20000000000fdffffff029594be0000000000160014c9d25250c0d6ef608eb7343c6d43be9e60d8dcd6a3540000000000001600149be9f198e0a2fb264f1afe22f874e917612de49a0140407a9364cb1b4024345eece3f976c976c9085ba625495e1fe70b60357b90c1e6f582e96a1f5d4c8decd787e9252c293633bb11e4dbf2c905b1fe36321557f829a1293b00".into(), // Placeholder txID
    };
    // Mock Bitcoin transaction input (replace with real Testnet data in practice)
    let mock_req = RequestInfoStruct {
        depositer_bit_address: "ea33a83a4121fd47ccba8ed634ffe6c850d95f9a0d37c4613780c2679f816455"
            .into(), // Placeholder txID
        target_deposit_address: "tb1qn05lrx8q5tajvnc6lc30sa8fzasjmey6fnl3p0".into(), // 1000 satoshis (0.00001 BTC)
        depositer_eth_address: "0xa86Ed347B8D1043533fe30c07Fc47f3E3b849a42".to_string(), // 6 confirmations
        amount: 21667,
    };
    let mock_merkle_proof = MerkleProof {
        siblings: vec![
            "8d544972083bbd81c62801238ee3b340ddba192f29a84646b0a341f75eb42cff".to_string(),
            "2a063e0b0b7fbfc1f3eb330a2be7305fc3b80f180e067767dac2013b282f307f".to_string(),
            "63b3a37f0b38b2c57968b6dbb12f73a566e3d05105843baf5ec1bdd15903ee80".to_string(),
            "672b8bebba4f8a5058b8e7ee901f1947e4d57eba9c529d2e58e3ddc43c5dd03a".to_string(),
            "6c3fb01b874ece9c16f19fa5d67cf16c1df97fe99a7245044af9dd67e658d8df".to_string(),
            "3d9276ac291be5506feeea8cd91b73b8653584d53a3d195baa8a557104da081e".to_string(),
            "264dedffd68da58e41be1eaf69d09be5bef7c5a3d4a38ce10f30a6735285ed2e".to_string(),
            "449142fa286fecfec294e51645fb129e603b58222d21f8d0a7629a1279e56bd1".to_string(),
            "ed05502acf2d9deadb8811b24ba4d4e1cabd847a81e43762c3f26ddb7ac65fbe".to_string(),
            "972e983bc8d9c761c9254047a5bbb8fe988e4d952230eba605f2708c5618ee97".to_string(),
        ],
        pos: 625,
    };

    let block_2 = Block {
        block_hash: "00000000000000cc7333d284eef6b40bc00afa4ca1f4440a52d9c183890dcaa4".to_string(),
        version: 536870912,
        parent_hash: "0000000000a56e2d16712889d625bfaf8facd02d8ab3ff943884e13d25d6bc5a".to_string(),
        merkle_root: "a2de21c06b1580ac52d285bc3a7d3acf053a50c49cd1b9da7f666f741b1982ab".to_string(),
        timestamp: 1740353445,
        difficulty: 436273151,
        nonce: 294214847,
    };
    let block_3 = Block {
        block_hash: "000000000043d2478726af30fc6baf86550fbbcc9bc0884ee5836d7cf6667bc4".to_string(),
        version: 546365440,
        parent_hash: "00000000000000cc7333d284eef6b40bc00afa4ca1f4440a52d9c183890dcaa4".to_string(),
        merkle_root: "1843348b72b981e65ebc2fd1dcd0ec529f470989735a3847e9ba68535a04f992".to_string(),
        timestamp: 1740354646,
        difficulty: 486604799,
        nonce: 2633564790,
    };
    let block_4 = Block {
        block_hash: "0000000000000074c5d6831a8c8c2f42d0165c0b785ca4ccd780d7b11eaf1bb6".to_string(),
        version: 545259520,
        parent_hash: "000000000043d2478726af30fc6baf86550fbbcc9bc0884ee5836d7cf6667bc4".to_string(),
        merkle_root: "fc2e605c8e3af0b3c8b342c9a1f11785190624002f4b2fef90d1a547a011491c".to_string(),
        timestamp: 1740353445,
        difficulty: 436273151,
        nonce: 4224864518,
    };
    let block_5 = Block {
        block_hash: "0000000007f661e78c869ad22953edc994649549e8b23cdd015dd4f9a83bbb80".to_string(),
        version: 536870912,
        parent_hash: "0000000000000074c5d6831a8c8c2f42d0165c0b785ca4ccd780d7b11eaf1bb6".to_string(),
        merkle_root: "38222d9e1fb29ebd7c97043ec5296d472f7edd43daeee7d3fe548b7318e192cf".to_string(),
        timestamp: 1740354646,
        difficulty: 486604799,
        nonce: 3862977561,
    };
    let block_6 = Block {
        block_hash: "00000000000000716500a7024056dec7a78542fa9917fc12df17319d12e18e55".to_string(),
        version: 647331840,
        parent_hash: "0000000007f661e78c869ad22953edc994649549e8b23cdd015dd4f9a83bbb80".to_string(),
        merkle_root: "e78d6f9d66b8e5e0a882d14031dd54a598cdbfe6b7359272f0041745d3b3c278".to_string(),
        timestamp: 1740353446,
        difficulty: 436273151,
        nonce: 821607044,
    };
    let block_7 = Block {
        block_hash: "000000000068e0cc9d3ba2173d5f8cc2526ff72b331c5a4855e28246b791ff0e".to_string(),
        version: 627023872,
        parent_hash: "00000000000000716500a7024056dec7a78542fa9917fc12df17319d12e18e55".to_string(),
        merkle_root: "345d45c0ae8988a0ed079c761c3c07e31411b37edd72ec0afda84010612a54d6".to_string(),
        timestamp: 1740354647,
        difficulty: 486604799,
        nonce: 2202599532,
    };
    let block_8 = Block {
        block_hash: "00000000000000d1648334d8dccf14bd28faabb4245c6644e013a81279c9d684".to_string(),
        version: 536870912,
        parent_hash: "000000000068e0cc9d3ba2173d5f8cc2526ff72b331c5a4855e28246b791ff0e".to_string(),
        merkle_root: "8921857ccceb91e2ea7afd3b595a95bf1b1d270771d05cfd51c3ba8f2fcd0f4b".to_string(),
        timestamp: 1740353447,
        difficulty: 436273151,
        nonce: 2738097306,
    };

    let mock_chain = Chain {
        blocks: vec![
            block_2, block_3, block_4, block_5, block_6, block_7, block_8,
        ],
    };

    // RUST_LOG=info cargo run --release -- --execute

    // Setup the inputs.
    let mut stdin = SP1Stdin::new();
    let bundle_data = BundleInfoStruct {
        merkle_proof: mock_merkle_proof,
        chains: mock_chain,
        bit_tx_info: mock_tx,
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
        // let decoded = ETHPublicValuesStruct::abi_decode(output.as_slice(), false).unwrap();

        // let ETHPublicValuesStruct {
        //     tx_id,
        //     depositer_address,
        //     amount,
        //     is_valid,
        // } = decoded;

        // println!("-------------------------------------------");
        // println!("tx_id: {:?}", tx_id);
        // println!("depositer eth address: {:?}", depositer_address);
        // println!("amount: {:?}", amount);
        // println!("is valid or not: {:?}", is_valid);
        // println!("Number of cycles: {:?}", report.total_instruction_count());
    } else {
        // Setup the program for proving.
        let (pk, vk) = client.setup(BITCOIN_VERIFY_ELF);

        // Generate the proof
        let proof = client
            .prove(&pk, &stdin)
            .run()
            .expect("failed to generate proof");

        println!("Successfully generated proof!");
        // println!("The proof is {:?}", proof.public_values.as_slice());
        // println!("Public values:{:?}", proof.public_values);
        let bytes = proof.public_values.as_slice();
        let decoded = ETHPublicValuesStruct::abi_decode(bytes, false).unwrap();
        println!("The tx_id ={:?}", decoded.tx_id);

        // Verify the proof.
        client.verify(&proof, &vk).expect("failed to verify proof");
        println!("Successfully verified proof!");
    }
    println!("Finish");
}
