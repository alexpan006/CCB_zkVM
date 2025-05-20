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
    let mock_tx_2 = BitcoinTrxInfoStruct {
        raw_tx_hex: "010000000001015564819f67c2803761c4370d9a5fd950c8e6ff34d68ebacc47fd21413aa833ea0100000000ffffffff03e8030000000000001600141240e21b1e7877f77bfe66cc59eefb02d17a0a3f00000000000000002c6a2a3078613836456433343742384431303433353333666533306330374663343766334533623834396134329b020000000000001600144cf2f041e4acc16071306ab41414cab4c76cfd5002483045022100bf43ff7d1ae782368550cb14cc916d389277a0f103643fa352ea76ba2ccd731502205028ba84f39deb9ff71db91153c6f71e7f9f5f6df9258c29bb49ec0461785b75012103292a330133c26afde92f10737cc3e38ebcf7403b4e2232c4b65821c1aa55cdf800000000".into(), // Placeholder txID
    };

    // let mock_merkle_proof = MerkleProof {
    //     siblings: vec![
    //         "8d544972083bbd81c62801238ee3b340ddba192f29a84646b0a341f75eb42cff".to_string(),
    //         "2a063e0b0b7fbfc1f3eb330a2be7305fc3b80f180e067767dac2013b282f307f".to_string(),
    //         "63b3a37f0b38b2c57968b6dbb12f73a566e3d05105843baf5ec1bdd15903ee80".to_string(),
    //         "672b8bebba4f8a5058b8e7ee901f1947e4d57eba9c529d2e58e3ddc43c5dd03a".to_string(),
    //         "6c3fb01b874ece9c16f19fa5d67cf16c1df97fe99a7245044af9dd67e658d8df".to_string(),
    //         "3d9276ac291be5506feeea8cd91b73b8653584d53a3d195baa8a557104da081e".to_string(),
    //         "264dedffd68da58e41be1eaf69d09be5bef7c5a3d4a38ce10f30a6735285ed2e".to_string(),
    //         "449142fa286fecfec294e51645fb129e603b58222d21f8d0a7629a1279e56bd1".to_string(),
    //         "ed05502acf2d9deadb8811b24ba4d4e1cabd847a81e43762c3f26ddb7ac65fbe".to_string(),
    //         "972e983bc8d9c761c9254047a5bbb8fe988e4d952230eba605f2708c5618ee97".to_string(),
    //     ],
    //     pos: 625,
    // };

    // let block_2 = Block {
    //     block_hash: "00000000000000cc7333d284eef6b40bc00afa4ca1f4440a52d9c183890dcaa4".to_string(),
    //     version: 536870912,
    //     parent_hash: "0000000000a56e2d16712889d625bfaf8facd02d8ab3ff943884e13d25d6bc5a".to_string(),
    //     merkle_root: "a2de21c06b1580ac52d285bc3a7d3acf053a50c49cd1b9da7f666f741b1982ab".to_string(),
    //     timestamp: 1740353445,
    //     difficulty: 436273151,
    //     nonce: 294214847,
    // };
    // let block_3 = Block {
    //     block_hash: "000000000043d2478726af30fc6baf86550fbbcc9bc0884ee5836d7cf6667bc4".to_string(),
    //     version: 546365440,
    //     parent_hash: "00000000000000cc7333d284eef6b40bc00afa4ca1f4440a52d9c183890dcaa4".to_string(),
    //     merkle_root: "1843348b72b981e65ebc2fd1dcd0ec529f470989735a3847e9ba68535a04f992".to_string(),
    //     timestamp: 1740354646,
    //     difficulty: 486604799,
    //     nonce: 2633564790,
    // };
    // let block_4 = Block {
    //     block_hash: "0000000000000074c5d6831a8c8c2f42d0165c0b785ca4ccd780d7b11eaf1bb6".to_string(),
    //     version: 545259520,
    //     parent_hash: "000000000043d2478726af30fc6baf86550fbbcc9bc0884ee5836d7cf6667bc4".to_string(),
    //     merkle_root: "fc2e605c8e3af0b3c8b342c9a1f11785190624002f4b2fef90d1a547a011491c".to_string(),
    //     timestamp: 1740353445,
    //     difficulty: 436273151,
    //     nonce: 4224864518,
    // };
    // let block_5 = Block {
    //     block_hash: "0000000007f661e78c869ad22953edc994649549e8b23cdd015dd4f9a83bbb80".to_string(),
    //     version: 536870912,
    //     parent_hash: "0000000000000074c5d6831a8c8c2f42d0165c0b785ca4ccd780d7b11eaf1bb6".to_string(),
    //     merkle_root: "38222d9e1fb29ebd7c97043ec5296d472f7edd43daeee7d3fe548b7318e192cf".to_string(),
    //     timestamp: 1740354646,
    //     difficulty: 486604799,
    //     nonce: 3862977561,
    // };
    // let block_6 = Block {
    //     block_hash: "00000000000000716500a7024056dec7a78542fa9917fc12df17319d12e18e55".to_string(),
    //     version: 647331840,
    //     parent_hash: "0000000007f661e78c869ad22953edc994649549e8b23cdd015dd4f9a83bbb80".to_string(),
    //     merkle_root: "e78d6f9d66b8e5e0a882d14031dd54a598cdbfe6b7359272f0041745d3b3c278".to_string(),
    //     timestamp: 1740353446,
    //     difficulty: 436273151,
    //     nonce: 821607044,
    // };
    // let block_7 = Block {
    //     block_hash: "000000000068e0cc9d3ba2173d5f8cc2526ff72b331c5a4855e28246b791ff0e".to_string(),
    //     version: 627023872,
    //     parent_hash: "00000000000000716500a7024056dec7a78542fa9917fc12df17319d12e18e55".to_string(),
    //     merkle_root: "345d45c0ae8988a0ed079c761c3c07e31411b37edd72ec0afda84010612a54d6".to_string(),
    //     timestamp: 1740354647,
    //     difficulty: 486604799,
    //     nonce: 2202599532,
    // };
    // let block_8 = Block {
    //     block_hash: "00000000000000d1648334d8dccf14bd28faabb4245c6644e013a81279c9d684".to_string(),
    //     version: 536870912,
    //     parent_hash: "000000000068e0cc9d3ba2173d5f8cc2526ff72b331c5a4855e28246b791ff0e".to_string(),
    //     merkle_root: "8921857ccceb91e2ea7afd3b595a95bf1b1d270771d05cfd51c3ba8f2fcd0f4b".to_string(),
    //     timestamp: 1740353447,
    //     difficulty: 436273151,
    //     nonce: 2738097306,
    // };

    //----------------------------------------------------------------------------------------------------
    let mock_merkle_proof = MerkleProof {
        siblings: vec![
            "cc4522617a92f7b27416f3cedad721949df7aec91d6e87f23ef2895c760e6eee".to_string(),
        ],
        pos: 1,
    };

    let block_2 = Block {
        block_hash: "00000000000002ee8b7a2baff6fc9366166d75b97301a68b0eceb3bf60f38d8f".to_string(),
        version: 633618432,
        parent_hash: "0000000000000bf53edcfa982a0cbcaab1abf62660ec3ec67149df036891b32b".to_string(),
        merkle_root: "214101dabc8c2b1e02999995163f31b187351c8ac1dad611e2660c2c4cae5ac6".to_string(),
        timestamp: 1744638928,
        difficulty: 437256176,
        nonce: 4137494058,
    };
    let block_3 = Block {
        block_hash: "00000000000003fd04b9cb97cc0f1ce28a4588d965c595dfb4dbaf9bfd8b2a82".to_string(),
        version: 770375680,
        parent_hash: "00000000000002ee8b7a2baff6fc9366166d75b97301a68b0eceb3bf60f38d8f".to_string(),
        merkle_root: "b4ce4f3646fd93a8ffed7711840a09039722919c45ff1beb029d5f3027c32858".to_string(),
        timestamp: 1744638928,
        difficulty: 437256176,
        nonce: 2932452395,
    };
    let block_4 = Block {
        block_hash: "0000000000000764853fd899f37e85d2765a1ec763dfd8bf2a1e739a9cad370c".to_string(),
        version: 710811648,
        parent_hash: "00000000000003fd04b9cb97cc0f1ce28a4588d965c595dfb4dbaf9bfd8b2a82".to_string(),
        merkle_root: "1d065531f64d5662ba174f7533bddd96632d4e530ed9df2b3d1470336f5c9daa".to_string(),
        timestamp: 1744638929,
        difficulty: 437256176,
        nonce: 2559894718,
    };
    let block_5 = Block {
        block_hash: "0000000000000ef1e4b025cfb3cb6ad42482deaf8551ea2d158c23189483723a".to_string(),
        version: 565084160,
        parent_hash: "0000000000000764853fd899f37e85d2765a1ec763dfd8bf2a1e739a9cad370c".to_string(),
        merkle_root: "e4781238e680b8712b32696569a8f7f8a7964612cccb1cc4564c252ba0c545cf".to_string(),
        timestamp: 1744638929,
        difficulty: 437256176,
        nonce: 2621199785,
    };
    let block_6 = Block {
        block_hash: "00000000000003d773169c1c0dab0a2be623b8b2357b2029d889a3078328ee5f".to_string(),
        version: 565624832,
        parent_hash: "0000000000000ef1e4b025cfb3cb6ad42482deaf8551ea2d158c23189483723a".to_string(),
        merkle_root: "e4b951c8dc1318c92de34759d26098c47c0b7562b05949fc741ee80b44a3d665".to_string(),
        timestamp: 1744638929,
        difficulty: 437256176,
        nonce: 2556017316,
    };
    let block_7 = Block {
        block_hash: "0000000000000d76abee84857450cfec57f49c9a2bc0e5ecbf018dc72bc8bbf7".to_string(),
        version: 585113600,
        parent_hash: "00000000000003d773169c1c0dab0a2be623b8b2357b2029d889a3078328ee5f".to_string(),
        merkle_root: "3eae91ae2faac30f4694b548caedab64b41c2147e04e5111f0f5b43de4e39904".to_string(),
        timestamp: 1744638929,
        difficulty: 437256176,
        nonce: 3028696670,
    };

    let mock_chain = Chain {
        blocks: vec![
            block_2, block_3, block_4, block_5, block_6, block_7, //, block_8
        ],
    };

    // RUST_LOG=info cargo run --release -- --execute

    // Setup the inputs.
    let mut stdin = SP1Stdin::new();
    let bundle_data = BundleInfoStruct {
        merkle_proof: mock_merkle_proof,
        chains: mock_chain,
        bit_tx_info: mock_tx_2,
    };
    stdin.write(&bundle_data);

    if args.execute {
        // Execute the program
        let (output, report) = client.execute(BITCOIN_VERIFY_ELF, &stdin).run().unwrap();
        // let total_compute_cycles = report.cycle_tracker.get("compute").unwrap();
        // let compute_invocation_count = report.invocation_tracker.get("compute").unwrap();
        println!("-------------------------------------------");
        // println!("Total compute cycles: {:?}", total_compute_cycles);
        // println!("Compute invocation count: {:?}", compute_invocation_count);
        // let decode_output = ;
        println!("Report:{:?},", report);
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
