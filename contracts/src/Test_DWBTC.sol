// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {ISP1Verifier} from "../lib/sp1-contracts/contracts/src/ISP1Verifier.sol";
import {ERC20} from "lib/openzeppelin-contracts/contracts/token/ERC20/ERC20.sol";
import {Ownable} from "lib/openzeppelin-contracts/contracts/access/Ownable.sol";

    /// @title DWBTC - Decentralized Wrapped Bitcoin
    /// @notice This contract verifies proofs and mints tokens based on verified transactions
contract Test_DWBTC is ERC20,Ownable{
    /// @notice The address of the SP1 verifier contract.
    /// @dev This can either be a specific SP1Verifier for a specific version, or the
    ///      SP1VerifierGateway which can be used to verify proofs for any version of SP1.
    ///      For the list of supported verifiers on each chain, see:
    ///      https://docs.succinct.xyz/onchain-verification/contract-addresses
    
    address public verifier;
    bytes32 public programVKey;

    // Mapping to track processed transaction IDs
    mapping(bytes32 => bool) public processedTxIds;

    // Event for proof verification and minting
    event ProofVerifiedAndMinted(
        bytes32 indexed txId,
        address indexed depositer,
        uint256 amount,
        bool isValid
    );

    struct ETHPublicValuesStruct {
        bytes32 tx_id;  // Record txid prevent re-entry.
        address depositer_address; // Address to send money.
        uint256 amount; // Amount to mint.
        bool is_valid;
    }


    constructor(address _verifier, bytes32 _programVKey)
    ERC20("Decentralized Wrapped Bitcoin", "DWBTC")
    Ownable(msg.sender)
    {
        verifier = _verifier;
        programVKey = _programVKey;
    }

    /// @notice The entrypoint for verifying the proof of a bitcoin swap request.
    /// @param _proofBytes The encoded proof.
    /// @param _publicValues The encoded public values.
    function verifyAndMint(bytes calldata _publicValues, bytes calldata _proofBytes)
        external
    {
        try ISP1Verifier(verifier).verifyProof(programVKey, _publicValues, _proofBytes){}
        catch  {
            revert("Invalid proof");
        }

        (bytes32 tx_id, address depositer_address, uint256 amount,bool is_valid) = abi.decode(_publicValues, (bytes32, address, uint256,bool));
        
        // Step 3: Check if tx_id has been processed
        if (processedTxIds[tx_id]) {
            revert("Transaction already processed");
        }

        // Step 4: Additional validation
        require(is_valid, "Proof is marked as invalid");
        require(amount > 0, "Amount must be greater than zero");
        require(depositer_address != address(0), "Invalid depositer address");

        // Step 5: Mark tx_id as processed
        processedTxIds[tx_id] = true;

        // Step 6: Mint tokens to depositer_address
        _mint(depositer_address, amount);

        // Emit event
        emit ProofVerifiedAndMinted(tx_id, depositer_address, amount, is_valid);

    }

    function test_verifyAndMint(bytes calldata _publicValues, bytes calldata _proofBytes)
    external
    {
        try ISP1Verifier(verifier).verifyProof(programVKey, _publicValues, _proofBytes){}
        catch  {
            revert("Invalid proof");
        }

        (bytes32 tx_id, address depositer_address, uint256 amount,bool is_valid) = abi.decode(_publicValues, (bytes32, address, uint256,bool));
        
        // // Step 3: Check if tx_id has been processed
        // if (processedTxIds[tx_id]) {
        //     revert("Transaction already processed");
        // }

        // Step 4: Additional validation
        require(is_valid, "Proof is marked as invalid");
        require(amount > 0, "Amount must be greater than zero");
        require(depositer_address != address(0), "Invalid depositer address");

        // // Step 5: Mark tx_id as processed
        // processedTxIds[tx_id] = true;

        // Step 6: Mint tokens to depositer_address
        _mint(depositer_address, amount);

        // Emit event
        emit ProofVerifiedAndMinted(tx_id, depositer_address, amount, is_valid);
    }





    /// @notice Original view function for verification only (kept for compatibility)
    function verifyBitTrxProof(bytes calldata _publicValues, bytes calldata _proofBytes)
        public
        view
        returns (bytes32, address, uint256, bool)
    {
        ISP1Verifier(verifier).verifyProof(programVKey, _publicValues, _proofBytes);
        (bytes32 tx_id, address depositer_address, uint256 amount, bool is_valid) = 
            abi.decode(_publicValues, (bytes32, address, uint256, bool));
        return (tx_id, depositer_address, amount, is_valid);
    }

    function test_decode(bytes calldata _publicValues)
    external
    pure
    returns(bytes32 tx_id, address depositer_address, uint256 amount, bool isValid)
    {
        ETHPublicValuesStruct memory publicValues = abi.decode(_publicValues, (ETHPublicValuesStruct));
        return (publicValues.tx_id, publicValues.depositer_address, publicValues.amount,publicValues.is_valid);
    }

    /// @notice Allows owner to update verifier address
    function change_verifier_address(address new_address) external onlyOwner {
        require(new_address != address(0), "Invalid verifier address");
        verifier = new_address;
    }

    /// @notice Allows owner to update program key
    function change_program_key(bytes32 new_pvkey) external onlyOwner {
        programVKey = new_pvkey;
    }

}
