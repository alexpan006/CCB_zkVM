// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {ISP1Verifier} from "../lib/sp1-contracts/contracts/src/ISP1Verifier.sol";

/// @title Fibonacci.
/// @author Succinct Labs
/// @notice This contract implements a simple example of verifying the proof of a computing a
///         fibonacci number.
contract DWBTC {
    /// @notice The address of the SP1 verifier contract.
    /// @dev This can either be a specific SP1Verifier for a specific version, or the
    ///      SP1VerifierGateway which can be used to verify proofs for any version of SP1.
    ///      For the list of supported verifiers on each chain, see:
    ///      https://docs.succinct.xyz/onchain-verification/contract-addresses
    address public verifier;

    /// @notice The verification key for the fibonacci program.
    bytes32 public programVKey;

    constructor(address _verifier, bytes32 _programVKey) {
        verifier = _verifier;
        programVKey = _programVKey;
    }

    /// @notice The entrypoint for verifying the proof of a fibonacci number.
    /// @param _proofBytes The encoded proof.
    /// @param _publicValues The encoded public values.
    function verifyBitTrxProof(bytes calldata _publicValues, bytes calldata _proofBytes)
        public
        view
        returns (bytes32, address, uint256,bool)
    {
        ISP1Verifier(verifier).verifyProof(programVKey, _publicValues, _proofBytes);
        (bytes32 tx_id, address depositer_address, uint256 amount,bool is_valid) = abi.decode(_publicValues, (bytes32, address, uint256,bool));
        return (tx_id, depositer_address, amount,is_valid);
    }

    function change_verifier_address(address new_address)
    public
    {
        verifier = new_address;
    }
    function change_program_key(address new_pvkey)
    public
    {
        verifier = new_pvkey;
    }

}
