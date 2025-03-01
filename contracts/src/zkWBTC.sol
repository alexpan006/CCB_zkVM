// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
import {ISP1Verifier} from "@sp1-contracts/ISP1Verifier.sol";

// Define struct matching zkVM PublicValues
struct PublicValuesStruct {
    bytes32 tx_id; // Transaction ID (32 bytes)
    bool is_valid; // Verification result
}

contract zkWBTC {
    address public verifier;
    bytes32 public bitcoinVerifierProgramVKey;
    mapping(address => uint256) public zkWBTCBalance; // Track zkWBTC balances

    event VerificationResult(bytes32 tx_id, bool is_valid);

    constructor(address _verifier, bytes32 _bitcoinVerifierProgramVKey) {
        verifier = _verifier;
        bitcoinVerifierProgramVKey = _bitcoinVerifierProgramVKey;
    }

    function verifyBitcoinTrxProof(bytes calldata _publicValues, bytes calldata _proofBytes)
        public
        returns (bool)
    {
        // Verify proof with SP1 verifier
        (bool success, ) = ISP1Verifier(verifier).verifyProof(
            bitcoinVerifierProgramVKey,
            _publicValues,
            _proofBytes
        );
        if (!success) revert("Proof verification failed");

        // Decode public values
        PublicValuesStruct memory publicValues = abi.decode(_publicValues, (PublicValuesStruct));
        emit VerificationResult(publicValues.tx_id, publicValues.is_valid);

        // Mint zkWBTC if valid (simplified; adjust amount logic as needed)
        if (publicValues.is_valid) {
            zkWBTCBalance[msg.sender] += 1e18; // Mint 1 zkWBTC (10^18 wei-like units)
        }

        return publicValues.is_valid;
    }
}