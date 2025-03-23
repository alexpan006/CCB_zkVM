// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import {ISP1Verifier} from "lib/sp1-contracts/contracts/src/ISP1Verifier.sol";
import {DWBTC} from "../src/DWBTC.sol";
import {Ownable} from "lib/openzeppelin-contracts/contracts/access/Ownable.sol";

contract DWBTCTest is Test {
    DWBTC public dwbtc;
    address public verifier = address(0x1234); // Mock verifier address
    bytes32 public programVKey = keccak256("test_vkey");
    address public user = address(0x5678);

    // Sample test data
    bytes public validPublicValues;
    bytes public validProof = hex"1234";
    bytes32 public txId = keccak256("test_tx");

    function setUp() public {
        dwbtc = new DWBTC(verifier, programVKey);

        // Encode valid public values
        validPublicValues = abi.encode(
            txId,              // bytes32
            user,              // address
            uint256(1000),     // amount
            true               // is_valid
        );

        // Mock successful proof verification
        vm.mockCall(
            verifier,
            abi.encodeWithSelector(ISP1Verifier.verifyProof.selector, programVKey, validPublicValues, validProof),
            abi.encode()
        );
    }

    function test_SuccessfulMint() public {
    // Check event for first call
    vm.expectEmit(true, true, false, true);
    emit DWBTC.ProofVerifiedAndMinted(txId, user, 1000, true);
    (bytes32 returnedTxId, address depositer, uint256 amount, bool isValid) = 
        dwbtc.verifyAndMint(validPublicValues, validProof);

    assertEq(returnedTxId, txId, "Tx ID mismatch");
    assertEq(depositer, user, "Depositer mismatch");
    assertEq(amount, 1000, "Amount mismatch");
    assertEq(isValid, true, "isValid mismatch");
    assertEq(dwbtc.balanceOf(user), 1000, "Tokens not minted");
    assertTrue(dwbtc.processedTxIds(txId), "Tx ID not marked as processed");
    }

    function test_RevertOnInvalidProof() public {
        bytes memory invalidProof = hex"abcd";

        // Mock failed verification (revert)
        vm.mockCallRevert(
            verifier,
            abi.encodeWithSelector(ISP1Verifier.verifyProof.selector, programVKey, validPublicValues, invalidProof),
            "Invalid proof from mock"
        );

        // Expect revert
        vm.expectRevert("Invalid proof");
        dwbtc.verifyAndMint(validPublicValues, invalidProof);
    }

    function test_RevertOnProcessedTx() public {
        // First successful mint
        dwbtc.verifyAndMint(validPublicValues, validProof);

        // Second attempt should revert
        vm.expectRevert("Transaction already processed");
        dwbtc.verifyAndMint(validPublicValues, validProof);
    }

    function test_RevertOnInvalidInputs() public {
        // Test invalid is_valid
        bytes memory invalidPublicValues = abi.encode(txId, user, uint256(1000), false);
        vm.mockCall(
            verifier,
            abi.encodeWithSelector(ISP1Verifier.verifyProof.selector, programVKey, invalidPublicValues, validProof),
            abi.encode()
        );
        vm.expectRevert("Proof is marked as invalid");
        dwbtc.verifyAndMint(invalidPublicValues, validProof);

        // Test zero amount
        invalidPublicValues = abi.encode(txId, user, uint256(0), true);
        vm.mockCall(
            verifier,
            abi.encodeWithSelector(ISP1Verifier.verifyProof.selector, programVKey, invalidPublicValues, validProof),
            abi.encode()
        );
        vm.expectRevert("Amount must be greater than zero");
        dwbtc.verifyAndMint(invalidPublicValues, validProof);

        // Test zero address
        invalidPublicValues = abi.encode(txId, address(0), uint256(1000), true);
        vm.mockCall(
            verifier,
            abi.encodeWithSelector(ISP1Verifier.verifyProof.selector, programVKey, invalidPublicValues, validProof),
            abi.encode()
        );
        vm.expectRevert("Invalid depositer address");
        dwbtc.verifyAndMint(invalidPublicValues, validProof);
    }

    function test_ChangeVerifierAddress() public {
        address newVerifier = address(0x9999);
        dwbtc.change_verifier_address(newVerifier);
        assertEq(dwbtc.verifier(), newVerifier, "Verifier address not updated");

        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, user));
        vm.prank(user);
        dwbtc.change_verifier_address(address(0x1111));
    }

    function test_ChangeProgramKey() public {
        bytes32 newKey = keccak256("new_key");
        dwbtc.change_program_key(newKey);
        assertEq(dwbtc.programVKey(), newKey, "Program key not updated");
    }
}