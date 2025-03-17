// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import {stdJson} from "forge-std/StdJson.sol";
import "../src/DWBTC.sol"; // Adjust the path to your contract;
import {SP1VerifierGateway} from "../lib/sp1-contracts/contracts/src/SP1VerifierGateway.sol";

// Struct to match your expected JSON fixture format
struct DWBTCProofFixtureJson {
    bytes32 vkey;
    bytes publicValue;
    bytes proof;
}

contract DWBTCTest is Test {
    using stdJson for string;

    DWBTC public dwbtc;
    address public verifier;

    // Load fixture from JSON file
    function loadFixture() public view returns (DWBTCProofFixtureJson memory) {
        string memory root = vm.projectRoot();
        string memory path = string.concat(root, "/src/fixtures/plonk-fixture.json");
        string memory json = vm.readFile(path);

        DWBTCProofFixtureJson memory fixture;

        // Parse each field individually
        fixture.vkey = json.readBytes32(".vkey");
        fixture.publicValue = json.readBytes(".publicValue");
        fixture.proof = json.readBytes(".proof");

        return fixture;    }

    function setUp() public {
        DWBTCProofFixtureJson memory fixture = loadFixture();
        
        // Deploy a mock verifier (or use a real one if available)
        verifier = address(new SP1VerifierGateway(address(1)));
        dwbtc = new DWBTC(verifier, fixture.vkey);



    }

    function test_ValidProof() public {
        DWBTCProofFixtureJson memory fixture = loadFixture();

        // Mock the verifier to accept the proof
        vm.mockCall(
            verifier,
            abi.encodeWithSelector(SP1VerifierGateway.verifyProof.selector),
            abi.encode(true) // Empty return as verifyProof returns nothing
        );


        // Test the proof verification
        (bytes32 txId, address depositer, uint256 amount, bool isValid) = 
            dwbtc.verifyBitTrxProof(fixture.publicValue, fixture.proof);

        // Decode publicValue to verify
        (bytes32 expectedTxId, address expectedDepositer, uint256 expectedAmount, bool expectedIsValid) = 
            abi.decode(fixture.publicValue, (bytes32, address, uint256, bool));

        // Verify returned values match fixture
        assertEq(isValid, true, "Transaction is valid");
        

    }

    // function testFail_InvalidProof() public {
    //     DWBTCProofFixtureJson memory fixture = loadFixture();

    //     // Create a fake proof with same length but different content
    //     bytes memory fakeProof = new bytes(fixture.proof.length);

    //     // Mock verifier to accept (so we can test our contract's logic separately)
    //     vm.mockCall(
    //         verifier,
    //         abi.encodeWithSelector(ISP1Verifier.verifyProof.selector, fixture.vkey, fixture.publicValues, fakeProof),
    //         abi.encode()
    //     );

    //     // This should still work since we're only testing decode
    //     // If you want to test verifier rejection, you'd need different mocking
    //     (bytes32 returnedTxId,,,) = dwbtc.verifyBitTrxProof(fixture.publicValues, fakeProof);
    //     assertEq(returnedTxId, fixture.tx_id, "Transaction ID should still decode correctly");
    // }

    // function testFail_InvalidPublicValues() public {
    //     DWBTCProofFixtureJson memory fixture = loadFixture();

    //     // Create invalid public values
    //     bytes memory invalidPublicValues = abi.encode("invalid", "data", "format");

    //     vm.mockCall(
    //         verifier,
    //         abi.encodeWithSelector(ISP1Verifier.verifyProof.selector, fixture.vkey, invalidPublicValues, fixture.proof),
    //         abi.encode()
    //     );

    //     // Expect revert due to decoding failure
    //     vm.expectRevert();
    //     dwbtc.verifyBitTrxProof(invalidPublicValues, fixture.proof);
    // }
}