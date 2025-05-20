// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import {DWBTC} from "../src/DWBTC.sol";
import {ISP1Verifier} from "../lib/sp1-contracts/contracts/src/ISP1Verifier.sol";

// Mock verifier contract
contract MockSP1Verifier is ISP1Verifier {
    bool public shouldPass;

    constructor(bool _shouldPass) {
        shouldPass = _shouldPass;
    }

    function setShouldPass(bool _shouldPass) external {
        shouldPass = _shouldPass;
    }

    function verifyProof(bytes32, bytes calldata, bytes calldata) external view {
        if (!shouldPass) revert("Invalid proof from verifier");
    }
}

contract DWBTCTest is Test {
    DWBTC dwbtc;
    MockSP1Verifier verifier;
    address owner = address(0x1);
    address user = address(0x2);
    address operator = address(0x3);
    address operator2 = address(0x4);
    address[] stakers = [address(0x5), address(0x6), address(0x7)];

    bytes32 constant PROGRAM_VKEY_MINT = keccak256("mint");
    bytes32 constant PROGRAM_VKEY_BURN = keccak256("burn");
    uint256 constant SATOSHI_TO_DWBTC = 10**10;
    uint256 constant SUBMISSION_PERIOD = 1 days;

    function setUp() public {
        vm.startPrank(owner);
        verifier = new MockSP1Verifier(true);
        dwbtc = new DWBTC(address(verifier), PROGRAM_VKEY_MINT, PROGRAM_VKEY_BURN, stakers);
        vm.stopPrank();
    }
    // Helper function to mint tokens for testing
    function mintForUser(address _user, uint256 satoshis) internal {
        vm.startPrank(operator2);
        bytes memory publicValues = abi.encode(keccak256("tx1"), _user, satoshis, true);
        bytes memory proofBytes = hex"1234";
        dwbtc.verifyAndMint(publicValues, proofBytes);
        vm.stopPrank();
    }
    function mintForUser_2(address _user, uint256 satoshis) internal {
        vm.startPrank(operator2);
        bytes memory publicValues = abi.encode(keccak256("tx2"), _user, satoshis, true);
        bytes memory proofBytes = hex"1234";
        dwbtc.verifyAndMint(publicValues, proofBytes);
        vm.stopPrank();
    }

    // Minting Tests
    function testVerifyAndMintHappyPath() public {
        uint256 satoshis = 100000;
        bytes memory publicValues = abi.encode(keccak256("tx1"), user, satoshis, true);
        bytes memory proofBytes = hex"1234";

        vm.prank(operator);
        (bytes32 txId, address depositer, uint256 amount, bool isValid) = 
            dwbtc.verifyAndMint(publicValues, proofBytes);

        uint256 amountDwbtc = satoshis * SATOSHI_TO_DWBTC;
        uint256 userAmount = (amountDwbtc * 9900) / 10000;
        uint256 feeAmount = amountDwbtc - userAmount;
        uint256 operatorReward = feeAmount / 2;
        uint256 stakerReward = feeAmount - operatorReward;

        assertEq(dwbtc.balanceOf(user), userAmount);
        assertEq(dwbtc.balanceOf(operator), operatorReward);
        assertEq(dwbtc.balanceOf(address(dwbtc)), stakerReward);
        assertEq(dwbtc.totalSupply(), userAmount + operatorReward + stakerReward);
        assertEq(txId, keccak256("tx1"));
        assertEq(depositer, user);
        assertEq(amount, userAmount);
        assertTrue(isValid);
    }

    function testVerifyAndMintMinAmount() public {
        uint256 satoshis = 1; // 1 satoshi = 10,000 DWBTC units, above min 15,000
        bytes memory publicValues = abi.encode(keccak256("tx2"), user, satoshis, true);
        bytes memory proofBytes = hex"1234";

        vm.prank(operator);
        dwbtc.verifyAndMint(publicValues, proofBytes);

        uint256 amountDwbtc = satoshis * SATOSHI_TO_DWBTC;
        uint256 userAmount = (amountDwbtc * 9900) / 10000;
        assertEq(dwbtc.balanceOf(user), userAmount);
    }

    function testVerifyAndMintBelowMinAmount() public {
        uint256 satoshis = 0; // Will result in < 15,000 DWBTC units
        bytes memory publicValues = abi.encode(keccak256("tx3"), user, satoshis, true);
        bytes memory proofBytes = hex"1234";

        vm.prank(operator);
        vm.expectRevert(DWBTC.MintingAmountZero.selector);
        dwbtc.verifyAndMint(publicValues, proofBytes);
    }

    function testVerifyAndMintInvalidProof() public {
        verifier.setShouldPass(false);
        bytes memory publicValues = abi.encode(keccak256("tx4"), user, 100_000, true);
        bytes memory proofBytes = hex"1234";

        vm.prank(operator);
        vm.expectRevert("Invalid proof from verifier");
        dwbtc.verifyAndMint(publicValues, proofBytes);
    }

    function testVerifyAndMintReuseTxId() public {
        bytes memory publicValues = abi.encode(keccak256("tx1"), user, 100_000, true);
        bytes memory proofBytes = hex"1234";

        vm.startPrank(operator);
        dwbtc.verifyAndMint(publicValues, proofBytes);
        vm.expectRevert(DWBTC.MintingRequestAlreadyProcessed.selector);
        dwbtc.verifyAndMint(publicValues, proofBytes);
        vm.stopPrank();
    }

    // Burning Tests
    function testInitiateBurnHappyPath() public {
        mintForUser(user, 100_0000_0000_0000); // Mint 100,000 satoshis worth
        uint256 burnAmount = dwbtc.balanceOf(user); // 1M DWBTC units
        // uint256 burnAmount = 100_0000_0000_0000; // 1M DWBTC units

        vm.prank(user);
        dwbtc.initiateBurn(burnAmount, "btcAddress");
        (
            address temp_user,
            uint256 total_amount,
            uint256 dwbtcToReimburse,
            uint256 exactBtcUserReceive,
            uint256 rewardOperator,
            uint256 rewardStaker,
            uint256 dust,
            string memory btcAddress,
            uint256 timestamp,
            bool fulfilled,
            bool reclaimed
        ) = dwbtc.burnRequests(0);

        DWBTC.BurnRequest memory request = DWBTC.BurnRequest({
            user: temp_user,
            total_amount: total_amount,
            dwbtcToReimburse: dwbtcToReimburse,
            exactBtcUserReceive: exactBtcUserReceive,
            rewardOperator: rewardOperator,
            rewardStaker: rewardStaker,
            dust: dust,
            btcAddress: btcAddress,
            timestamp: timestamp,
            fulfilled: fulfilled,
            reclaimed: reclaimed
        });



        uint256 expectedAmount = (burnAmount * 9900 / 10000) / SATOSHI_TO_DWBTC;
        assertEq(request.user, user); // Ensure the user is correct
        assertEq(request.total_amount, burnAmount); // Ensure the total amount is correct(in DWBTC units)
        assertEq(request.exactBtcUserReceive, expectedAmount); // Ensure the exact BTC user receives is correct(btc units)
        assertFalse(request.fulfilled); // Ensure the request is not fulfilled
        assertFalse(request.reclaimed); // Ensure the request is not reclaimed
        assertEq(dwbtc.balanceOf(user), 0); // User's balance should be 0 after burn initiation
    }

    function testInitiateBurnInsufficientBalance() public {
        mintForUser(user, 100); // Mint 100,000 satoshis worth
        vm.prank(user);
        vm.expectRevert(DWBTC.BurnInsufficientBalance.selector);
        dwbtc.initiateBurn(100_0000_0000_000, "btcAddress");
    }

    function testInitiateBurnInvalidAmount() public {
        mintForUser(user, 100000);
        vm.prank(user);
        vm.expectRevert(DWBTC.BurnAmountTooSmall.selector);
        dwbtc.initiateBurn(100000, "btcAddress");
    }

    function testSubmitBurnProofHappyPath() public {
        // mintForUser(user, 100_0000_0000); // Mint 100,000 satoshis worth
        mintForUser(user, 12353); // Mint 100,000 satoshis worth
        uint256 burnAmount = dwbtc.balanceOf(user); // 1M DWBTC units

        vm.prank(user);
        dwbtc.initiateBurn(burnAmount, "btcAddress");
        (
            address temp_user,
            uint256 total_amount,
            uint256 dwbtcToReimburse,
            uint256 exactBtcUserReceive,
            uint256 rewardOperator,
            uint256 rewardStaker,
            uint256 dust,
            string memory btcAddress,
            uint256 timestamp,
            bool fulfilled,
            bool reclaimed
        ) = dwbtc.burnRequests(0);

        DWBTC.BurnRequest memory request = DWBTC.BurnRequest({
            user: temp_user,
            total_amount: total_amount,
            dwbtcToReimburse: dwbtcToReimburse,
            exactBtcUserReceive: exactBtcUserReceive,
            rewardOperator: rewardOperator,
            rewardStaker: rewardStaker,
            dust: dust,
            btcAddress: btcAddress,
            timestamp: timestamp,
            fulfilled: fulfilled,
            reclaimed: reclaimed
        });

        bytes memory publicValues = abi.encode("btcAddress", (burnAmount* 9900 / SATOSHI_TO_DWBTC), true);
        bytes memory proofBytes = hex"5678";

        vm.prank(operator);
        dwbtc.submitBurnProof(0, publicValues, proofBytes);
        console.log("Balance of user after burn",dwbtc.balanceOf(user),",dust:",request.dust);
        console.log("Balance of operator after burn",dwbtc.balanceOf(operator));
        console.log("Operator reimbursement:",request.dwbtcToReimburse,", reward:",request.rewardOperator);
        console.log("Staker reward:",request.rewardStaker);
        assertEq(dwbtc.balanceOf(user), request.dust); // User's balance should be equal to dust after burn
        (
            temp_user,
            total_amount,
            dwbtcToReimburse,
            exactBtcUserReceive,
            rewardOperator,
            rewardStaker,
            dust,
            btcAddress,
            timestamp,
            fulfilled,
            reclaimed
        ) = dwbtc.burnRequests(0);

        request = DWBTC.BurnRequest({
            user: temp_user,
            total_amount: total_amount,
            dwbtcToReimburse: dwbtcToReimburse,
            exactBtcUserReceive: exactBtcUserReceive,
            rewardOperator: rewardOperator,
            rewardStaker: rewardStaker,
            dust: dust,
            btcAddress: btcAddress,
            timestamp: timestamp,
            fulfilled: fulfilled,
            reclaimed: reclaimed
        });

        assertTrue(request.fulfilled);
        assertEq(dwbtc.balanceOf(operator), request.dwbtcToReimburse + request.rewardOperator);
    }

    function testSubmitBurnProofAfterSubmissionPeriod()  public {
        mintForUser(user, 100_0000_0000); // Mint 100,000 satoshis worth
        uint256 burnAmount = dwbtc.balanceOf(user); // 1M DWBTC units

        vm.prank(user);
        dwbtc.initiateBurn(burnAmount, "btcAddress");
        bytes memory publicValues = abi.encode("btcAddress", (burnAmount* 9900 / SATOSHI_TO_DWBTC), true);
        bytes memory proofBytes = hex"5678";

        vm.prank(operator);
        // Warp to after submission period
        vm.warp(block.timestamp + SUBMISSION_PERIOD + 2);
        vm.expectRevert(DWBTC.BurnRequestExpired.selector);
        dwbtc.submitBurnProof(0, publicValues, proofBytes);
    }

    function testReclaimBurnHappyPath() public {
        mintForUser(user, 10000000);
        uint256 burnAmount = dwbtc.balanceOf(user); // 1M DWBTC units

        vm.prank(user);
        dwbtc.initiateBurn(burnAmount, "btcAddress");

        vm.warp(block.timestamp + 2 days );
        vm.prank(user);
        dwbtc.reclaimBurn(0);
        (
            address temp_user,
            uint256 total_amount,
            uint256 dwbtcToReimburse,
            uint256 exactBtcUserReceive,
            uint256 rewardOperator,
            uint256 rewardStaker,
            uint256 dust,
            string memory btcAddress,
            uint256 timestamp,
            bool fulfilled,
            bool reclaimed
        ) = dwbtc.burnRequests(0);

        DWBTC.BurnRequest memory request = DWBTC.BurnRequest({
            user: temp_user,
            total_amount: total_amount,
            dwbtcToReimburse: dwbtcToReimburse,
            exactBtcUserReceive: exactBtcUserReceive,
            rewardOperator: rewardOperator,
            rewardStaker: rewardStaker,
            dust: dust,
            btcAddress: btcAddress,
            timestamp: timestamp,
            fulfilled: fulfilled,
            reclaimed: reclaimed
        });
        // DWBTC.BurnRequest memory request = dwbtc.burnRequests(0);
        assertTrue(request.reclaimed);
        assertTrue(request.fulfilled);
        assertEq(dwbtc.balanceOf(user), burnAmount);
    }
        
    function testReclaimBurnAlreadyClaimed() public {
        mintForUser(user, 10000000);
        uint256 burnAmount = dwbtc.balanceOf(user); 

        vm.prank(user);
        dwbtc.initiateBurn(burnAmount, "btcAddress");

        vm.warp(block.timestamp + 2 days );
        vm.prank(user);
        dwbtc.reclaimBurn(0);
        vm.expectRevert(DWBTC.BurnRequestAlreadyReclaimed.selector);
        vm.prank(user);
        dwbtc.reclaimBurn(0);
    }
    function testReclaimOpenRequest() public {
        mintForUser(user, 10000000);
        uint256 burnAmount = dwbtc.balanceOf(user); 

        vm.prank(user);
        dwbtc.initiateBurn(burnAmount, "btcAddress");

        vm.warp(block.timestamp);
        vm.prank(user);
        vm.expectRevert(DWBTC.BurnRequestStillOpen.selector);
        dwbtc.reclaimBurn(0);
    }


    // Reward Claiming Tests
    function testClaimStakerReward() public {
        mintForUser(user, 10000000);
        vm.prank(stakers[0]);
        dwbtc.claimStakerReward();

        assertEq(dwbtc.balanceOf(stakers[0]), dwbtc.cumulativeRewardPerStaker()); // Already claimed
    }
    function testClaimStakerRewardNoReward() public {
        vm.prank(stakers[0]);
        vm.expectRevert(DWBTC.NoRewardToClaim.selector);
        dwbtc.claimStakerReward();
    }

    function testDistributeDust() public {
        mintForUser(user, 1); // Accumulate some dust
        mintForUser_2(user, 1); // Accumulate some dust
        uint256 before_staker_reward =  dwbtc.cumulativeRewardPerStaker();

        vm.prank(stakers[0]);
        dwbtc.distributeDust();

        assertGt(dwbtc.cumulativeRewardPerStaker(), before_staker_reward);
    }

    // Admin Tests
    function testChangeVerifierAddress() public {
        vm.prank(owner);
        dwbtc.change_verifier_address(address(0x6));
        assertEq(dwbtc.verifier(), address(0x6));
    }
}