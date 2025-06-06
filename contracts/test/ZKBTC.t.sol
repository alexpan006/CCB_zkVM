// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import {ZKBTC} from "../src/ZKBTC.sol";
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

contract ZKBTCTest is Test {
    ZKBTC zkbtc;
    MockSP1Verifier verifier;
    address owner = address(0x1);
    address user = address(0x2);
    address operator = address(0x3);
    address operator2 = address(0x4);
    address[] stakers = [address(0x5), address(0x6), address(0x7)];

    string bridge = "abc";

    bytes32 constant PROGRAM_VKEY_MINT = keccak256("mint");
    bytes32 constant PROGRAM_VKEY_BURN = keccak256("burn");
    uint256 constant SATOSHI_TO_ZKBTC = 10**10;
    uint256 constant SUBMISSION_PERIOD = 1 days;

    function setUp() public {
        vm.startPrank(owner);
        verifier = new MockSP1Verifier(true);
        zkbtc = new ZKBTC(address(verifier), PROGRAM_VKEY_MINT, PROGRAM_VKEY_BURN, bridge,stakers);
        vm.stopPrank();
    }
    // Helper function to mint tokens for testing
    function mintForUser(address _user, uint256 satoshis) internal {
        vm.startPrank(operator2);
        bytes memory publicValues = abi.encode(keccak256("tx1"), _user, satoshis, true);
        bytes memory proofBytes = hex"1234";
        zkbtc.verifyAndMint(publicValues, proofBytes);
        vm.stopPrank();
    }
    function mintForUser_2(address _user, uint256 satoshis) internal {
        vm.startPrank(operator2);
        bytes memory publicValues = abi.encode(keccak256("tx2"), _user, satoshis, true);
        bytes memory proofBytes = hex"1234";
        zkbtc.verifyAndMint(publicValues, proofBytes);
        vm.stopPrank();
    }

    // Minting Tests
    function testVerifyAndMintHappyPath() public {
        uint256 satoshis = 100000;
        bytes memory publicValues = abi.encode(keccak256("tx1"), user, satoshis, true);
        bytes memory proofBytes = hex"1234";

        vm.prank(operator);
        (bytes32 txId, address depositer, uint256 amount, bool isValid) = 
            zkbtc.verifyAndMint(publicValues, proofBytes);

        uint256 amountZkbtc = satoshis * SATOSHI_TO_ZKBTC;
        uint256 userAmount = (amountZkbtc * 9900) / 10000;
        uint256 feeAmount = amountZkbtc - userAmount;
        uint256 operatorReward = feeAmount / 2;
        uint256 stakerReward = feeAmount - operatorReward;

        assertEq(zkbtc.balanceOf(user), userAmount);
        assertEq(zkbtc.balanceOf(operator), operatorReward);
        assertEq(zkbtc.balanceOf(address(zkbtc)), stakerReward);
        assertEq(zkbtc.totalSupply(), userAmount + operatorReward + stakerReward+(1*1e18)*3);
        assertEq(txId, keccak256("tx1"));
        assertEq(depositer, user);
        assertEq(amount, userAmount);
        assertTrue(isValid);
    }

    function testVerifyAndMintMinAmount() public {
        uint256 satoshis = 1; // 1 satoshi = 10,000 ZKBTC units, above min 15,000
        bytes memory publicValues = abi.encode(keccak256("tx2"), user, satoshis, true);
        bytes memory proofBytes = hex"1234";

        vm.prank(operator);
        zkbtc.verifyAndMint(publicValues, proofBytes);

        uint256 amountZkbtc = satoshis * SATOSHI_TO_ZKBTC;
        uint256 userAmount = (amountZkbtc * 9900) / 10000;
        assertEq(zkbtc.balanceOf(user), userAmount);
    }

    function testVerifyAndMintBelowMinAmount() public {
        uint256 satoshis = 0; // Will result in < 15,000 ZKBTC units
        bytes memory publicValues = abi.encode(keccak256("tx3"), user, satoshis, true);
        bytes memory proofBytes = hex"1234";

        vm.prank(operator);
        vm.expectRevert(ZKBTC.MintingAmountZero.selector);
        zkbtc.verifyAndMint(publicValues, proofBytes);
    }

    function testVerifyAndMintInvalidProof() public {
        verifier.setShouldPass(false);
        bytes memory publicValues = abi.encode(keccak256("tx4"), user, 100_000, true);
        bytes memory proofBytes = hex"1234";

        vm.prank(operator);
        vm.expectRevert("Invalid proof from verifier");
        zkbtc.verifyAndMint(publicValues, proofBytes);
    }

    function testVerifyAndMintReuseTxId() public {
        bytes memory publicValues = abi.encode(keccak256("tx1"), user, 100_000, true);
        bytes memory proofBytes = hex"1234";

        vm.startPrank(operator);
        zkbtc.verifyAndMint(publicValues, proofBytes);
        vm.expectRevert(ZKBTC.MintingRequestAlreadyProcessed.selector);
        zkbtc.verifyAndMint(publicValues, proofBytes);
        vm.stopPrank();
    }

    // Burning Tests
    function testInitiateBurnHappyPath() public {
        mintForUser(user, 100_0000_0000_0000); // Mint 100,000 satoshis worth
        uint256 burnAmount = zkbtc.balanceOf(user); // 1M ZKBTC units
        // uint256 burnAmount = 100_0000_0000_0000; // 1M ZKBTC units

        vm.prank(user);
        zkbtc.initiateBurn(burnAmount, "btcAddress");
        (
            address temp_user,
            uint256 total_amount,
            uint256 zkbtcToReimburse,
            uint256 exactBtcUserReceive,
            uint256 rewardOperator,
            uint256 rewardStaker,
            uint256 dust,
            string memory btcAddress,
            uint256 timestamp,
            bool fulfilled,
            bool reclaimed
        ) = zkbtc.burnRequests(0);

        ZKBTC.BurnRequest memory request = ZKBTC.BurnRequest({
            user: temp_user,
            total_amount: total_amount,
            zkbtcToReimburse: zkbtcToReimburse,
            exactBtcUserReceive: exactBtcUserReceive,
            rewardOperator: rewardOperator,
            rewardStaker: rewardStaker,
            dust: dust,
            btcAddress: btcAddress,
            timestamp: timestamp,
            fulfilled: fulfilled,
            reclaimed: reclaimed
        });



        uint256 expectedAmount = (burnAmount * 9900 / 10000) / SATOSHI_TO_ZKBTC;
        assertEq(request.user, user); // Ensure the user is correct
        assertEq(request.total_amount, burnAmount); // Ensure the total amount is correct(in ZKBTC units)
        assertEq(request.exactBtcUserReceive, expectedAmount); // Ensure the exact BTC user receives is correct(btc units)
        assertFalse(request.fulfilled); // Ensure the request is not fulfilled
        assertFalse(request.reclaimed); // Ensure the request is not reclaimed
        assertEq(zkbtc.balanceOf(user), 0); // User's balance should be 0 after burn initiation
    }

    function testInitiateBurnInsufficientBalance() public {
        mintForUser(user, 100); // Mint 100,000 satoshis worth
        vm.prank(user);
        vm.expectRevert(ZKBTC.BurnInsufficientBalance.selector);
        zkbtc.initiateBurn(100_0000_0000_000, "btcAddress");
    }

    function testInitiateBurnInvalidAmount() public {
        mintForUser(user, 100000);
        vm.prank(user);
        vm.expectRevert(ZKBTC.BurnAmountTooSmall.selector);
        zkbtc.initiateBurn(100000, "btcAddress");
    }

    function testSubmitBurnProofHappyPath() public {
        // mintForUser(user, 100_0000_0000); // Mint 100,000 satoshis worth
        mintForUser(user, 12353); // Mint 100,000 satoshis worth
        uint256 burnAmount = zkbtc.balanceOf(user); // 1M ZKBTC units

        vm.prank(user);
        zkbtc.initiateBurn(burnAmount, "btcAddress");
        (
            address temp_user,
            uint256 total_amount,
            uint256 zkbtcToReimburse,
            uint256 exactBtcUserReceive,
            uint256 rewardOperator,
            uint256 rewardStaker,
            uint256 dust,
            string memory btcAddress,
            uint256 timestamp,
            bool fulfilled,
            bool reclaimed
        ) = zkbtc.burnRequests(0);

        ZKBTC.BurnRequest memory request = ZKBTC.BurnRequest({
            user: temp_user,
            total_amount: total_amount,
            zkbtcToReimburse: zkbtcToReimburse,
            exactBtcUserReceive: exactBtcUserReceive,
            rewardOperator: rewardOperator,
            rewardStaker: rewardStaker,
            dust: dust,
            btcAddress: btcAddress,
            timestamp: timestamp,
            fulfilled: fulfilled,
            reclaimed: reclaimed
        });

        bytes memory publicValues = abi.encode("btcAddress", (burnAmount* 9900 / SATOSHI_TO_ZKBTC), true);
        bytes memory proofBytes = hex"5678";

        vm.prank(operator);
        zkbtc.submitBurnProof(0, publicValues, proofBytes);
        console.log("Balance of user after burn",zkbtc.balanceOf(user),",dust:",request.dust);
        console.log("Balance of operator after burn",zkbtc.balanceOf(operator));
        console.log("Operator reimbursement:",request.zkbtcToReimburse,", reward:",request.rewardOperator);
        console.log("Staker reward:",request.rewardStaker);
        assertEq(zkbtc.balanceOf(user), request.dust); // User's balance should be equal to dust after burn
        (
            temp_user,
            total_amount,
            zkbtcToReimburse,
            exactBtcUserReceive,
            rewardOperator,
            rewardStaker,
            dust,
            btcAddress,
            timestamp,
            fulfilled,
            reclaimed
        ) = zkbtc.burnRequests(0);

        request = ZKBTC.BurnRequest({
            user: temp_user,
            total_amount: total_amount,
            zkbtcToReimburse: zkbtcToReimburse,
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
        assertEq(zkbtc.balanceOf(operator), request.zkbtcToReimburse + request.rewardOperator);
    }

    function testSubmitBurnProofAfterSubmissionPeriod()  public {
        mintForUser(user, 100_0000_0000); // Mint 100,000 satoshis worth
        uint256 burnAmount = zkbtc.balanceOf(user); // 1M ZKBTC units

        vm.prank(user);
        zkbtc.initiateBurn(burnAmount, "btcAddress");
        bytes memory publicValues = abi.encode("btcAddress", (burnAmount* 9900 / SATOSHI_TO_ZKBTC), true);
        bytes memory proofBytes = hex"5678";

        vm.prank(operator);
        // Warp to after submission period
        vm.warp(block.timestamp + SUBMISSION_PERIOD + 2);
        vm.expectRevert(ZKBTC.BurnRequestExpired.selector);
        zkbtc.submitBurnProof(0, publicValues, proofBytes);
    }

    function testReclaimBurnHappyPath() public {
        mintForUser(user, 10000000);
        uint256 burnAmount = zkbtc.balanceOf(user); // 1M ZKBTC units

        vm.prank(user);
        zkbtc.initiateBurn(burnAmount, "btcAddress");

        vm.warp(block.timestamp + 2 days );
        vm.prank(user);
        zkbtc.reclaimBurn(0);
        (
            address temp_user,
            uint256 total_amount,
            uint256 zkbtcToReimburse,
            uint256 exactBtcUserReceive,
            uint256 rewardOperator,
            uint256 rewardStaker,
            uint256 dust,
            string memory btcAddress,
            uint256 timestamp,
            bool fulfilled,
            bool reclaimed
        ) = zkbtc.burnRequests(0);

        ZKBTC.BurnRequest memory request = ZKBTC.BurnRequest({
            user: temp_user,
            total_amount: total_amount,
            zkbtcToReimburse: zkbtcToReimburse,
            exactBtcUserReceive: exactBtcUserReceive,
            rewardOperator: rewardOperator,
            rewardStaker: rewardStaker,
            dust: dust,
            btcAddress: btcAddress,
            timestamp: timestamp,
            fulfilled: fulfilled,
            reclaimed: reclaimed
        });
        // ZKBTC.BurnRequest memory request = zkbtc.burnRequests(0);
        assertTrue(request.reclaimed);
        assertTrue(request.fulfilled);
        assertEq(zkbtc.balanceOf(user), burnAmount);
    }
        
    function testReclaimBurnAlreadyClaimed() public {
        mintForUser(user, 10000000);
        uint256 burnAmount = zkbtc.balanceOf(user); 

        vm.prank(user);
        zkbtc.initiateBurn(burnAmount, "btcAddress");

        vm.warp(block.timestamp + 2 days );
        vm.prank(user);
        zkbtc.reclaimBurn(0);
        vm.expectRevert(ZKBTC.BurnRequestAlreadyReclaimed.selector);
        vm.prank(user);
        zkbtc.reclaimBurn(0);
    }
    function testReclaimOpenRequest() public {
        mintForUser(user, 10000000);
        uint256 burnAmount = zkbtc.balanceOf(user); 

        vm.prank(user);
        zkbtc.initiateBurn(burnAmount, "btcAddress");

        vm.warp(block.timestamp);
        vm.prank(user);
        vm.expectRevert(ZKBTC.BurnRequestStillOpen.selector);
        zkbtc.reclaimBurn(0);
    }


    // Reward Claiming Tests
    function testClaimStakerReward() public {
        mintForUser(user, 10000000);
        vm.prank(stakers[0]);
        zkbtc.claimStakerReward();

        assertEq(zkbtc.balanceOf(stakers[0]), zkbtc.cumulativeRewardPerStaker()+1*1e18); // Already claimed
    }
    function testClaimStakerRewardNoReward() public {
        vm.prank(stakers[0]);
        vm.expectRevert(ZKBTC.NoRewardToClaim.selector);
        zkbtc.claimStakerReward();
    }

    function testDistributeDust() public {
        mintForUser(user, 1); // Accumulate some dust
        mintForUser_2(user, 1); // Accumulate some dust
        uint256 before_staker_reward =  zkbtc.cumulativeRewardPerStaker();

        vm.prank(stakers[0]);
        zkbtc.distributeDust();

        assertGt(zkbtc.cumulativeRewardPerStaker(), before_staker_reward);
    }
    function testDistributeDustTooLow() public {
        mintForUser(user, 1); // Accumulate some dust
        vm.prank(stakers[0]);
        vm.expectRevert(ZKBTC.DustTooLow.selector);
        zkbtc.distributeDust();
    }


    // Admin Tests
    function testChangeVerifierAddress() public {
        vm.prank(owner);
        zkbtc.change_verifier_address(address(0x6));
        assertEq(zkbtc.verifier(), address(0x6));
    }

        // Setup phase for the tests
    function testStakerInitialMintOnDeploy() public {
        // After deployment, all stakers should have received their initial mint and lock state
        for (uint256 i = 0; i < stakers.length; i++) {
            address s = stakers[i];
            assertEq(zkbtc.balanceOf(s), zkbtc.INITIAL_MINT_PER_STAKER());
            assertEq(zkbtc.stakerInitialLocked(s), zkbtc.INITIAL_MINT_PER_STAKER());
            assertEq(zkbtc.stakerUnlocked(s), 0);
            assertEq(zkbtc.stakerForeverLocked(s), zkbtc.FOREVER_LOCKED_PER_STAKER());
            assertEq(zkbtc.initialMinted(), true);
        }
    }

    // For unlocking staker funds
    function testUnlockStakerTokensLinearUnlock() public {
        address staker = stakers[0];
        uint256 foreverLocked = zkbtc.FOREVER_LOCKED_PER_STAKER();
        uint256 totalLocked = zkbtc.INITIAL_MINT_PER_STAKER();
        uint256 unlockDuration = zkbtc.INITIAL_UNLOCK_DURATION();

        // Move forward half the unlock period
        vm.warp(block.timestamp + unlockDuration / 2);

        // Unlock tokens
        vm.prank(staker);
        zkbtc.unlockStakerTokens();

        // Calculate expected unlocked
        uint256 expectedUnlocked = ((totalLocked - foreverLocked) * (unlockDuration / 2)) / unlockDuration;
        assertApproxEqAbs(zkbtc.stakerUnlocked(staker), expectedUnlocked, 1e10); // Allow small rounding error
        assertEq(zkbtc.stakerLastUnlockTime(staker), block.timestamp);
    }

    function testUnlockStakerTokensAfterFullPeriod() public {
        address staker = stakers[0];
        uint256 foreverLocked = zkbtc.FOREVER_LOCKED_PER_STAKER();
        uint256 totalLocked = zkbtc.INITIAL_MINT_PER_STAKER();
        uint256 unlockDuration = zkbtc.INITIAL_UNLOCK_DURATION();

        // Move forward to exactly after unlock period
        vm.warp(block.timestamp + unlockDuration);

        vm.prank(staker);
        zkbtc.unlockStakerTokens();

        uint256 expectedUnlocked = totalLocked - foreverLocked;
        assertEq(zkbtc.stakerUnlocked(staker), expectedUnlocked);
        assertEq(zkbtc.stakerLastUnlockTime(staker), block.timestamp);
    }

    function testUnlockStakerTokensNothingToUnlock() public {
        address staker = stakers[0];

        // Unlock immediately (should be nothing to unlock)
        vm.prank(staker);
        zkbtc.unlockStakerTokens();

        // Should still be zero unlocked
        assertEq(zkbtc.stakerUnlocked(staker), 0);
    }

}