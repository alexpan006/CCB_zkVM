// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {ISP1Verifier} from "../lib/sp1-contracts/contracts/src/ISP1Verifier.sol";
import {ERC20} from "lib/openzeppelin-contracts/contracts/token/ERC20/ERC20.sol";
import {Ownable} from "lib/openzeppelin-contracts/contracts/access/Ownable.sol";
import {ReentrancyGuard} from "../lib/openzeppelin-contracts/contracts/utils/ReentrancyGuard.sol";
/// @title DWBTC - Decentralized Wrapped Bitcoin
/// @notice This contract verifies proofs and mints/burns tokens based on verified transactions
contract DWBTC is ERC20, Ownable, ReentrancyGuard {
    address public verifier;
    bytes32 public programVKey_mint;
    bytes32 public programVKey_burn;
    uint256 public constant FEE = 100; // 1% fee in basis points (100 = 1%)
    uint256 public constant SATOSHI_TO_DWBTC = 10**10;// Conversion factor: 1 satoshi = 10^10 DWBTC units


    address[] public stakers;
    mapping(address => bool) public isStaker;
    mapping(address => uint256) public claimedReward;
    uint256 public cumulativeRewardPerStaker;
    uint256 public dustCollected;

    // Staker related variables
    mapping(address => uint256) public stakerInitialLocked;
    mapping(address => uint256) public stakerUnlocked;
    mapping(address => uint256) public stakerLastUnlockTime;
    mapping(address => uint256) public stakerForeverLocked;
    uint256 public initialMintUnlockStart;
    uint256 public initialMintUnlockEnd;
    bool public initialMinted;


    // Mapping to track processed transaction IDs
    mapping(bytes32 => bool) public processedTxIds;

    // Burn request structure
    struct BurnRequest {
        address user;
        uint256 total_amount; // DWBTC units burned
        uint256 dwbtcToReimburse;       // DWBTC units to reimburse operator
        uint256 exactBtcUserReceive; // satoshis operator must send to user
        uint256 rewardOperator; // DWBTC units
        uint256 rewardStaker; // DWBTC units
        uint256 dust; // DWBTC units
        string btcAddress;
        uint256 timestamp;
        bool fulfilled;
        bool reclaimed;
    }

    mapping(uint256 => BurnRequest) public burnRequests;
    uint256 public nextBurnId = 0;
    uint256 public constant SUBMISSION_PERIOD = 1 days;
    string public  BRIDGE_ADDRESS;

    // Reward percentages in basis points (1% = 100 basis points)
    uint256 public constant BURN_SUBMITTER_REWARD = 50; // 0.5%
    uint256 public constant BURN_STAKER_REWARD = 50; // 0.5%
    uint256 public constant MIN_MINTING_AMOUNT = 1*SATOSHI_TO_DWBTC; // 1 satoshi

    // Events
    event ProofVerifiedAndMinted(bytes32 indexed txId, address indexed depositer, uint256 amount, bool isValid);
    event BurnInitiated(uint256 indexed burnId, address indexed user, uint256 amount, string btcAddress);
    event BurnFulfilled(uint256 indexed burnId, address indexed submitter);
    event BurnReclaimed(uint256 indexed burnId, address indexed user, uint256 amount);
    event DustDistributed(uint256 distributedPerStaker, uint256 remainingDust);
    event StakerRewardClaimed(address indexed staker, uint256 amount);
    event OperatorReward(address indexed operator, uint256 amount);
    event StakerRewardAdded(uint256 amount);
    event StakerDustAdded(uint256 amount);

    // Error messages

    // Mint related errors
    error InvalidProof();
    error InvalidProofFromVerifier();
    error MintingRequestAlreadyProcessed();
    error MintingAmountZero();
    error MintingAmountTooSmall();

    // Burn related errors
    error BurnRequestNotFound();
    error BurnAlreadyFulfilled();
    error BurnRequestExpired();
    error BurnRequestAlreadyReclaimed();
    error OperatorUnderpaid();
    error ReclaimNotRequester();
    error BurnAmountZero();
    error OperatorSendWrongRecipent();
    error BurnAmountTooSmall();
    error BurnInsufficientBalance();
    error BurnRequestStillOpen();

    // Reward related errors
    error NotStaker();
    error RewardZero();
    error NoRewardToClaim();
    error DustTooLow();

    // Common errors
    error InvalidAddress();
    error StakerRequired();
    error InitializationStakerListError();

    // Initial mint related errors
    error InitialMintAlreadyDone();
    error InitialMintAmountTooSmall();

    constructor(
        address _verifier,
        bytes32 _programVKey_mint,
        bytes32 _programVKey_burn,
        string memory _bridge_address,
        address[] memory _stakers
    ) ERC20("Decentralized Wrapped Bitcoin", "DWBTC") Ownable(msg.sender) {
        verifier = _verifier;
        programVKey_mint = _programVKey_mint;
        programVKey_burn = _programVKey_burn;
        BRIDGE_ADDRESS = _bridge_address;

        require(_stakers.length > 0, "Stakers required");
        for (uint256 i = 0; i < _stakers.length; i++) {
            address s = _stakers[i];
            require(s != address(0) && !isStaker[s], InitializationStakerListError());
            stakers.push(s);
            isStaker[s] = true;
        }
    }

    function initialMint(
    uint256 amountPerStaker,
    uint256 foreverLockedAmount,
    uint256 unlockDuration
    )
    external
    onlyOwner
    {
        require(!initialMinted, "Already minted");
        require(amountPerStaker > foreverLockedAmount, "Forever locked must be less than minted");
        initialMinted = true;
        initialMintUnlockStart = block.timestamp;
        initialMintUnlockEnd = block.timestamp + unlockDuration;

        for (uint256 i = 0; i < stakers.length; i++) {
            address s = stakers[i];
            _mint(s, amountPerStaker);
            stakerInitialLocked[s] = amountPerStaker;
            stakerUnlocked[s] = 0;
            stakerLastUnlockTime[s] = block.timestamp;
            stakerForeverLocked[s] = foreverLockedAmount;
        }
    }

    /// @notice Verifies a proof and mints DWBTC, deducting a fee for the staking pool
    function verifyAndMint(bytes calldata _publicValues, bytes calldata _proofBytes)
        external
        nonReentrant 
        returns (bytes32, address, uint256, bool)
    {
        try ISP1Verifier(verifier).verifyProof(programVKey_mint, _publicValues, _proofBytes) {}
        catch {
            revert("Invalid proof from verifier");
        }

        (bytes32 tx_id, address depositer_address, uint256 amount, bool is_valid) =
            abi.decode(_publicValues, (bytes32, address, uint256, bool));

        require(!processedTxIds[tx_id], MintingRequestAlreadyProcessed());
        require(is_valid, InvalidProof());
        require(amount > 0, MintingAmountZero());
        require(depositer_address != address(0), InvalidAddress());

        processedTxIds[tx_id] = true;

        amount*=SATOSHI_TO_DWBTC; // Convert to DWBTC units
        require(amount >= MIN_MINTING_AMOUNT, MintingAmountTooSmall());

        
        uint256 userAmount = (amount * (10000 - FEE)) / 10000; // 99%
        uint256 feeAmount = amount - userAmount; // 1%
        uint256 operatorReward = feeAmount/2; // 0.5%
        uint256 stakerReward =amount- userAmount - operatorReward; // 0.5% + dust

        _mint(depositer_address, userAmount);           // User gets 99%
        _mint(msg.sender, operatorReward);        // Operator gets 0.5% directly
        _mint(address(this), stakerReward); // Mint to contract for stakers, and later it could be distributed
        _addRewardToStakers(stakerReward);
        emit OperatorReward(msg.sender, operatorReward);
        emit ProofVerifiedAndMinted(tx_id, depositer_address, userAmount, is_valid);
        return (tx_id, depositer_address, userAmount, is_valid);
    }

    function initiateBurn(uint256 amountRequestBurnDwbtc, string calldata btcAddress)
        external
    {
        require(balanceOf(msg.sender) >= amountRequestBurnDwbtc , BurnInsufficientBalance());
        require(amountRequestBurnDwbtc >= MIN_MINTING_AMOUNT, BurnAmountTooSmall());
        

        uint256 feeAmount = (amountRequestBurnDwbtc * FEE) / 10000; // Calculate fee
        uint256 dwbtcAvailable = amountRequestBurnDwbtc - feeAmount; // total amount of DWBTC that will be redeemed

        uint256 userSatoshi = dwbtcAvailable / SATOSHI_TO_DWBTC; // Convert to satoshis, indicating how many satoshis the user will receive in bitcoin.

        uint256 actualDwbtcSent = userSatoshi * SATOSHI_TO_DWBTC; // Indicating how many wbtc the operator will get reimbursed.
        uint256 dust = dwbtcAvailable - actualDwbtcSent;// Calculate dust (remainder that can't be converted to whole satoshis)

        // Distribute fee between operator and stakers
        uint256 operatorReward = feeAmount / 2;
        uint256 stakerReward = feeAmount - operatorReward;

        _transfer(msg.sender, address(this), amountRequestBurnDwbtc);

        // Store the burn request with adjusted total_amount
        burnRequests[nextBurnId] = BurnRequest({
            user: msg.sender,
            total_amount: amountRequestBurnDwbtc,        // Net DWBTC burned
            dwbtcToReimburse: actualDwbtcSent,       // DWBTC to reimburse operator
            exactBtcUserReceive: userSatoshi, // Exact satoshis user receives
            rewardOperator: operatorReward,
            rewardStaker: stakerReward,
            dust: dust,
            btcAddress: btcAddress,
            timestamp: block.timestamp,
            fulfilled: false,
            reclaimed: false
        });

        emit BurnInitiated(nextBurnId, msg.sender, userSatoshi, btcAddress);
        nextBurnId++;
    }

    /// @notice Submits a proof that BTC was sent to the user’s BTC address
    function submitBurnProof(uint256 burnId, bytes calldata _publicValues, bytes calldata _proofBytes)
        external
        nonReentrant 
    {
        BurnRequest storage request = burnRequests[burnId];
        require(request.user != address(0), BurnRequestNotFound());
        require(!request.fulfilled, BurnAlreadyFulfilled());
        require(block.timestamp <= request.timestamp + SUBMISSION_PERIOD, BurnRequestExpired());

        try ISP1Verifier(verifier).verifyProof(programVKey_burn, _publicValues, _proofBytes) {}
        catch {
            revert("Invalid proof");
        }
        (string memory user_btc_address, uint256 amount,bool is_valid) = abi.decode(_publicValues, (string, uint256, bool));

        require(is_valid, InvalidProof());
        require(
            keccak256(abi.encodePacked(burnRequests[burnId].btcAddress)) == 
            keccak256(abi.encodePacked(user_btc_address)),
            OperatorSendWrongRecipent()
        );
        require(amount >= burnRequests[burnId].exactBtcUserReceive, OperatorUnderpaid()); 

        request.fulfilled = true;

        // Send escrowed DWBTC to submitter
        _transfer(address(this), msg.sender, request.dwbtcToReimburse);
        _transfer(address(this), msg.sender, request.rewardOperator); // Operator reward
        _transfer(address(this), request.user, request.dust); // Dust back to user

        _addRewardToStakers(request.rewardStaker);
        emit OperatorReward(msg.sender, request.rewardOperator);
        emit BurnFulfilled(burnId, msg.sender);
    }
    

    /// @notice Reclaims DWBTC if no proof is submitted within the period
    function reclaimBurn(uint256 burnId)
        external
        nonReentrant 
    {
        BurnRequest storage request = burnRequests[burnId];
        require(request.user == msg.sender, ReclaimNotRequester());
        require(!request.reclaimed, BurnRequestAlreadyReclaimed());
        require(!request.fulfilled, BurnAlreadyFulfilled());
        require(block.timestamp > request.timestamp + SUBMISSION_PERIOD, BurnRequestStillOpen());

        request.reclaimed = true;
        request.fulfilled = true;
        _transfer(address(this), msg.sender, request.total_amount);
        emit BurnReclaimed(burnId, msg.sender, request.total_amount);
    }

    // Admin functions
    function change_verifier_address(address new_address) external onlyOwner {
        require(new_address != address(0), InvalidAddress());
        verifier = new_address;
    }

    function change_program_key_mint(bytes32 new_pvkey) external onlyOwner {
        programVKey_mint = new_pvkey;
    }

    function change_program_key_burn(bytes32 new_pvkey) external onlyOwner {
        programVKey_burn = new_pvkey;
    }


    // -------------------- Reward claiming related functions ----------------------
    function _addRewardToStakers(uint256 totalReward) internal {
        require(stakers.length > 0, StakerRequired());
        require(totalReward > 0, RewardZero());
        uint256 n = stakers.length;
        uint256 rewardPerStaker = totalReward / n;
        uint256 dust = totalReward - (rewardPerStaker * n);
        cumulativeRewardPerStaker += rewardPerStaker;
        dustCollected += dust;
        emit StakerRewardAdded(totalReward);
        emit StakerDustAdded(dust);
    }

    function claimStakerReward()
        external
        nonReentrant 
    {
        require(isStaker[msg.sender], NotStaker());
        uint256 reward = cumulativeRewardPerStaker - claimedReward[msg.sender];
        require(reward > 0, NoRewardToClaim());
        claimedReward[msg.sender] = cumulativeRewardPerStaker;
        _transfer(address(this),msg.sender, reward);
        emit StakerRewardClaimed(msg.sender, reward);
    }

    function distributeDust()
        external
        nonReentrant 
    {
        require(dustCollected >= stakers.length, DustTooLow());
        uint256 dustPerStaker = dustCollected / stakers.length;
        dustCollected -= (dustPerStaker * stakers.length);
        cumulativeRewardPerStaker += dustPerStaker;
        emit DustDistributed(dustPerStaker, dustCollected);
    }
}

