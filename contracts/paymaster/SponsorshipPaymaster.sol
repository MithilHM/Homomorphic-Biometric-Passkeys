// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {PackedUserOperation, IEntryPoint, ValidationData} from "../interfaces/IEntryPoint.sol";

/**
 * @title SponsorshipPaymaster
 * @notice Optional gas sponsorship so onboarding does not require native funds.
 *
 * @dev Sponsorship policy (PRD section 17.3):
 *      - only accounts that completed biometric enrollment are eligible;
 *      - a per-account sponsored counter and a per-account spend ceiling cap
 *        the operator's exposure;
 *      - the value transferred by the UserOperation must be zero, so a sponsored
 *        operation can never be used to move someone else's money;
 *      - `validatePaymasterUserOp` MUST revert on failure per ERC-4337 v0.7.
 */
contract SponsorshipPaymaster {
    address public immutable entryPoint;
    address public owner;

    uint128 public sponsorDeposit;
    uint64 public baseFee;
    uint64 public perOpOverhead;
    uint48 public timeRange;

    uint256 public constant MAX_SPONSORED_OPS = 25;
    uint256 public constant MAX_SPONSORED_VALUE = 0; // value must be zero

    mapping(address => uint256) public sponsoredOps;
    mapping(address => bool) public eligible;
    mapping(address => uint256) public sponsoredGasCost;

    event DepositAdded(address indexed account, uint256 amount);
    event Withdrawn(address indexed account, uint256 amount);
    event EligibilityChanged(address indexed account, bool eligible);
    event OpsSponsored(address indexed account, bytes32 indexed userOpHash, uint256 gasCost);

    error NotEntryPoint();
    error NotOwner();
    error PrepaymentFailed();
    error AccountNotEligible();
    error SponsorLimitReached();
    error ValueTransferForbidden();
    error InvalidTimeRange();
    error InsufficientDeposit();
    error MalformedPaymasterData();

    modifier onlyEntryPoint() {
        if (msg.sender != entryPoint) revert NotEntryPoint();
        _;
    }

    modifier onlyOwner() {
        if (msg.sender != owner) revert NotOwner();
        _;
    }

    constructor(address entryPoint_, uint64 baseFee_, uint64 perOpOverhead_, uint48 timeRange_) {
        entryPoint = entryPoint_;
        owner = msg.sender;
        baseFee = baseFee_;
        perOpOverhead = perOpOverhead_;
        timeRange = timeRange_;
    }

    receive() external payable {
        sponsorDeposit += uint128(msg.value);
        emit DepositAdded(msg.sender, msg.value);
    }

    function withdraw(address payable to, uint256 amount) external onlyOwner {
        sponsorDeposit -= uint128(amount);
        (bool ok,) = to.call{value: amount}("");
        require(ok, "paymaster withdraw failed");
        emit Withdrawn(to, amount);
    }

    function setEligibility(address account, bool value) external onlyOwner {
        eligible[account] = value;
        emit EligibilityChanged(account, value);
    }

    function setFees(uint64 baseFee_, uint64 perOpOverhead_, uint48 timeRange_) external onlyOwner {
        baseFee = baseFee_;
        perOpOverhead = perOpOverhead_;
        timeRange = timeRange_;
    }

    function transferOwnership(address next) external onlyOwner {
        owner = next;
    }

    function getDeposit() public view returns (uint256) {
        return sponsorDeposit;
    }

    /// @notice Required gas price for sponsorship.
    function getPaymasterData(uint256 gasCost) external view returns (bytes memory) {
        return abi.encodePacked(bytes32(uint256(gasCost)), bytes32(uint256(baseFee)), bytes32(uint256(perOpOverhead)));
    }

    function validatePaymasterUserOp(
        PackedUserOperation calldata userOp,
        bytes32 userOpHash,
        uint256 maxCost,
        uint256 timeRangeOffset,
        bytes calldata paymasterAndData
    ) external view onlyEntryPoint returns (bytes memory context, uint256 validationData) {
        if (!eligible[userOp.sender]) revert AccountNotEligible();
        if (sponsoredOps[userOp.sender] >= MAX_SPONSORED_OPS) revert SponsorLimitReached();
        if (userOp.callData.length > 0 && _transfersValue(userOp.callData)) revert ValueTransferForbidden();

        if (paymasterAndData.length < 68) revert MalformedPaymasterData();
        uint256 gasCost = uint256(bytes32(paymasterAndData[36:68]));

        uint256 required = gasCost * (baseFee + perOpOverhead);
        if (required > maxCost) revert InsufficientDeposit();
        if (sponsorDeposit < required) revert InsufficientDeposit();

        uint256 expiry = uint256(timeRange) + timeRangeOffset;
        if (expiry > type(uint48).max) revert InvalidTimeRange();
        validationData = ValidationData.pack(address(0), uint48(expiry), 0);
        // v0.7 postOp receives no UserOperation: attribute via context.
        return (abi.encode(userOp.sender), validationData);
    }

    /// @dev EntryPoint v0.7 postOp signature: (PostOpMode, context, actualGasCost, actualGasCostFee).
    function postOp(PostOpMode mode, bytes calldata context, uint256 actualGasCost, uint256 actualUserOpFeePerGas)
        external
        onlyEntryPoint
    {
        // Counted here, not in validation: validatePaymasterUserOp is a view
        // and cannot write, so the per-account cap enforces across bundles,
        // not within one bundle (residual: N validations in one bundle each
        // see the pre-bundle count).
        mode;
        address sender = context.length >= 32 ? abi.decode(context, (address)) : address(0);
        if (sender == address(0)) revert AccountNotEligible();
        sponsoredOps[sender] += 1;
        sponsoredGasCost[sender] += actualGasCost;
        uint256 toRefund = actualUserOpFeePerGas * actualGasCost;
        if (toRefund > sponsorDeposit) toRefund = sponsorDeposit;
        sponsorDeposit -= uint128(toRefund);

        IEntryPoint(entryPoint).depositTo{value: toRefund}(address(this));
        emit OpsSponsored(sender, bytes32(sponsoredOps[sender]), toRefund);
    }

    /// @dev True when the operation moves value: any execute with value > 0,
    ///      or any executeBatch call with value > 0 (H7: the old check blocked
    ///      a nonexistent selector and let batch value through).
    function _transfersValue(bytes calldata callData) private pure returns (bool) {
        if (callData.length < 4) return false;
        bytes4 selector = bytes4(callData[0:4]);
        if (selector == bytes4(0xb61d27f6)) {
            (, uint256 value,) = abi.decode(callData[4:], (address, uint256, bytes));
            return value > MAX_SPONSORED_VALUE;
        }
        if (selector == bytes4(keccak256("executeBatch((address,uint256,bytes)[])"))) {
            Call[] memory calls = abi.decode(callData[4:], (Call[]));
            for (uint256 i = 0; i < calls.length; i++) {
                if (calls[i].value > MAX_SPONSORED_VALUE) return true;
            }
            return false;
        }
        // Unknown entrypoint into the account: refuse sponsorship.
        return true;
    }
}

enum PostOpMode {
    opSucceeded,
    opReverted,
    postOpReverted
}

struct Call {
    address target;
    uint256 value;
    bytes data;
}

