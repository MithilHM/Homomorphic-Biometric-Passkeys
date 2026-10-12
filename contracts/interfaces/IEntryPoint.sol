// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title PackedUserOperation
 * @notice The ERC-4337 v0.7 UserOperation struct and EntryPoint interface.
 *
 * @dev Declared locally rather than vendored so the account compiles against a
 *      pinned, auditable copy of the standard's data layout. The field ORDER is
 *      part of the protocol: it determines the userOpHash the passkey signature
 *      and the biometric authorization both commit to.
 */

struct PackedUserOperation {
    address sender;
    uint256 nonce;
    bytes initCode;
    bytes callData;
    uint256 callGasLimit;
    uint256 verificationGasLimit;
    uint256 preVerificationGas;
    uint256 maxPriorityFeePerGas;
    uint256 maxFeePerGas;
    bytes paymasterAndData;
    bytes signature;
}

/// @notice Validation data conventions from ERC-4337 v0.7.
library ValidationData {
    uint256 internal constant VALIDATION_SUCCESS = 0;
    uint256 internal constant SIG_FAILED = 1;

    uint256 internal constant OFFSET_TIME_RANGE = 0xFFFFFF;
    uint256 internal constant OFFSET_VALIDATION_FAILED = 1 << 255;

    function pack(address aggregator, uint32 sigFailed, uint64 validUntil) internal pure returns (uint256) {
        uint256 timeRange = (uint256(validUntil) << (64 + 32)) | uint256(uint32(sigFailed));
        return uint256(uint160(aggregator)) | timeRange;
    }

    function unpack(uint256 validationData) internal pure returns (address aggregator, bool failed, uint48 validUntil) {
        aggregator = address(uint160(validationData));
        failed = (validationData & OFFSET_VALIDATION_FAILED) != 0;
        validUntil = uint48(validationData >> (64 + 32));
    }

    function getSigFailed(uint256 validationData) internal pure returns (bool) {
        return (validationData >> (64 + 32)) & 0x01 == 1;
    }

    function getAggregator(address aggregator, uint256 validationData) internal pure returns (address) {
        if (validationData == 0) return address(0);
        if (validationData >> 160 != 0) return address(uint160(validationData));
        return aggregator;
    }
}

interface IEntryPoint {
    struct UserOpsPerAggregator {
        PackedUserOperation[] userOps;
        address aggregator;
        bytes signature;
    }

    function handleOps(PackedUserOperation[] calldata ops, address payable beneficiary) external;

    function handleAggregatedOps(UserOpsPerAggregator[] calldata opsPerAggregator, address payable beneficiary) external;

    function getUserOpHash(PackedUserOperation calldata userOp) external view returns (bytes32);

    function getNonce(address sender, uint192 key) external view returns (uint256 nonce);

    function incrementNonce(uint192 key) external;

    function depositTo(address account) external payable;

    function balanceOf(address account) external view returns (uint256);

    function withdrawTo(address payable withdrawAddress, uint256 withdrawAmount) external;

    function addStake(uint32 unstakeDelaySec) external payable;

    function unlockStake() external;

    function withdrawStake(address payable withdrawAddress) external;

    function getDepositInfo(address account)
        external
        view
        returns (uint112 deposit, bool staked, uint112 stake, uint32 unstakeDelaySec, uint48 withdrawTime);

    function senderCreator() external view returns (address);

    function delegateAndRevert(address target, bytes calldata data) external;
}

interface IAccount {
    function validateUserOp(PackedUserOperation calldata userOp, bytes32 userOpHash, uint256 missingAccountFunds)
        external
        returns (uint256 validationData);
}

