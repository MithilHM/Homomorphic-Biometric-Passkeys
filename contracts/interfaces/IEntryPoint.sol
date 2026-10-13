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
///
/// Layout (all standard, so a real EntryPoint parses what we return):
///   [0..160)   aggregator address (zero when no aggregator is used)
///   [160..208) validUntil (uint48, 0 = no expiry bound from this field)
///   [208..256) validAfter (uint48, 0 = effective immediately)
library ValidationData {
    uint256 internal constant VALIDATION_SUCCESS = 0;

    function pack(address aggregator, uint48 validUntil, uint48 validAfter) internal pure returns (uint256) {
        return uint256(uint160(aggregator)) | (uint256(validUntil) << 160) | (uint256(validAfter) << 208);
    }

    function unpack(uint256 validationData)
        internal
        pure
        returns (address aggregator, bool failed, uint48 validUntil)
    {
        aggregator = address(uint160(validationData));
        // This account reverts on failure instead of returning a failure flag.
        failed = false;
        validUntil = uint48(validationData >> 160);
    }

    function getSigFailed(uint256) internal pure returns (bool) {
        return false;
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

