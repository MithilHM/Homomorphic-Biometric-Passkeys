// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {PackedUserOperation} from "../interfaces/IEntryPoint.sol";

/**
 * @title IAuthorizationVerifier
 * @notice The trust boundary between a smart account and the off-chain decision.
 */
interface IAuthorizationVerifier {
    /**
     * @notice Verify a biometric authorization for a specific operation.
     * @dev MUST revert (or return a falsy result) for: replayed session ids,
     *      expired authorizations, wrong wallet, wrong chain, wrong userOpHash,
     *      a false decision, or a policy the account does not accept.
     */
    function verify(
        address account,
        bytes32 userOpHash,
        uint256 chainId,
        Authorization calldata authorization
    ) external view returns (bool);

    function consumed(bytes16 sessionId) external view returns (bool);

    /// @notice One-time consumption; separate from `verify` so validation can
    ///         check cheaply and only a successful execution marks it used.
    function consume(bytes16 sessionId) external;

    function verifyAndConsume(
        address account,
        bytes32 userOpHash,
        uint256 chainId,
        Authorization calldata authorization
    ) external returns (bool);
}

/// @notice The canonical authorization object (PRD section 15).
struct Authorization {
    uint8 version;
    address wallet;
    uint64 chainId;
    bytes32 userOpHash;
    bytes16 sessionId;
    bytes32 policyHash;
    uint32 templateVersion;
    uint32 fheKeyVersion;
    bool decision;
    uint32 thresholdBps;
    bytes32 resultCommitment;
    uint64 issuedAt;
    uint64 expiresAt;
    uint32 proofSystem;
    uint32 verifierVersion;
    bytes32 decisionProgramHash;
    bytes32 attestationHash;
    bytes signature; // 65-byte secp256k1 signature over EIP-191(attestationHash)
}

/// @notice Versioned verifier registry (governance controlled).
interface IProofVerifierRegistry {
    function verifier(uint32 proofSystem, uint32 verifierVersion) external view returns (address);

    function isAcceptedDecisionProgram(bytes32 programHash) external view returns (bool);
}

interface ISessionKeyRegistry {
    function validate(
        address wallet,
        address sessionKey,
        address target,
        bytes4 selector,
        uint256 value
    ) external returns (uint256 spent);

    function spend(address wallet, address sessionKey, address target, bytes4 selector, uint256 value)
        external
        returns (uint256 spent);

    function revoke(address sessionKey) external;

    function grant(
        address sessionKey,
        uint64 validUntil,
        uint256 maxValuePerTx,
        uint32 nonceDomain,
        address[] calldata allowedTargets,
        bytes4[] calldata allowedSelectors,
        bytes32 scopeHash
    ) external;
}

interface IRecoveryRegistry {
    function isRecoveryPending(address wallet) external view returns (bool);

    function initiate(bytes32 newPasskeyHash, uint64 delay) external returns (bytes32 requestId);

    function cancel(bytes32 requestId) external;

    function finalize(bytes32 requestId, bytes32 newPasskeyHash) external;
}
