// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IAuthorizationVerifier, Authorization, IProofVerifierRegistry} from "../interfaces/IAuthorizationVerifier.sol";
import {AuthDomain} from "../protocol/AuthDomain.sol";

/**
 * @title AuthorizationVerifier
 * @notice Validates threshold-committee attestations for the biometric factor.
 *
 * @dev Design notes:
 *
 *      1. The biometric result is an AUTHORIZATION CONDITION, not a signature.
 *          This contract recovers the coprocessor committee's secp256k1
 *          signature and checks every binding field; it never treats
 *          `decision == true` on its own as sufficient.
 *      2. Replay protection is per-session and one-way: a session id that has
 *          been consumed can never be consumed again, even by the same wallet.
 *      3. Verifier keys are versioned and set through the governance path, so a
 *          compromised coprocessor can be rotated out without redeploying
 *          accounts.
 *      4. Every check re-derives `attestationHash` from the struct; the signed
 *          digest is never trusted to describe its own contents.
 */
contract AuthorizationVerifier is IAuthorizationVerifier {
    /// @notice ERC-191 personal-message prefix, so a signature can never be
    ///         replayed as a transaction on another chain.
    bytes private constant SIGNATURE_PREFIX = "\x19Ethereum Signed Message:\n32";

    address public governance;
    IProofVerifierRegistry public immutable registry;

    /// @notice Guard rail: minimum proof system the account will accept.
    uint32 public immutable minVerifierVersion;

    /// @notice Hard cap on authorization lifetime, regardless of what the
    ///         coprocessor signs. A stolen committee key cannot mint long-lived
    ///         authorizations.
    uint64 public immutable maxAuthorizationLifetime;

    mapping(bytes16 => bool) public override consumed;
    mapping(bytes16 => address) public sessionOwner;

    event AuthorizationConsumed(
        bytes16 indexed sessionId, address indexed account, bytes32 indexed userOpHash, bool decision
    );
    event GovernanceTransferred(address indexed previous, address indexed next);
    event AuthorizationRejected(bytes16 indexed sessionId, address indexed account, string reason);

    error NotGovernance();
    error AlreadyConsumed();
    error SessionBelongsToAnotherAccount();
    error AuthorizationExpired();
    error AuthorizationNotYetValid();
    error WalletMismatch();
    error ChainMismatch();
    error OperationMismatch();
    error NegativeDecision();
    error SignatureInvalid();
    error UnsupportedProofSystem();
    error UnknownVerifierVersion();
    error UnknownDecisionProgram();
    error WrongCommitment();
    error AuthorizationTooLongLived();

    modifier onlyGovernance() {
        if (msg.sender != governance) revert NotGovernance();
        _;
    }

    constructor(
        address governance_,
        IProofVerifierRegistry registry_,
        uint32 minVerifierVersion_,
        uint64 maxAuthorizationLifetime_
    ) {
        governance = governance_;
        registry = registry_;
        minVerifierVersion = minVerifierVersion_;
        maxAuthorizationLifetime = maxAuthorizationLifetime_;
        emit GovernanceTransferred(address(0), governance_);
    }

    function transferGovernance(address next) external onlyGovernance {
        emit GovernanceTransferred(governance, next);
        governance = next;
    }

    /// @inheritdoc IAuthorizationVerifier
    function verify(address account, bytes32 userOpHash, uint256 chainId, Authorization calldata authorization)
        external
        view
        returns (bool)
    {
        if (consumed[authorization.sessionId]) revert AlreadyConsumed();
        _check(account, userOpHash, chainId, authorization);
        return true;
    }

    /// @inheritdoc IAuthorizationVerifier
    function verifyAndConsume(
        address account,
        bytes32 userOpHash,
        uint256 chainId,
        Authorization calldata authorization
    ) external returns (bool) {
        if (consumed[authorization.sessionId]) revert AlreadyConsumed();
        if (sessionOwner[authorization.sessionId] != address(0)) {
            revert SessionBelongsToAnotherAccount();
        }
        _check(account, userOpHash, chainId, authorization);

        consumed[authorization.sessionId] = true;
        sessionOwner[authorization.sessionId] = account;
        emit AuthorizationConsumed(authorization.sessionId, account, userOpHash, authorization.decision);
        return true;
    }

    function _check(address account, bytes32 userOpHash, uint256 chainId, Authorization calldata a) private view {
        if (a.wallet != account) revert WalletMismatch();
        if (uint256(a.chainId) != chainId) revert ChainMismatch();
        if (a.userOpHash != userOpHash) revert OperationMismatch();

        uint64 blockTime = uint64(block.timestamp);
        if (a.issuedAt > blockTime) revert AuthorizationNotYetValid();
        if (a.expiresAt < blockTime) revert AuthorizationExpired();
        if (a.expiresAt - a.issuedAt > maxAuthorizationLifetime) revert AuthorizationTooLongLived();

        // A negative decision is never an authorization, whatever it signed.
        if (!a.decision) revert NegativeDecision();

        if (a.proofSystem != 1) revert UnsupportedProofSystem();
        if (a.verifierVersion < minVerifierVersion) revert UnknownVerifierVersion();

        address verifier = registry.verifier(a.proofSystem, a.verifierVersion);
        if (verifier == address(0)) revert UnknownVerifierVersion();
        if (!registry.isAcceptedDecisionProgram(a.decisionProgramHash)) revert UnknownDecisionProgram();

        bytes32 expected = AuthDomain.authorizationHash(
            a.version,
            a.wallet,
            a.chainId,
            a.userOpHash,
            a.sessionId,
            a.policyHash,
            a.templateVersion,
            a.fheKeyVersion,
            a.decision,
            a.thresholdBps,
            a.resultCommitment,
            a.issuedAt,
            a.expiresAt,
            a.proofSystem,
            a.verifierVersion,
            a.decisionProgramHash
        );
        if (expected != a.attestationHash) revert WrongCommitment();
        if (_recover(a.attestationHash, a.signature) != verifier) revert SignatureInvalid();
    }

    function _recover(bytes32 digest, bytes calldata signature) private pure returns (address) {
        if (signature.length != 65) revert SignatureInvalid();
        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly {
            r := calldataload(signature.offset)
            s := calldataload(add(signature.offset, 0x20))
            v := byte(0, calldataload(add(signature.offset, 0x40)))
        }
        if (v < 27) v += 27;
        if (v != 27 && v != 28) revert SignatureInvalid();
        // Reject malleable (high-s) signatures so one digest has one signature.
        if (uint256(s) > 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0) {
            revert SignatureInvalid();
        }
        return ecrecover(keccak256(abi.encodePacked(SIGNATURE_PREFIX, digest)), v, r, s);
    }
}

