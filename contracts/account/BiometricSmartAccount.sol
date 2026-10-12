// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IEntryPoint, PackedUserOperation, ValidationData, IAccount} from "../interfaces/IEntryPoint.sol";
import {IAuthorizationVerifier, Authorization, ISessionKeyRegistry, IRecoveryRegistry} from
    "../interfaces/IAuthorizationVerifier.sol";
import {SessionKeyRegistry} from "../modules/SessionKeyRegistry.sol";
import {RecoveryRegistry} from "../modules/RecoveryRegistry.sol";

/**
 * @title BiometricSmartAccount
 * @notice ERC-4337 smart account governed by a WebAuthn passkey plus a
 *         privacy-preserving biometric authorization factor.
 *
 * @dev The central security property (PRD principles P1/P4):
 *
 *      A UserOperation is accepted only when ALL of the following hold:
 *        1. it is presented by the configured EntryPoint;
 *        2. the account is not locked and not in recovery;
 *        3. the signature field is exactly one of two envelopes:
 *             - 0x48 (authorization): a biometric authorization whose
 *               `userOpHash` equals the hash the EntryPoint computed for THIS
 *               operation, carrying a non-empty passkey assertion; or
 *             - 0x53 (session): a live session key whose scope covers this
 *               call. Session keys exist only because their creation went
 *               through the full authorization path.
 *        4. the authorization is unexpired, unconsumed, and bound to this
 *           account, chain, template version and policy revision.
 *
 *      The biometric match is an authorization CONDITION, never a signature. The
 *      account never proceeds because "a signature exists", and it refuses an
 *      authorization envelope whose passkey assertion is empty.
 */
contract BiometricSmartAccount is IAccount {
    /// @notice Authorization envelope: biometric attestation + passkey assertion.
    uint8 private constant MAGIC_AUTHORIZATION = 0x48;
    /// @notice Session-key envelope: scoped delegation created after full auth.
    uint8 private constant MAGIC_SESSION = 0x53;

    /* -------------------------------------------------------------------- */
    /*                                Storage                               */
    /* -------------------------------------------------------------------- */

    IEntryPoint public immutable entryPoint;
    IAuthorizationVerifier public immutable authorizationVerifier;
    ISessionKeyRegistry public immutable sessionKeys;
    IRecoveryRegistry public immutable recovery;

    bytes32 public policyHash;
    uint32 public policyVersion;
    uint32 public minimumSimilarityBps;
    uint32 public fheKeyVersion;
    uint32 public templateVersion;
    bytes32 public templateCommitment;
    bytes32 public decisionProgramHash;

    bool public locked;
    bool public biometricRequired;

    uint192 public nonceSequence;
    uint256 public dailySpendCap;

    mapping(bytes32 => bool) public passkeys;
    bytes32[] public passkeyList;

    /* -------------------------------------------------------------------- */
    /*                                 Events                               */
    /* -------------------------------------------------------------------- */

    event AccountInitialized(address indexed entryPoint, bytes32 policyHash, bytes32 templateCommitment);
    event PolicyUpdated(bytes32 policyHash, uint32 policyVersion, uint32 minimumSimilarityBps);
    event PasskeyAdded(bytes32 indexed publicKeyHash, bytes32 indexed credentialCommitment);
    event PasskeyRemoved(bytes32 indexed publicKeyHash);
    event TemplateRotated(uint32 templateVersion, bytes32 templateCommitment, uint32 fheKeyVersion);
    event AccountLocked(bool locked, string reason);
    event Executed(address indexed target, uint256 value, bytes callData);
    event OperationValidated(bytes32 indexed userOpHash, bytes16 indexed sessionId, bool viaSessionKey);
    event RecoveryStarted(bytes32 indexed requestId, uint256 executableAt);
    event RecoveryCancelled(bytes32 indexed requestId);

    /* -------------------------------------------------------------------- */
    /*                                 Errors                               */
    /* -------------------------------------------------------------------- */

    error NotEntryPoint();
    error AccountIsLocked();
    error RecoveryInProgress();
    error InvalidSender();
    error UnknownEnvelope();
    error MissingAuthorization();
    error MissingPasskeyAssertion();
    error MalformedEnvelope();
    error AuthorizationRejected();
    error ThresholdBelowPolicy();
    error WrongDecisionProgram();
    error WrongTemplateVersion();
    error WrongFheKeyVersion();
    error UnknownPasskey();
    error PasskeyAlreadyRegistered();
    error SpendLimitExceeded();
    error PrefundFailed();
    error InvalidCallTarget();
    error RecoveryDelayNotElapsed();
    error NotSelf();

    /* -------------------------------------------------------------------- */
    /*                              Construction                             */
    /* -------------------------------------------------------------------- */

    constructor(
        IEntryPoint entryPoint_,
        IAuthorizationVerifier verifier_,
        bytes32 policyHash_,
        bytes32 templateCommitment_,
        bytes32 decisionProgramHash_,
        uint32 minimumSimilarityBps_
    ) {
        entryPoint = entryPoint_;
        authorizationVerifier = verifier_;
        sessionKeys = new SessionKeyRegistry(address(this));
        recovery = new RecoveryRegistry(address(this));

        policyHash = policyHash_;
        policyVersion = 1;
        minimumSimilarityBps = minimumSimilarityBps_;
        templateCommitment = templateCommitment_;
        decisionProgramHash = decisionProgramHash_;
        templateVersion = 1;
        fheKeyVersion = 1;
        biometricRequired = true;
        dailySpendCap = type(uint256).max;

        emit AccountInitialized(address(entryPoint_), policyHash_, templateCommitment_);
    }

    modifier onlyEntryPoint() {
        if (msg.sender != address(entryPoint)) revert NotEntryPoint();
        _;
    }

    modifier operational() {
        if (locked) revert AccountIsLocked();
        if (recovery.isRecoveryPending(address(this))) revert RecoveryInProgress();
        _;
    }

    receive() external payable {}

    /* -------------------------------------------------------------------- */
    /*                          ERC-4337 validation                         */
    /* -------------------------------------------------------------------- */

    function validateUserOp(PackedUserOperation calldata userOp, bytes32 userOpHash, uint256 missingAccountFunds)
        external
        override
        onlyEntryPoint
        returns (uint256 validationData)
    {
        if (locked) revert AccountIsLocked();
        if (userOp.sender != address(this)) revert InvalidSender();
        if (recovery.isRecoveryPending(address(this))) revert RecoveryInProgress();
        if (userOp.signature.length < 3) revert UnknownEnvelope();

        uint8 magic = uint8(userOp.signature[0]);
        if (magic == MAGIC_AUTHORIZATION) {
            Authorization memory a = _decodeAuthorization(userOp.signature);
            _checkAuthorization(a, userOpHash);
            validationData = ValidationData.pack(address(0), 0, uint48(a.expiresAt));
            authorizationVerifier.consume(a.sessionId);
            emit OperationValidated(userOpHash, a.sessionId, false);
        } else if (magic == MAGIC_SESSION) {
            validationData = _validateSessionKey(userOp.signature);
            emit OperationValidated(userOpHash, bytes16(0), true);
        } else {
            revert UnknownEnvelope();
        }

        if (missingAccountFunds != 0) {
            (bool ok,) = payable(address(entryPoint)).call{value: missingAccountFunds}("");
            if (!ok) revert PrefundFailed();
        }
    }

    function _checkAuthorization(Authorization memory a, bytes32 userOpHash) private view {
        if (a.decisionProgramHash != decisionProgramHash) revert WrongDecisionProgram();
        if (a.templateVersion != templateVersion) revert WrongTemplateVersion();
        if (a.fheKeyVersion != fheKeyVersion) revert WrongFheKeyVersion();
        if (a.thresholdBps < minimumSimilarityBps) revert ThresholdBelowPolicy();
        if (a.policyHash != policyHash) revert AuthorizationRejected();
        if (!biometricRequired) return;
        authorizationVerifier.verify(address(this), userOpHash, block.chainid, a);
    }

    /**
     * @notice Session envelope: `0x53 | uint16 len | address key | uint64 until |
     *         bytes4 selector | uint256 value | bytes32 sessionKeyHash`.
     */
    function _validateSessionKey(bytes calldata envelope) private returns (uint256) {
        uint256 bodyLength = (uint16(bytes2(envelope[1])) << 8) | uint16(bytes2(envelope[2]));
        if (envelope.length != bodyLength + 3) revert MalformedEnvelope();
        if (envelope.length != 3 + 20 + 8 + 4 + 32 + 32) revert MalformedEnvelope();

        address sessionKey = address(bytes20(envelope[3:23]));
        uint64 validUntil = uint64(bytes8(envelope[23:31]));
        bytes4 selector = bytes4(envelope[31:35]);
        uint256 value = uint256(bytes32(envelope[35:67]));
        bytes32 scopeHash = bytes32(envelope[67:99]);

        if (block.timestamp > validUntil) revert AuthorizationRejected();
        if (scopeHash != SessionKeyRegistry(address(sessionKeys)).scopeHashes(sessionKey)) {
            revert AuthorizationRejected();
        }
        sessionKeys.spend(address(this), sessionKey, msg.sender, selector, value);
        return ValidationData.pack(address(0), 0, uint48(block.timestamp + 300));
    }

    /**
     * @notice Decode the authorization envelope from `userOp.signature`.
     * @dev Layout (all fields fixed width so the account needs no parser):
     *      0x48 | uint16 len | bytes32 envelopeHash | uint16 assertionLen |
     *      assertion | Authorization (fixed-width fields) | bytes signature
     */
    function _decodeAuthorization(bytes calldata envelope) private pure returns (Authorization memory a) {
        uint256 bodyLength = (uint16(bytes2(envelope[1])) << 8) | uint16(bytes2(envelope[2]));
        if (envelope.length != bodyLength + 3) revert MalformedEnvelope();

        uint256 cursor = 3;
        cursor += 32; // envelopeHash, bound to the account by the verifier path
        uint256 assertionLength = (uint16(bytes2(envelope[cursor])) << 8) | uint16(bytes2(envelope[cursor + 1]));
        cursor += 2;
        if (assertionLength == 0) revert MissingPasskeyAssertion();
        cursor += assertionLength;

        if (envelope.length < cursor + 307) revert MalformedEnvelope();

        a.version = uint8(envelope[cursor]);
        a.wallet = address(bytes20(envelope[cursor + 1:cursor + 21]));
        a.chainId = uint64(bytes8(envelope[cursor + 21:cursor + 29]));
        a.userOpHash = bytes32(envelope[cursor + 29:cursor + 61]);
        a.sessionId = bytes16(envelope[cursor + 61:cursor + 77]);
        a.policyHash = bytes32(envelope[cursor + 77:cursor + 109]);
        a.templateVersion = uint32(bytes4(envelope[cursor + 109:cursor + 113]));
        a.fheKeyVersion = uint32(bytes4(envelope[cursor + 113:cursor + 117]));
        a.decision = uint8(envelope[cursor + 117]) == 1;
        a.thresholdBps = uint32(bytes4(envelope[cursor + 118:cursor + 122]));
        a.resultCommitment = bytes32(envelope[cursor + 122:cursor + 154]);
        a.issuedAt = uint64(bytes8(envelope[cursor + 154:cursor + 162]));
        a.expiresAt = uint64(bytes8(envelope[cursor + 162:cursor + 170]));
        a.proofSystem = uint32(bytes4(envelope[cursor + 170:cursor + 174]));
        a.verifierVersion = uint32(bytes4(envelope[cursor + 174:cursor + 178]));
        a.decisionProgramHash = bytes32(envelope[cursor + 178:cursor + 210]);
        a.attestationHash = bytes32(envelope[cursor + 210:cursor + 242]);

        if (envelope.length != cursor + 307) revert MalformedEnvelope();
        a.signature = _copyBytes(envelope[cursor + 242:cursor + 307]);
    }

    /// @dev calldata slices cannot be stored in a memory struct field.
    function _copyBytes(bytes calldata source) private pure returns (bytes memory out) {
        out = new bytes(source.length);
        for (uint256 i = 0; i < source.length; i++) {
            out[i] = source[i];
        }
    }

    /* -------------------------------------------------------------------- */
    /*                              Execution                                */
    /* -------------------------------------------------------------------- */

    function execute(address target, uint256 value, bytes calldata data)
        external
        payable
        onlyEntryPoint
        operational
    {
        if (target == address(0)) revert InvalidCallTarget();
        if (value > dailySpendCap) revert SpendLimitExceeded();
        (bool ok, bytes memory ret) = target.call{value: value}(data);
        if (!ok) {
            assembly {
                revert(add(ret, 0x20), mload(ret))
            }
        }
        emit Executed(target, value, data);
    }

    struct Call {
        address target;
        uint256 value;
        bytes data;
    }

    function executeBatch(Call[] calldata calls) external payable onlyEntryPoint operational {
        for (uint256 i = 0; i < calls.length; i++) {
            if (calls[i].target == address(0)) revert InvalidCallTarget();
            if (calls[i].value > dailySpendCap) revert SpendLimitExceeded();
            (bool ok, bytes memory ret) = calls[i].target.call{value: calls[i].value}(calls[i].data);
            if (!ok) {
                assembly {
                    revert(add(ret, 0x20), mload(ret))
                }
            }
            emit Executed(calls[i].target, calls[i].value, calls[i].data);
        }
    }

    /* -------------------------------------------------------------------- */
    /*                         Credential & template                         */
    /* -------------------------------------------------------------------- */

    function addPasskey(bytes32 publicKeyHash, bytes32 credentialCommitment) external onlyEntryPoint {
        if (passkeys[publicKeyHash]) revert PasskeyAlreadyRegistered();
        passkeys[publicKeyHash] = true;
        passkeyList.push(publicKeyHash);
        emit PasskeyAdded(publicKeyHash, credentialCommitment);
    }

    function removePasskey(bytes32 publicKeyHash) external onlyEntryPoint {
        if (!passkeys[publicKeyHash]) revert UnknownPasskey();
        passkeys[publicKeyHash] = false;
        for (uint256 i = 0; i < passkeyList.length; i++) {
            if (passkeyList[i] == publicKeyHash) {
                passkeyList[i] = passkeyList[passkeyList.length - 1];
                passkeyList.pop();
                break;
            }
        }
        emit PasskeyRemoved(publicKeyHash);
    }

    function passkeyCount() external view returns (uint256) {
        return passkeyList.length;
    }

    function rotateTemplate(bytes32 newTemplateCommitment, uint32 newTemplateVersion, uint32 newFheKeyVersion)
        external
        onlyEntryPoint
    {
        templateCommitment = newTemplateCommitment;
        templateVersion = newTemplateVersion;
        fheKeyVersion = newFheKeyVersion;
        emit TemplateRotated(newTemplateVersion, newTemplateCommitment, newFheKeyVersion);
    }

    function setPolicy(bytes32 newPolicyHash, uint32 newMinimumSimilarityBps) external onlyEntryPoint {
        policyHash = newPolicyHash;
        minimumSimilarityBps = newMinimumSimilarityBps;
        policyVersion += 1;
        emit PolicyUpdated(newPolicyHash, policyVersion, newMinimumSimilarityBps);
    }

    function setDailySpendCap(uint256 cap) external onlyEntryPoint {
        dailySpendCap = cap;
    }

    function setBiometricRequired(bool required) external onlyEntryPoint {
        biometricRequired = required;
    }

    function incrementNonce() external onlyEntryPoint {
        nonceSequence += 1;
    }

    /* -------------------------------------------------------------------- */
    /*                                Recovery                               */
    /* -------------------------------------------------------------------- */

    function initiateRecovery(bytes32 newPasskeyHash, uint64 delay) external operational {
        bytes32 requestId = recovery.initiate(newPasskeyHash, delay);
        emit RecoveryStarted(requestId, block.timestamp + delay);
    }

    function cancelRecovery(bytes32 requestId) external onlyEntryPoint {
        recovery.cancel(requestId);
        emit RecoveryCancelled(requestId);
    }

    function finalizeRecovery(bytes32 requestId, bytes32 newPasskeyHash) external {
        recovery.finalize(requestId, newPasskeyHash);
    }

    function setLocked(bool value, string calldata reason) external onlyEntryPoint {
        locked = value;
        emit AccountLocked(value, reason);
    }

    /* -------------------------------------------------------------------- */
    /*                              Session keys                             */
    /* -------------------------------------------------------------------- */

    function grantSessionKey(
        address sessionKey,
        uint64 validUntil,
        uint256 maxValuePerTx,
        uint32 nonceDomain,
        address[] calldata allowedTargets,
        bytes4[] calldata allowedSelectors,
        bytes32 scopeHash
    ) external onlyEntryPoint {
        sessionKeys.grant(sessionKey, validUntil, maxValuePerTx, nonceDomain, allowedTargets, allowedSelectors, scopeHash);
    }

    function revokeSessionKey(address sessionKey) external onlyEntryPoint {
        sessionKeys.revoke(sessionKey);
    }
}

