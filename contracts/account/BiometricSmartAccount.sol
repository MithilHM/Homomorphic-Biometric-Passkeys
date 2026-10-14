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
 *        5. the per-account daily authorization budget is not exhausted
 *           (at most MAX_AUTHORIZATIONS_PER_DAY consumed 0x48
 *           authorizations per UTC day; recovery cancellation bypasses
 *           it so the owner can always cancel).
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
    /// @notice Cap on consumed 0x48 authorizations per UTC day, per account.
    ///         Mirrors SponsorshipPaymaster.MAX_SPONSORED_OPS (T-15).
    uint256 public constant MAX_AUTHORIZATIONS_PER_DAY = 25;
    /// @notice Similarity is expressed in millionths: 1_000_000 == perfect match.
    uint32 public constant MAX_SIMILARITY_BPS = 1_000_000;

    /* -------------------------------------------------------------------- */
    /*                                Storage                               */
    /* -------------------------------------------------------------------- */

    IEntryPoint public immutable entryPoint;
    IAuthorizationVerifier public immutable authorizationVerifier;
    ISessionKeyRegistry public immutable sessionKeys;
    IRecoveryRegistry public immutable recovery;
    /// @notice Factory that deployed this account (zero for directly deployed
    ///         accounts). It may enroll the FIRST passkey only (H6).
    address public immutable enrollmentFactory;

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
    /// @notice UTC day of the last counted authorization (block.timestamp / 1 days).
    uint64 public lastAuthDay;
    /// @notice 0x48 authorizations consumed on lastAuthDay. Resets at UTC midnight.
    uint32 public authCountToday;

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
    error ThresholdAboveMaximum();
    error WrongDecisionProgram();
    error WrongTemplateVersion();
    error WrongFheKeyVersion();
    error UnknownPasskey();
    error PasskeyAlreadyRegistered();
    error NotEnrollmentFactory();
    error SpendLimitExceeded();
    error DailyAuthorizationBudgetExceeded();
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
        enrollmentFactory = msg.sender;

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
        // C3: while a recovery is pending the ONLY callable path is cancelling
        // it — otherwise cancel would be unreachable and any grief-initiated
        // recovery would deadlock the account (and its funds) forever.
        if (recovery.isRecoveryPending(address(this)) && !_isCancelRecovery(userOp.callData)) {
            revert RecoveryInProgress();
        }
        if (userOp.signature.length < 3) revert UnknownEnvelope();

        uint8 magic = uint8(userOp.signature[0]);
        if (magic == MAGIC_AUTHORIZATION) {
            Authorization memory a = _decodeAuthorization(userOp.signature);
            _checkAuthorization(a, userOpHash, _isCancelRecovery(userOp.callData));
            validationData = ValidationData.pack(address(0), uint48(a.expiresAt), 0);
            emit OperationValidated(userOpHash, a.sessionId, false);
        } else if (magic == MAGIC_SESSION) {
            validationData = _validateSessionKey(userOp.signature, userOp);
            emit OperationValidated(userOpHash, bytes16(0), true);
        } else {
            revert UnknownEnvelope();
        }

        if (missingAccountFunds != 0) {
            (bool ok,) = payable(address(entryPoint)).call{value: missingAccountFunds}("");
            if (!ok) revert PrefundFailed();
        }
    }

    function _checkAuthorization(Authorization memory a, bytes32 userOpHash, bool isCancel) private {
        if (a.decisionProgramHash != decisionProgramHash) revert WrongDecisionProgram();
        if (a.templateVersion != templateVersion) revert WrongTemplateVersion();
        if (a.fheKeyVersion != fheKeyVersion) revert WrongFheKeyVersion();
        if (a.thresholdBps < minimumSimilarityBps) revert ThresholdBelowPolicy();
        if (a.thresholdBps > MAX_SIMILARITY_BPS) revert ThresholdAboveMaximum();
        if (a.policyHash != policyHash) revert AuthorizationRejected();
        // T-15: daily budget on consumed 0x48 authorizations. Checked BEFORE
        // verifyAndConsume so a capped attempt neither burns the session nor
        // the budget; counted only after a successful consume. A recovery
        // cancellation bypasses the budget: at the cap the owner must still
        // be able to cancel, or the account (and its funds) locks forever.
        // The 0x53 session-key path never reaches here and is unaffected.
        if (!isCancel) _checkAuthBudget();
        // C2: no passkey-only fallback. The committee attestation (signature,
        // expiry, binding, decision, replay) is always verified, regardless of
        // the biometricRequired flag.
        authorizationVerifier.verifyAndConsume(address(this), userOpHash, block.chainid, a);
        if (!isCancel) _spendAuthBudget();
    }

    /// @dev UTC day number, so the budget resets at midnight UTC.
    function _authDay() private view returns (uint64) {
        return uint64(block.timestamp / 1 days);
    }

    /// @dev Reverts when today's authorization budget is already spent.
    function _checkAuthBudget() private view {
        if (lastAuthDay == _authDay() && authCountToday >= MAX_AUTHORIZATIONS_PER_DAY) {
            revert DailyAuthorizationBudgetExceeded();
        }
    }

    /// @dev Counts one consumed authorization against today's budget.
    function _spendAuthBudget() private {
        uint64 today = _authDay();
        if (lastAuthDay != today) {
            lastAuthDay = today;
            authCountToday = 1;
        } else {
            authCountToday += 1;
        }
    }

    /**
     * @notice Session envelope: `0x53 | uint16 len | address key | uint64 until |
     *         bytes4 selector | uint256 value | bytes32 sessionKeyHash`.
     * @dev The targets/selectors/values are decoded from the UserOperation's
     *      OWN callData — never from the self-asserted envelope (H3). The
     *      envelope's selector/value must match a decoded call exactly, so a
     *      scoped key cannot be waved at an arbitrary execution.
     */
    function _validateSessionKey(bytes calldata envelope, PackedUserOperation calldata userOp) private returns (uint256) {
        uint256 bodyLength = (uint256(uint8(envelope[1])) << 8) | uint256(uint8(envelope[2]));
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
        _spendSessionCalls(sessionKey, selector, value, userOp.callData);
        return ValidationData.pack(address(0), uint48(validUntil), 0);
    }

    /// @dev Decode execute/executeBatch targets from calldata and spend each
    ///      against the session scope. Anything else cannot be session-authorized.
    function _spendSessionCalls(address sessionKey, bytes4 selector, uint256 value, bytes calldata callData)
        private
    {
        if (callData.length < 4) revert MalformedEnvelope();
        bytes4 outer = bytes4(callData[0:4]);
        SessionKeyRegistry registry = SessionKeyRegistry(address(sessionKeys));
        if (outer == this.execute.selector) {
            (address target, uint256 callValue, bytes memory data) =
                abi.decode(callData[4:], (address, uint256, bytes));
            bytes4 inner = data.length >= 4 ? bytes4(data) : bytes4(0);
            if (inner != selector || callValue != value) revert AuthorizationRejected();
            registry.spend(address(this), sessionKey, target, inner, callValue);
        } else if (outer == this.executeBatch.selector) {
            Call[] memory calls = abi.decode(callData[4:], (Call[]));
            if (calls.length == 0) revert MalformedEnvelope();
            bool covered;
            for (uint256 i = 0; i < calls.length; i++) {
                bytes4 inner = calls[i].data.length >= 4 ? bytes4(calls[i].data) : bytes4(0);
                registry.spend(address(this), sessionKey, calls[i].target, inner, calls[i].value);
                if (inner == selector && calls[i].value == value) covered = true;
            }
            if (!covered) revert AuthorizationRejected();
        } else {
            revert UnknownEnvelope();
        }
    }

    /**
     * @notice Decode the authorization envelope from `userOp.signature`.
     * @dev Layout (all fields fixed width so the account needs no parser):
     *      0x48 | uint16 len | bytes32 envelopeHash | uint16 assertionLen |
     *      assertion | Authorization (fixed-width fields) | bytes signature
     */
    function _decodeAuthorization(bytes calldata envelope) private pure returns (Authorization memory a) {
        uint256 bodyLength = (uint256(uint8(envelope[1])) << 8) | uint256(uint8(envelope[2]));
        if (envelope.length != bodyLength + 3) revert MalformedEnvelope();

        uint256 cursor = 3;
        cursor += 32; // envelopeHash, bound to the account by the verifier path
        uint256 assertionLength = (uint256(uint8(envelope[cursor])) << 8) | uint256(uint8(envelope[cursor + 1]));
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
    {
        _recoveryGate(target, data);
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

    function executeBatch(Call[] calldata calls) external payable onlyEntryPoint {
        for (uint256 i = 0; i < calls.length; i++) {
            _recoveryGate(calls[i].target, calls[i].data);
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

    /// @dev First-key enrollment: the deploying factory may register key #0 so
    ///      counterfactual accounts are usable without a prior UserOperation.
    ///      Later keys require a validated UserOperation (onlyEntryPoint).
    function addPasskey(bytes32 publicKeyHash, bytes32 credentialCommitment) external {
        if (msg.sender != address(entryPoint)) {
            if (msg.sender != enrollmentFactory || passkeyList.length != 0) revert NotEnrollmentFactory();
        }
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
        if (newMinimumSimilarityBps > MAX_SIMILARITY_BPS) revert ThresholdAboveMaximum();
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

    /// @dev Completing recovery REGISTERs the new key: finalization without a
    ///      key write was a no-op lock, not recovery (C3).
    function finalizeRecovery(bytes32 requestId, bytes32 newPasskeyHash) external {
        recovery.finalize(requestId, newPasskeyHash);
        if (!passkeys[newPasskeyHash]) {
            passkeys[newPasskeyHash] = true;
            passkeyList.push(newPasskeyHash);
            emit PasskeyAdded(newPasskeyHash, bytes32(0));
        }
    }

    /// @dev True when this operation only cancels a pending recovery.
    function _isCancelRecovery(bytes calldata callData) private pure returns (bool) {
        if (callData.length < 4) return false;
        return bytes4(callData[0:4]) == this.cancelRecovery.selector;
    }

    /// @dev Execution gate: locked accounts execute nothing; accounts in
    ///      recovery execute only the cancellation of that recovery, so the
    ///      owner can always unlock but an attacker can never spend.
    function _recoveryGate(address target, bytes calldata data) private view {
        if (locked) revert AccountIsLocked();
        if (!recovery.isRecoveryPending(address(this))) return;
        if (target != address(this) || data.length < 4 || bytes4(data[0:4]) != this.cancelRecovery.selector) {
            revert RecoveryInProgress();
        }
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

