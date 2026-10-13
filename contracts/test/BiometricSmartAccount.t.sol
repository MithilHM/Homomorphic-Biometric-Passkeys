// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {AuthorizationVerifier} from "../validators/AuthorizationVerifier.sol";
import {ProofVerifierRegistry} from "../validators/ProofVerifierRegistry.sol";
import {BiometricSmartAccount} from "../account/BiometricSmartAccount.sol";
import {AuthDomain} from "../protocol/AuthDomain.sol";
import {Authorization} from "../interfaces/IAuthorizationVerifier.sol";
import {PackedUserOperation, IEntryPoint, ValidationData} from "../interfaces/IEntryPoint.sol";

/**
 * @title BiometricSmartAccount.t.sol
 * @notice Execution tests for the account and the verifier.
 *
 * @dev These are the tests that matter most. The account is where the PRD's
 *      central claim lives — *a biometric match is an authorization CONDITION,
 *      never a signature* — and that claim is only worth something if the
 *      contract actually enforces it under adversarial input.
 *
 *      The focus is therefore adversarial: almost every test asks "can an
 *      attacker who controls the authorization blob get an operation executed?"
 *      The expected answer is always no, and the reason differs per field.
 */
contract BiometricSmartAccountTest is Test {
    /* ------------------------------- actors -------------------------------- */

    address governance = address(0x9999999999999999999999999999999999999999);
    address committeeKey;
    uint256 committeePrivateKey;

    ProofVerifierRegistry registry;
    AuthorizationVerifier verifier;
    BiometricSmartAccount account;
    IEntryPoint entryPoint;

    /* ------------------------------ fixtures ------------------------------- */

    bytes32 constant POLICY_HASH = keccak256("policy-v1");
    bytes32 constant TEMPLATE_COMMITMENT = keccak256("template");
    bytes32 constant DECISION_PROGRAM = keccak256("rlwe-negacyclic-d1/cosine");
    uint32 constant MIN_BPS = 700_000;
    uint32 constant APPLIED_BPS = 820_000;

    uint64 constant TTL = 180;
    uint32 constant PROOF_SYSTEM = 1;
    uint32 constant VERIFIER_VERSION = 1;

    function setUp() public {
        (committeeKey, committeePrivateKey) = makeAddrAndKey("committee");

        entryPoint = IEntryPoint(address(new MockEntryPoint()));

        registry = new ProofVerifierRegistry(governance);
        vm.prank(governance);
        registry.registerVerifier(PROOF_SYSTEM, VERIFIER_VERSION, committeeKey);
        vm.prank(governance);
        registry.acceptDecisionProgram(DECISION_PROGRAM, "rlwe-negacyclic-d1 cosine similarity");

        // A 10-minute hard cap: a stolen committee key must not be able to mint
        // long-lived authorizations no matter what it signs.
        verifier = new AuthorizationVerifier(governance, registry, 1, 10 minutes);

        account = new BiometricSmartAccount(
            entryPoint, verifier, POLICY_HASH, TEMPLATE_COMMITMENT, DECISION_PROGRAM, MIN_BPS
        );
    }

    /// A fully valid, correctly signed authorization for THIS account.
    function _authorization(bytes32 userOpHash) internal view returns (Authorization memory a) {
        a.version = 1;
        a.wallet = address(account);
        a.chainId = uint64(block.chainid);
        a.userOpHash = userOpHash;
        a.sessionId = bytes16(keccak256("session"));
        a.policyHash = POLICY_HASH;
        a.templateVersion = 1;
        a.fheKeyVersion = 1;
        a.decision = true;
        a.thresholdBps = APPLIED_BPS;
        a.resultCommitment = keccak256("result");
        a.issuedAt = uint64(block.timestamp);
        a.expiresAt = uint64(block.timestamp) + TTL;
        a.proofSystem = PROOF_SYSTEM;
        a.verifierVersion = VERIFIER_VERSION;
        a.decisionProgramHash = DECISION_PROGRAM;
        _sign(a);
    }

    function _sign(Authorization memory a) internal view {
        bytes32 digest = AuthDomain.authorizationHash(
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
        a.attestationHash = digest;
        bytes32 prefixed = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", digest));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(committeePrivateKey, prefixed);
        a.signature = abi.encodePacked(r, s, v);
    }

    /// Pack the 0x48 envelope exactly as `_decodeAuthorization` reads it.
    function _pack(Authorization memory a, bytes memory assertion) internal pure returns (bytes memory) {
        bytes memory fields = abi.encodePacked(
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
            a.decisionProgramHash,
            a.attestationHash
        );
        bytes memory body =
            abi.encodePacked(keccak256("envelopeHash"), uint16(assertion.length), assertion, fields, a.signature);
        return abi.encodePacked(uint8(0x48), uint16(body.length), body);
    }

    function _userOp(bytes memory signature) internal view returns (PackedUserOperation memory op) {
        op.sender = address(account);
        op.nonce = 0;
        op.initCode = "";
        op.callData = "";
        op.callGasLimit = 100_000;
        op.verificationGasLimit = 500_000;
        op.preVerificationGas = 50_000;
        op.maxFeePerGas = 1 gwei;
        op.maxPriorityFeePerGas = 1;
        op.paymasterAndData = "";
        op.signature = signature;
    }

    function _validate(bytes memory envelope, bytes32 userOpHash) internal returns (uint256) {
        vm.prank(address(entryPoint));
        return account.validateUserOp(_userOp(envelope), userOpHash, 0);
    }

    /* ================================ happy path ============================ */

    function test_validAuthorization_isAccepted() public {
        bytes32 userOpHash = keccak256("op");
        Authorization memory a = _authorization(userOpHash);
        uint256 validationData = _validate(_pack(a, hex"aabb"), userOpHash);

        (address aggregator, bool failed, uint48 validUntil) = ValidationData.unpack(validationData);
        assertEq(aggregator, address(0), "aggregator must be zero");
        assertFalse(failed, "validation must not report a signature failure");
        assertEq(uint256(validUntil), uint256(a.expiresAt), "validUntil must be the authorization expiry");
        assertTrue(verifier.consumed(a.sessionId), "the session must be consumed during validation");
    }

    /// A spent authorization cannot be replayed, not even by the account itself.
    function test_consumedSession_cannotBeReplayed() public {
        bytes32 userOpHash = keccak256("op");
        Authorization memory a = _authorization(userOpHash);
        _validate(_pack(a, hex"aabb"), userOpHash);

        vm.expectRevert(AuthorizationVerifier.AlreadyConsumed.selector);
        _validate(_pack(a, hex"aabb"), userOpHash);
    }

    /* =================== the biometric result is a CONDITION ================ */

    function test_falseDecision_isNeverAnAuthorization() public {
        bytes32 userOpHash = keccak256("op");
        Authorization memory a = _authorization(userOpHash);
        a.decision = false;
        _sign(a); // correctly signed — the point is that the signature is valid

        vm.expectRevert(AuthorizationVerifier.NegativeDecision.selector);
        _validate(_pack(a, hex"aabb"), userOpHash);
    }

    /**
     * The load-bearing test. An envelope with NO passkey assertion must be
     * rejected even though the biometric attestation is perfectly valid. This
     * is the concrete, executable form of "the passkey is the authority".
     */
    function test_emptyPasskeyAssertion_isRejected() public {
        bytes32 userOpHash = keccak256("op");
        Authorization memory a = _authorization(userOpHash);

        vm.expectRevert(BiometricSmartAccount.MissingPasskeyAssertion.selector);
        _validate(_pack(a, ""), userOpHash);
    }

    function test_thresholdBelowTheAccountFloor_isRejected() public {
        bytes32 userOpHash = keccak256("op");
        Authorization memory a = _authorization(userOpHash);
        a.thresholdBps = MIN_BPS - 1;
        _sign(a);

        vm.expectRevert(BiometricSmartAccount.ThresholdBelowPolicy.selector);
        _validate(_pack(a, hex"aabb"), userOpHash);
    }

    /// A permissive off-chain policy cannot push the on-chain floor down.
    function test_thresholdExactlyAtTheFloor_isAccepted() public {
        bytes32 userOpHash = keccak256("op");
        Authorization memory a = _authorization(userOpHash);
        a.thresholdBps = MIN_BPS;
        _sign(a);
        _validate(_pack(a, hex"aabb"), userOpHash);
    }

    function test_wrongDecisionProgram_isRejected() public {
        bytes32 userOpHash = keccak256("op");
        Authorization memory a = _authorization(userOpHash);
        a.decisionProgramHash = keccak256("some-other-engine");
        _sign(a);

        vm.expectRevert(BiometricSmartAccount.WrongDecisionProgram.selector);
        _validate(_pack(a, hex"aabb"), userOpHash);
    }

    function test_wrongPolicyHash_isRejected() public {
        bytes32 userOpHash = keccak256("op");
        Authorization memory a = _authorization(userOpHash);
        a.policyHash = keccak256("a-different-policy-revision");
        _sign(a);

        vm.expectRevert(BiometricSmartAccount.AuthorizationRejected.selector);
        _validate(_pack(a, hex"aabb"), userOpHash);
    }

    function test_wrongFheKeyVersion_isRejected() public {
        bytes32 userOpHash = keccak256("op");
        Authorization memory a = _authorization(userOpHash);
        a.fheKeyVersion = 7;
        _sign(a);

        vm.expectRevert(BiometricSmartAccount.WrongFheKeyVersion.selector);
        _validate(_pack(a, hex"aabb"), userOpHash);
    }

    /* =========================== binding to the operation ================= */

    function test_authorizationForAnotherOperation_isRejected() public {
        Authorization memory a = _authorization(keccak256("op-one"));

        // Presented with the EntryPoint's hash for a DIFFERENT operation. The
        // verifier compares against that value, not the one inside the blob.
        vm.expectRevert(AuthorizationVerifier.OperationMismatch.selector);
        _validate(_pack(a, hex"aabb"), keccak256("op-two"));
    }

    function test_authorizationForAnotherAccount_isRejected() public {
        bytes32 userOpHash = keccak256("op");
        Authorization memory a = _authorization(userOpHash);
        a.wallet = address(0xdead);
        _sign(a);

        vm.expectRevert(AuthorizationVerifier.WalletMismatch.selector);
        _validate(_pack(a, hex"aabb"), userOpHash);
    }

    function test_authorizationForAnotherChain_isRejected() public {
        bytes32 userOpHash = keccak256("op");
        Authorization memory a = _authorization(userOpHash);
        a.chainId = 1;
        _sign(a);

        vm.expectRevert(AuthorizationVerifier.ChainMismatch.selector);
        _validate(_pack(a, hex"aabb"), userOpHash);
    }

    /* =============================== signatures ============================ */

    function test_signatureFromTheWrongKey_isRejected() public {
        bytes32 userOpHash = keccak256("op");
        Authorization memory a = _authorization(userOpHash);
        (, uint256 attackerKey) = makeAddrAndKey("attacker");
        bytes32 prefixed = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", a.attestationHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(attackerKey, prefixed);
        a.signature = abi.encodePacked(r, s, v);

        vm.expectRevert(AuthorizationVerifier.SignatureInvalid.selector);
        _validate(_pack(a, hex"aabb"), userOpHash);
    }

    /// Tampering with any signed field breaks the re-derived hash.
    function test_tamperingWithASignedField_isRejected() public {
        bytes32 userOpHash = keccak256("op");
        Authorization memory a = _authorization(userOpHash);
        a.thresholdBps = 999_000; // raise the claimed threshold AFTER signing
        // signature and attestationHash still describe the ORIGINAL struct.

        vm.expectRevert(AuthorizationVerifier.WrongCommitment.selector);
        _validate(_pack(a, hex"aabb"), userOpHash);
    }

    /// One digest must admit exactly one signature, not two via malleability.
    function test_malleableSignature_isRejected() public {
        bytes32 userOpHash = keccak256("op");
        Authorization memory a = _authorization(userOpHash);
        bytes memory sig = a.signature;
        bytes32 r = bytes32(sig[0:32]);
        bytes32 s = bytes32(sig[32:64]);
        uint8 v = uint8(sig[64]);
        // The true ECDSA mirror: s' = n - s with the other recovery id.
        bytes32 sPrime =
            bytes32(0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141 - uint256(s));
        uint8 vPrime = v == 27 ? 28 : 27;
        a.signature = abi.encodePacked(r, sPrime, vPrime);

        vm.expectRevert(AuthorizationVerifier.SignatureInvalid.selector);
        _validate(_pack(a, hex"aabb"), userOpHash);
    }

    function test_wrongLengthSignature_isRejected() public {
        bytes32 userOpHash = keccak256("op");
        Authorization memory a = _authorization(userOpHash);
        a.signature = hex"aabbcc"; // not 65 bytes

        vm.expectRevert(BiometricSmartAccount.MalformedEnvelope.selector);
        _validate(_pack(a, hex"aabb"), userOpHash);
    }

    /* ================================ expiry =============================== */

    function test_expiredAuthorization_isRejected() public {
        bytes32 userOpHash = keccak256("op");
        Authorization memory a = _authorization(userOpHash);
        a.issuedAt = uint64(block.timestamp) - 1000;
        a.expiresAt = uint64(block.timestamp) - 1;
        _sign(a);

        vm.expectRevert(AuthorizationVerifier.AuthorizationExpired.selector);
        _validate(_pack(a, hex"aabb"), userOpHash);
    }

    function test_notYetValid_isRejected() public {
        bytes32 userOpHash = keccak256("op");
        Authorization memory a = _authorization(userOpHash);
        a.issuedAt = uint64(block.timestamp) + 600;
        a.expiresAt = a.issuedAt + TTL;
        _sign(a);

        vm.expectRevert(AuthorizationVerifier.AuthorizationNotYetValid.selector);
        _validate(_pack(a, hex"aabb"), userOpHash);
    }

    /**
     * A fully compromised committee key still must not be able to mint an
     * authorization the account will honour beyond the hard cap.
     */
    function test_stolenCommitteeKey_cannotMintLongLivedAuthorizations() public {
        bytes32 userOpHash = keccak256("op");
        Authorization memory a = _authorization(userOpHash);
        a.issuedAt = uint64(block.timestamp);
        a.expiresAt = a.issuedAt + 365 days;
        _sign(a);

        vm.expectRevert(AuthorizationVerifier.AuthorizationTooLongLived.selector);
        _validate(_pack(a, hex"aabb"), userOpHash);
    }

    /* ========================== version / program gates =================== */

    function test_unregisteredVerifierVersion_isRejected() public {
        bytes32 userOpHash = keccak256("op");
        Authorization memory a = _authorization(userOpHash);
        a.verifierVersion = 99;
        _sign(a);

        vm.expectRevert(AuthorizationVerifier.UnknownVerifierVersion.selector);
        _validate(_pack(a, hex"aabb"), userOpHash);
    }

    function test_deactivatedVerifier_isRejected() public {
        vm.prank(governance);
        registry.deactivateVerifier(PROOF_SYSTEM, VERIFIER_VERSION);

        bytes32 userOpHash = keccak256("op");
        Authorization memory a = _authorization(userOpHash);

        vm.expectRevert(AuthorizationVerifier.UnknownVerifierVersion.selector);
        _validate(_pack(a, hex"aabb"), userOpHash);
    }

    function test_removedDecisionProgram_isRejected() public {
        vm.prank(governance);
        registry.removeDecisionProgram(DECISION_PROGRAM);

        bytes32 userOpHash = keccak256("op");
        Authorization memory a = _authorization(userOpHash);

        vm.expectRevert(AuthorizationVerifier.UnknownDecisionProgram.selector);
        _validate(_pack(a, hex"aabb"), userOpHash);
    }

    function test_unsupportedProofSystem_isRejected() public {
        bytes32 userOpHash = keccak256("op");
        Authorization memory a = _authorization(userOpHash);
        a.proofSystem = 2; // the SP1 system, which has no registered verifier
        _sign(a);

        vm.expectRevert(AuthorizationVerifier.UnsupportedProofSystem.selector);
        _validate(_pack(a, hex"aabb"), userOpHash);
    }

    /* ============================ envelope framing ======================== */

    function test_unknownMagic_isRejected() public {
        vm.expectRevert(BiometricSmartAccount.UnknownEnvelope.selector);
        _validate(abi.encodePacked(uint8(0x99), uint16(0)), keccak256("op"));
    }

    function test_truncatedEnvelope_isRejected() public {
        bytes32 userOpHash = keccak256("op");
        Authorization memory a = _authorization(userOpHash);
        bytes memory packed = _pack(a, hex"aabb");
        // Chop the tail without touching the declared bodyLength.
        bytes memory truncated = new bytes(packed.length - 10);
        for (uint256 i = 0; i < truncated.length; i++) {
            truncated[i] = packed[i];
        }

        vm.expectRevert(BiometricSmartAccount.MalformedEnvelope.selector);
        _validate(truncated, userOpHash);
    }

    function test_bodyLengthMismatch_isRejected() public {
        bytes32 userOpHash = keccak256("op");
        Authorization memory a = _authorization(userOpHash);
        bytes memory packed = _pack(a, hex"aabb");
        // Overstate the body length by one byte.
        packed[2] = bytes1(uint8(packed[2]) + 1);

        vm.expectRevert(BiometricSmartAccount.MalformedEnvelope.selector);
        _validate(packed, userOpHash);
    }

    /* ============================ account lifecycle ======================== */

    function test_lockedAccount_refusesOperations() public {
        vm.prank(address(entryPoint));
        account.setLocked(true, "compromised");

        bytes32 userOpHash = keccak256("op");
        Authorization memory a = _authorization(userOpHash);

        vm.expectRevert(BiometricSmartAccount.AccountIsLocked.selector);
        _validate(_pack(a, hex"aabb"), userOpHash);
    }

    function test_onlyTheEntryPointMayValidate() public {
        bytes32 userOpHash = keccak256("op");
        Authorization memory a = _authorization(userOpHash);

        vm.expectRevert(BiometricSmartAccount.NotEntryPoint.selector);
        account.validateUserOp(_userOp(_pack(a, hex"aabb")), userOpHash, 0);
    }

    function test_templateRotation_invalidatesOldAuthorizations() public {
        bytes32 userOpHash = keccak256("op");
        Authorization memory a = _authorization(userOpHash);
        a.templateVersion = 2;
        _sign(a);

        vm.expectRevert(BiometricSmartAccount.WrongTemplateVersion.selector);
        _validate(_pack(a, hex"aabb"), userOpHash);
    }

    /* ================================ recovery ============================= */

    function test_recoveryBlocksOperationsButNeverSpends() public {
        account.initiateRecovery(keccak256("new-passkey"), 48 hours);

        bytes32 userOpHash = keccak256("op");
        Authorization memory a = _authorization(userOpHash);

        // Recovery can only LOCK the account. It cannot execute anything.
        vm.expectRevert(BiometricSmartAccount.RecoveryInProgress.selector);
        _validate(_pack(a, hex"aabb"), userOpHash);
    }

    function test_recoveryDelayCannotBeShortened() public {
        // 1 hour is below the 48-hour floor. Pinned to the exact error so this
        // cannot pass for an unrelated reason (e.g. NotAccount).
        vm.expectRevert(abi.encodeWithSignature("DelayTooShort()"));
        account.initiateRecovery(keccak256("new-passkey"), 1 hours);
    }
}

/// @dev Minimal EntryPoint stand-in: the account only ever checks msg.sender.
contract MockEntryPoint {
    function getUserOpHash(PackedUserOperation calldata) external pure returns (bytes32) {
        return keccak256("mock");
    }
}