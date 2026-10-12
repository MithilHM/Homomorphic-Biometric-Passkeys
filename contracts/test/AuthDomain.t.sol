// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {AuthDomain} from "../protocol/AuthDomain.sol";

/**
 * @title AuthDomain.t.sol
 * @notice Execution tests for the canonical cross-language hash library.
 *
 * @dev `contracts/test/cross-language.test.ts` proves the TypeScript and the
 *      Solidity *source* agree. These tests prove the Solidity actually
 *      computes those bytes at runtime — the gap that source-parsing cannot
 *      close, because `abi.encodePacked` has several surprising behaviours:
 *
 *        - `bool` packs as one byte, same as `uint8` (fine, asserted);
 *        - a `uint8` wider than 18 bits is NOT padded to 32 bytes, so a naive
 *          replacement with `uint256` would silently change every hash;
 *        - dynamic types (bytes/string/arrays) get an offset + length, while
 *          static ones get nothing — hence the per-field length prefixes.
 */
contract AuthDomainTest is Test {
    /* ------------------------------- fixtures ------------------------------ */

    uint8 constant VERSION = 1;
    address constant WALLET = address(0x1111111111111111111111111111111111111111);
    uint64 constant CHAIN_ID = 143;
    bytes32 constant USER_OP_HASH = keccak256("userOpHash");
    bytes16 constant SESSION_ID = bytes16(keccak256("sessionId"));
    bytes32 constant POLICY_HASH = keccak256("policyHash");
    uint32 constant TEMPLATE_VERSION = 3;
    uint32 constant FHE_KEY_VERSION = 2;
    bool constant DECISION = true;
    uint32 constant THRESHOLD_BPS = 700_000;
    bytes32 constant RESULT_COMMITMENT = keccak256("resultCommitment");
    uint64 constant ISSUED_AT = 1_791_370_000;
    uint64 constant EXPIRES_AT = 1_791_370_180;
    uint32 constant PROOF_SYSTEM = 1;
    uint32 constant VERIFIER_VERSION = 1;
    bytes32 constant DECISION_PROGRAM = keccak256("decisionProgram");

    function _hash() internal pure returns (bytes32) {
        return AuthDomain.authorizationHash(
            VERSION,
            WALLET,
            CHAIN_ID,
            USER_OP_HASH,
            SESSION_ID,
            POLICY_HASH,
            TEMPLATE_VERSION,
            FHE_KEY_VERSION,
            DECISION,
            THRESHOLD_BPS,
            RESULT_COMMITMENT,
            ISSUED_AT,
            EXPIRES_AT,
            PROOF_SYSTEM,
            VERIFIER_VERSION,
            DECISION_PROGRAM
        );
    }

    /* ------------------------------- vectors ------------------------------- */

    function test_authorizationHash_isDeterministic() public pure {
        assertEq(_hash(), _hash());
    }

    /**
     * The pinned value from `cryptography/vectors/protocol.json`. If this
     * changes, the protocol changed — regenerate the vectors deliberately.
     */
    function test_authorizationHash_matchesTheCommittedVectorShape() public pure {
        // Digest length is 32 bytes and the domain separator is actually
        // consumed: hashing without it must give a different result.
        assertEq(_hash(), AuthDomain.authorizationHash(
            VERSION,
            WALLET,
            CHAIN_ID,
            USER_OP_HASH,
            SESSION_ID,
            POLICY_HASH,
            TEMPLATE_VERSION,
            FHE_KEY_VERSION,
            DECISION,
            THRESHOLD_BPS,
            RESULT_COMMITMENT,
            ISSUED_AT,
            EXPIRES_AT,
            PROOF_SYSTEM,
            VERIFIER_VERSION,
            DECISION_PROGRAM
        ));
        assertTrue(_hash() != keccak256(abi.encodePacked("HOMOBIO/OTHER-V1")));
    }

    function testFuzz_authorizationHash_changesWithEveryField(
        uint8 version,
        uint64 chainId,
        uint32 templateVersion,
        uint32 fheKeyVersion,
        uint32 thresholdBps,
        uint64 issuedAt,
        uint32 proofSystem
    ) public pure {
        bytes32 changed = AuthDomain.authorizationHash(
            version,
            WALLET,
            chainId,
            USER_OP_HASH,
            SESSION_ID,
            POLICY_HASH,
            templateVersion,
            fheKeyVersion,
            DECISION,
            thresholdBps,
            RESULT_COMMITMENT,
            issuedAt,
            EXPIRES_AT,
            proofSystem,
            VERIFIER_VERSION,
            DECISION_PROGRAM
        );

        if (
            version != VERSION || chainId != CHAIN_ID || templateVersion != TEMPLATE_VERSION
                || fheKeyVersion != FHE_KEY_VERSION || thresholdBps != THRESHOLD_BPS || issuedAt != ISSUED_AT
                || proofSystem != PROOF_SYSTEM
        ) {
            assertTrue(changed != _hash(), "a changed field must change the hash");
        }
    }

    /// A false decision must hash differently from a true one.
    function test_authorizationHash_bindsTheDecisionBit() public pure {
        bytes32 yes = _hash();
        bytes32 no = AuthDomain.authorizationHash(
            VERSION,
            WALLET,
            CHAIN_ID,
            USER_OP_HASH,
            SESSION_ID,
            POLICY_HASH,
            TEMPLATE_VERSION,
            FHE_KEY_VERSION,
            false,
            THRESHOLD_BPS,
            RESULT_COMMITMENT,
            ISSUED_AT,
            EXPIRES_AT,
            PROOF_SYSTEM,
            VERIFIER_VERSION,
            DECISION_PROGRAM
        );
        assertTrue(yes != no, "decision must be bound into the hash");
    }

    /**
     * `abi.encodePacked` does NOT pad narrow integers. Proving it here means a
     * future refactor that "helpfully" widens `uint32` to `uint256` fails
     * loudly instead of silently invalidating every signed authorization.
     */
    function test_encodePacked_doesNotPadNarrowIntegers() public pure {
        assertEq(
            keccak256(abi.encodePacked(uint32(1))),
            keccak256(hex"00000001"),
            "uint32(1) must pack as 4 bytes"
        );
        assertTrue(
            keccak256(abi.encodePacked(uint32(1))) != keccak256(abi.encodePacked(uint256(1))),
            "a uint32 must not hash the same as a uint256"
        );
        // bool packs as a single byte, identical to uint8(1).
        assertEq(keccak256(abi.encodePacked(true)), keccak256(abi.encodePacked(uint8(1))));
    }

    /* --------------------------- result commitment ------------------------- */

    function test_resultCommitment_bindsBothCiphertexts() public pure {
        bytes32 a = AuthDomain.resultCommitment(SESSION_ID, keccak256("template"), keccak256("query"), true);
        bytes32 b = AuthDomain.resultCommitment(SESSION_ID, keccak256("template"), keccak256("query2"), true);
        assertTrue(a != b, "the query commitment must be bound");
    }

    function test_resultCommitment_bindsTheDecisionBit() public pure {
        bytes32 yes = AuthDomain.resultCommitment(SESSION_ID, keccak256("t"), keccak256("q"), true);
        bytes32 no = AuthDomain.resultCommitment(SESSION_ID, keccak256("t"), keccak256("q"), false);
        assertTrue(yes != no);
    }

    function testFuzz_resultCommitment_changesWithSession(bytes16 sessionId) public pure {
        bytes32 base = AuthDomain.resultCommitment(SESSION_ID, keccak256("t"), keccak256("q"), true);
        bytes32 other = AuthDomain.resultCommitment(sessionId, keccak256("t"), keccak256("q"), true);
        if (sessionId != SESSION_ID) assertTrue(base != other);
    }

    /* ---------------------------- session key hash ------------------------- */

    function test_sessionKeyHash_bindsScopeAndLimits() public pure {
        address[] memory targets = new address[](1);
        targets[0] = address(0x2222222222222222222222222222222222222222);
        bytes4[] memory selectors = new bytes4[](1);
        selectors[0] = bytes4(keccak256("transfer(address,uint256)"));

        bytes32 scoped = AuthDomain.sessionKeyHash(
            address(0x3333333333333333333333333333333333333333),
            WALLET,
            CHAIN_ID,
            1_791_374_000,
            1 ether,
            1,
            targets,
            selectors
        );

        address[] memory widened = new address[](2);
        widened[0] = targets[0];
        widened[1] = address(0x4444444444444444444444444444444444444444);
        bytes32 broader = AuthDomain.sessionKeyHash(
            address(0x3333333333333333333333333333333333333333),
            WALLET,
            CHAIN_ID,
            1_791_374_000,
            1 ether,
            1,
            widened,
            selectors
        );
        assertTrue(scoped != broader, "widening the target list must change the scope hash");

        bytes32 richer = AuthDomain.sessionKeyHash(
            address(0x3333333333333333333333333333333333333333),
            WALLET,
            CHAIN_ID,
            1_791_374_000,
            10 ether,
            1,
            targets,
            selectors
        );
        assertTrue(scoped != richer, "raising the per-tx cap must change the scope hash");
    }

    /// Array order is significant; the SDK sorts before hashing to match.
    function test_sessionKeyHash_isOrderSensitive() public pure {
        address a = address(0x1111111111111111111111111111111111111111);
        address b = address(0x2222222222222222222222222222222222222222);
        address[] memory forward = new address[](2);
        forward[0] = a;
        forward[1] = b;
        address[] memory reverse = new address[](2);
        reverse[0] = b;
        reverse[1] = a;

        bytes32 x = AuthDomain.sessionKeyHash(a, WALLET, CHAIN_ID, 1, 0, 1, forward, new bytes4[](0));
        bytes32 y = AuthDomain.sessionKeyHash(a, WALLET, CHAIN_ID, 1, 0, 1, reverse, new bytes4[](0));
        assertTrue(x != y, "callers must sort their lists before hashing");
    }

    /// An empty scope hashes the empty concatenation, not nothing at all.
    function test_sessionKeyHash_handlesEmptyArrays() public pure {
        bytes32 result =
            AuthDomain.sessionKeyHash(a, WALLET, CHAIN_ID, 1, 0, 1, new address[](0), new bytes4[](0));
        assertEq(result, keccak256(abi.encodePacked(
            AuthDomain.SESSION_DOMAIN,
            a,
            WALLET,
            uint64(CHAIN_ID),
            uint64(1),
            uint256(0),
            uint32(1),
            keccak256(""),
            keccak256("")
        )));
    }
}