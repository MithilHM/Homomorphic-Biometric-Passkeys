// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title BiometricValidator
 * @notice Validates cryptographic attestations from the FHE coprocessor / zkVM
 * @dev Conforms to PRD Section 14, 15, 24
 */
contract BiometricValidator {
    address public coprocessorAuthority;
    mapping(bytes32 => bool) public consumedAttestations;

    event AttestationVerified(bytes32 indexed attestationId, address indexed wallet, bytes32 indexed operationHash);
    event CoprocessorUpdated(address indexed oldCoprocessor, address indexed newCoprocessor);

    constructor(address _coprocessorAuthority) {
        coprocessorAuthority = _coprocessorAuthority;
    }

    struct Attestation {
        bytes32 attestationId;
        bytes32 challengeId;
        address wallet;
        bytes32 operationHash;
        bool distanceSatisfied;
        uint256 thresholdUsed;
        bytes32 resultCommitment;
        uint256 validUntil;
        bytes signature;
    }

    /**
     * @notice Verify that an attestation is valid, timely, and issued by the trusted coprocessor
     */
    function verifyAttestation(Attestation calldata att) external returns (bool) {
        require(!consumedAttestations[att.attestationId], "Attestation already consumed");
        require(block.timestamp <= att.validUntil, "Attestation expired");
        require(att.distanceSatisfied, "Biometric distance threshold not satisfied");

        // Verify attestation message hash
        bytes32 messageHash = keccak256(
            abi.encodePacked(
                att.attestationId,
                att.challengeId,
                att.wallet,
                att.operationHash,
                att.distanceSatisfied,
                att.thresholdUsed,
                att.resultCommitment,
                att.validUntil
            )
        );

        bytes32 ethSignedMessageHash = keccak256(
            abi.encodePacked("\x19Ethereum Signed Message:\n32", messageHash)
        );

        (bytes32 r, bytes32 s, uint8 v) = splitSignature(att.signature);
        address signer = ecrecover(ethSignedMessageHash, v, r, s);
        require(signer == coprocessorAuthority, "Invalid coprocessor signature");

        consumedAttestations[att.attestationId] = true;
        emit AttestationVerified(att.attestationId, att.wallet, att.operationHash);
        return true;
    }

    function splitSignature(bytes memory sig) internal pure returns (bytes32 r, bytes32 s, uint8 v) {
        require(sig.length == 65, "invalid signature length");
        assembly {
            r := mload(add(sig, 32))
            s := mload(add(sig, 64))
            v := byte(0, mload(add(sig, 96)))
        }
    }
}
