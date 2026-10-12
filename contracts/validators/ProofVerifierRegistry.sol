// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IProofVerifierRegistry} from "../interfaces/IAuthorizationVerifier.sol";

/**
 * @title ProofVerifierRegistry
 * @notice Versioned registry of proof/attestation verifiers and accepted
 *         decision programs.
 *
 * @dev Security rules (PRD section 24, 38):
 *      - keys can only be changed through `governance` (a multisig in
 *        production, a timelock in staging) â€” never by an arbitrary caller;
 *      - the decision program hash pins WHICH FHE circuit/decision logic a
 *        verifier is willing to speak for, so swapping in a weaker engine
 *        requires an explicit governance act;
 *      - old versions are never deleted, only superseded, so historical
 *        authorizations remain explainable.
 */
contract ProofVerifierRegistry is IProofVerifierRegistry {
    address public governance;
    address public pendingGovernance;

    struct VerifierKey {
        address verifier;
        uint64 activatedAt;
        bool active;
    }

    /// @notice proofSystem => verifierVersion => key
    mapping(uint32 => mapping(uint32 => VerifierKey)) private verifiers;
    mapping(bytes32 => bool) private acceptedPrograms;
    mapping(bytes32 => string) public programDescriptions;

    uint32 public minVerifierVersion;

    event VerifierRegistered(
        uint32 indexed proofSystem, uint32 indexed verifierVersion, address verifier, uint64 activatedAt
    );
    event VerifierDeactivated(uint32 indexed proofSystem, uint32 indexed verifierVersion);
    event DecisionProgramAccepted(bytes32 indexed programHash, string description);
    event DecisionProgramRemoved(bytes32 indexed programHash);
    event GovernanceTransferStarted(address indexed current, address indexed pending);
    event GovernanceTransferred(address indexed previous, address indexed next);

    error NotGovernance();
    error NotPendingGovernance();
    error VerifierAlreadyRegistered();
    error ZeroVerifier();
    event MinVerifierVersionUpdated(uint32 version);

    constructor(address governance_) {
        governance = governance_;
        emit GovernanceTransferred(address(0), governance_);
    }

    modifier onlyGovernance() {
        if (msg.sender != governance) revert NotGovernance();
        _;
    }

    /* ------------------------------ governance ----------------------------- */

    function startGovernanceTransfer(address pending) external onlyGovernance {
        pendingGovernance = pending;
        emit GovernanceTransferStarted(governance, pending);
    }

    function acceptGovernance() external {
        if (msg.sender != pendingGovernance) revert NotPendingGovernance();
        emit GovernanceTransferred(governance, pendingGovernance);
        governance = pendingGovernance;
        pendingGovernance = address(0);
    }

    /* ------------------------------- verifiers ----------------------------- */

    function registerVerifier(uint32 proofSystem, uint32 verifierVersion, address verifier) external onlyGovernance {
        if (verifier == address(0)) revert ZeroVerifier();
        if (verifiers[proofSystem][verifierVersion].active) revert VerifierAlreadyRegistered();
        verifiers[proofSystem][verifierVersion] =
            VerifierKey({verifier: verifier, activatedAt: uint64(block.timestamp), active: true});
        emit VerifierRegistered(proofSystem, verifierVersion, verifier, uint64(block.timestamp));
    }

    function deactivateVerifier(uint32 proofSystem, uint32 verifierVersion) external onlyGovernance {
        verifiers[proofSystem][verifierVersion].active = false;
        emit VerifierDeactivated(proofSystem, verifierVersion);
    }

    function setMinVerifierVersion(uint32 version) external onlyGovernance {
        minVerifierVersion = version;
        emit MinVerifierVersionUpdated(version);
    }

    /* --------------------------- decision programs -------------------------- */

    function acceptDecisionProgram(bytes32 programHash, string calldata description) external onlyGovernance {
        acceptedPrograms[programHash] = true;
        programDescriptions[programHash] = description;
        emit DecisionProgramAccepted(programHash, description);
    }

    function removeDecisionProgram(bytes32 programHash) external onlyGovernance {
        acceptedPrograms[programHash] = false;
        emit DecisionProgramRemoved(programHash);
    }

    /* -------------------------------- views -------------------------------- */

    function verifier(uint32 proofSystem, uint32 verifierVersion) external view override returns (address) {
        VerifierKey storage key = verifiers[proofSystem][verifierVersion];
        if (!key.active || verifierVersion < minVerifierVersion) return address(0);
        return key.verifier;
    }

    function isAcceptedDecisionProgram(bytes32 programHash) external view override returns (bool) {
        return acceptedPrograms[programHash];
    }

    function isActiveVerifier(uint32 proofSystem, uint32 verifierVersion) external view returns (bool) {
        return verifiers[proofSystem][verifierVersion].active;
    }
}

