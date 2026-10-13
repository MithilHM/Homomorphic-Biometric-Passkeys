// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {BiometricSmartAccount} from "../account/BiometricSmartAccount.sol";
import {IEntryPoint} from "../interfaces/IEntryPoint.sol";
import {IAuthorizationVerifier} from "../interfaces/IAuthorizationVerifier.sol";

/**
 * @title BiometricAccountFactory
 * @notice Deterministic (counterfactual) deployment for biometric smart accounts.
 *
 * @dev The account address is derived from
 *      `keccak256(credentialCommitment, salt, policyHash, templateCommitment)`
 *      so the client can compute it before the account exists, and the first
 *      UserOperation deploys it through `initCode` (ERC-4337 counterfactual
 *      deployment). The address is therefore stable across chains only for a
 *      given factory; it is never reused for a different credential.
 */
contract BiometricAccountFactory {
    address public immutable entryPoint;
    address public immutable authorizationVerifier;
    uint32 public immutable minimumSimilarityBps;

    event AccountCreated(
        address indexed account, bytes32 indexed credentialCommitment, bytes32 salt, uint32 templateVersion
    );
    event FactoryParametersChanged(address entryPoint, address verifier, uint32 minimumSimilarityBps);

    error ZeroAddress();
    error DeploymentFailed();
    error InitCodeTooLong();

    constructor(IEntryPoint entryPoint_, IAuthorizationVerifier verifier_, uint32 minimumSimilarityBps_) {
        if (address(entryPoint_) == address(0) || address(verifier_) == address(0)) revert ZeroAddress();
        entryPoint = address(entryPoint_);
        authorizationVerifier = address(verifier_);
        minimumSimilarityBps = minimumSimilarityBps_;
    }

    /// @notice Deterministic address of the account for a given registration.
    function getAddress(
        bytes32 credentialCommitment,
        bytes32 salt,
        bytes32 policyHash,
        bytes32 templateCommitment,
        bytes32 decisionProgramHash
    ) public view returns (address) {
        bytes32 bytecodeHash = keccak256(
            abi.encodePacked(
                type(BiometricSmartAccount).creationCode,
                abi.encode(
                    IEntryPoint(entryPoint),
                    IAuthorizationVerifier(authorizationVerifier),
                    policyHash,
                    templateCommitment,
                    decisionProgramHash,
                    minimumSimilarityBps
                )
            )
        );
        bytes32 salt2 = keccak256(abi.encodePacked(credentialCommitment, salt));
        return address(uint160(uint256(keccak256(abi.encodePacked(bytes1(0xff), address(this), salt2, bytecodeHash)))));
    }

    /**
     * @notice Deploy an account.
     * @dev The caller must have completed WebAuthn + FHE enrollment first; the
     *      factory never inspects private material and never holds an admin key.
     *      Authority over the account is expressed solely by its passkeys.
     */
    function createAccount(
        bytes32 credentialCommitment,
        bytes32 salt,
        bytes32 policyHash,
        bytes32 templateCommitment,
        bytes32 decisionProgramHash
    ) external returns (address account) {
        account = getAddress(credentialCommitment, salt, policyHash, templateCommitment, decisionProgramHash);
        if (account.code.length != 0) return account;

        account = address(new BiometricSmartAccount{salt: _deploymentSalt(credentialCommitment, salt)}(
            IEntryPoint(entryPoint),
            IAuthorizationVerifier(authorizationVerifier),
            policyHash,
            templateCommitment,
            decisionProgramHash,
            minimumSimilarityBps
        ));

        emit AccountCreated(account, credentialCommitment, salt, 1);
    }

    /// @notice Register the first passkey; only callable by the new account.
    /// @dev Pass-through to the account's first-key enrollment (H6). Anyone
    ///      may call it, but it only succeeds while the account holds zero
    ///      keys, and a front-run key is removable by the owner through a
    ///      validated UserOperation — so griefing buys nothing permanent.
    function initializePasskey(address account, bytes32 publicKeyHash, bytes32 credentialCommitment) external {
        if (account.code.length == 0) revert DeploymentFailed();
        BiometricSmartAccount(payable(account)).addPasskey(publicKeyHash, credentialCommitment);
    }

    function _deploymentSalt(bytes32 credentialCommitment, bytes32 salt) private pure returns (bytes32) {
        return keccak256(abi.encodePacked(credentialCommitment, salt));
    }
}

