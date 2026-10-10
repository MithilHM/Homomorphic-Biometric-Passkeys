// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "../account/BiometricSmartAccount.sol";

/**
 * @title SmartAccountFactory
 * @notice Factory for deploying BiometricSmartAccount contracts with deterministic addresses
 */
contract SmartAccountFactory {
    address public immutable entryPoint;
    address public immutable biometricValidator;

    event AccountCreated(address indexed account, bytes32 passkeyHash, bytes32 salt);

    constructor(address _entryPoint, address _biometricValidator) {
        entryPoint = _entryPoint;
        biometricValidator = _biometricValidator;
    }

    function createAccount(bytes32 passkeyHash, bytes32 salt) external returns (address) {
        address account = address(
            new BiometricSmartAccount{salt: salt}(
                entryPoint,
                biometricValidator,
                passkeyHash
            )
        );
        emit AccountCreated(account, passkeyHash, salt);
        return account;
    }

    function getAddress(bytes32 passkeyHash, bytes32 salt) external view returns (address) {
        bytes memory bytecode = abi.encodePacked(
            type(BiometricSmartAccount).creationCode,
            abi.encode(entryPoint, biometricValidator, passkeyHash)
        );
        bytes32 hash = keccak256(
            abi.encodePacked(bytes1(0xff), address(this), salt, keccak256(bytecode))
        );
        return address(uint160(uint256(hash)));
    }
}
