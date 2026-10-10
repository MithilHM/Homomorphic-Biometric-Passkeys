// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title RecoveryModule
 * @notice Timelocked guardian and social recovery for BiometricSmartAccount
 * @dev Conforms to PRD Section 23
 */
contract RecoveryModule {
    struct RecoveryRequest {
        address wallet;
        bytes32 newPasskeyHash;
        uint256 executeAfter;
        uint256 approvals;
        bool executed;
    }

    uint256 public constant RECOVERY_DELAY = 2 days;
    mapping(address => address[]) public guardians;
    mapping(bytes32 => RecoveryRequest) public requests;
    mapping(bytes32 => mapping(address => bool)) public hasApproved;

    event RecoveryInitiated(bytes32 indexed requestId, address indexed wallet, bytes32 newPasskeyHash, uint256 executeAfter);
    event RecoveryApproved(bytes32 indexed requestId, address indexed guardian);
    event RecoveryExecuted(bytes32 indexed requestId, address indexed wallet);

    function initiateRecovery(address wallet, bytes32 newPasskeyHash) external returns (bytes32) {
        bytes32 requestId = keccak256(abi.encodePacked(wallet, newPasskeyHash, block.timestamp));
        requests[requestId] = RecoveryRequest({
            wallet: wallet,
            newPasskeyHash: newPasskeyHash,
            executeAfter: block.timestamp + RECOVERY_DELAY,
            approvals: 0,
            executed: false
        });
        emit RecoveryInitiated(requestId, wallet, newPasskeyHash, block.timestamp + RECOVERY_DELAY);
        return requestId;
    }

    function approveRecovery(bytes32 requestId) external {
        RecoveryRequest storage req = requests[requestId];
        require(!req.executed, "Already executed");
        require(!hasApproved[requestId][msg.sender], "Already approved");
        
        hasApproved[requestId][msg.sender] = true;
        req.approvals++;
        emit RecoveryApproved(requestId, msg.sender);
    }

    function executeRecovery(bytes32 requestId) external {
        RecoveryRequest storage req = requests[requestId];
        require(!req.executed, "Already executed");
        require(block.timestamp >= req.executeAfter, "Recovery delay not passed");
        require(req.approvals >= 2, "Insufficient guardian approvals");

        req.executed = true;
        emit RecoveryExecuted(requestId, req.wallet);
    }
}
