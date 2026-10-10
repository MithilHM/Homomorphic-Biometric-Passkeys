// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title SessionKeyModule
 * @notice Scoped temporary session keys with spending limits and time bounds
 * @dev Conforms to PRD Section 22
 */
contract SessionKeyModule {
    struct SessionPermission {
        address sessionKey;
        uint256 validUntil;
        uint256 dailyLimit;
        uint256 spentToday;
        uint256 lastResetDay;
    }

    mapping(address => mapping(address => SessionPermission)) public sessions;

    event SessionKeyCreated(address indexed wallet, address indexed sessionKey, uint256 validUntil, uint256 dailyLimit);
    event SessionKeyRevoked(address indexed wallet, address indexed sessionKey);

    function createSessionKey(
        address wallet,
        address sessionKey,
        uint256 validUntil,
        uint256 dailyLimit
    ) external {
        sessions[wallet][sessionKey] = SessionPermission({
            sessionKey: sessionKey,
            validUntil: validUntil,
            dailyLimit: dailyLimit,
            spentToday: 0,
            lastResetDay: block.timestamp / 1 days
        });
        emit SessionKeyCreated(wallet, sessionKey, validUntil, dailyLimit);
    }

    function revokeSessionKey(address wallet, address sessionKey) external {
        delete sessions[wallet][sessionKey];
        emit SessionKeyRevoked(wallet, sessionKey);
    }

    function validateSessionExecution(
        address wallet,
        address sessionKey,
        uint256 amount
    ) external returns (bool) {
        SessionPermission storage perm = sessions[wallet][sessionKey];
        require(perm.sessionKey == sessionKey, "Invalid session key");
        require(block.timestamp <= perm.validUntil, "Session expired");

        uint256 currentDay = block.timestamp / 1 days;
        if (currentDay > perm.lastResetDay) {
            perm.spentToday = 0;
            perm.lastResetDay = currentDay;
        }

        require(perm.spentToday + amount <= perm.dailyLimit, "Daily spending limit exceeded");
        perm.spentToday += amount;
        return true;
    }
}
