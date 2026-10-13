// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {ISessionKeyRegistry} from "../interfaces/IAuthorizationVerifier.sol";

/**
 * @title SessionKeyRegistry
 * @notice Scoped, time-boxed session keys whose creation required the full
 *         biometric + passkey path.
 *
 * @dev A session key is a delegation, never an authority: it reaches only the
 *      granted targets and selectors, only within a per-transaction and per-day
 *      cap, and only until it expires. The account can revoke at any time, and a
 *      session key can revoke itself.
 */
contract SessionKeyRegistry is ISessionKeyRegistry {
    uint256 private constant DAILY_CAP_MULTIPLIER = 10;

    struct SessionKey {
        uint64 validUntil;
        uint256 maxValuePerTx;
        uint256 spentToday;
        uint256 spentTotal;
        uint64 dayStamp;
        uint32 nonceDomain;
        bool active;
    }

    struct Scope {
        bool allowAnyTarget;
        mapping(address => bool) targets;
        mapping(bytes4 => bool) selectors;
    }

    address public immutable account;

    mapping(address => SessionKey) public sessionKeys;
    mapping(address => bytes32) public scopeHashes;
    mapping(address => Scope) private scopes;
    /// @dev Granted entries per key, so a re-grant can clear stale scope
    ///      instead of only ever widening it (M2).
    mapping(address => address[]) private grantedTargets;
    mapping(address => bytes4[]) private grantedSelectors;

    event SessionKeyGranted(
        address indexed sessionKey, uint64 validUntil, uint256 maxValuePerTx, uint32 nonceDomain, uint8 targetCount
    );
    event SessionKeySpent(address indexed sessionKey, address indexed target, uint256 amount, uint256 spentToday);
    event SessionKeyRevoked(address indexed sessionKey, string reason);

    error NotAccount();
    error NotAuthorized();
    error SessionKeyUnknown();
    error SessionKeyExpired();
    error SessionKeyInactive();
    error TargetNotAllowed();
    error SelectorNotAllowed();
    error ValueExceedsPerTxLimit();
    error ExceedsDailyCap();
    error CannotGrantToSelf();

    modifier onlyAccount() {
        if (msg.sender != account) revert NotAccount();
        _;
    }

    constructor(address account_) {
        account = account_;
    }

    function grant(
        address sessionKey,
        uint64 validUntil,
        uint256 maxValuePerTx,
        uint32 nonceDomain,
        address[] calldata allowedTargets,
        bytes4[] calldata allowedSelectors,
        bytes32 scopeHash
    ) external override onlyAccount {
        if (sessionKey == address(0) || sessionKey == account) revert CannotGrantToSelf();

        sessionKeys[sessionKey] = SessionKey({
            validUntil: validUntil,
            maxValuePerTx: maxValuePerTx,
            spentToday: 0,
            spentTotal: 0,
            dayStamp: uint64(block.timestamp / 1 days),
            nonceDomain: nonceDomain,
            active: true
        });

        scopes[sessionKey].allowAnyTarget = allowedTargets.length == 0;
        // Clear stale scope first: without this a re-grant could only widen,
        // never narrow, a key's authority (M2).
        address[] storage oldTargets = grantedTargets[sessionKey];
        for (uint256 i = 0; i < oldTargets.length; i++) {
            scopes[sessionKey].targets[oldTargets[i]] = false;
        }
        delete grantedTargets[sessionKey];
        bytes4[] storage oldSelectors = grantedSelectors[sessionKey];
        for (uint256 i = 0; i < oldSelectors.length; i++) {
            scopes[sessionKey].selectors[oldSelectors[i]] = false;
        }
        delete grantedSelectors[sessionKey];
        for (uint256 i = 0; i < allowedTargets.length; i++) {
            scopes[sessionKey].targets[allowedTargets[i]] = true;
            grantedTargets[sessionKey].push(allowedTargets[i]);
        }
        for (uint256 i = 0; i < allowedSelectors.length; i++) {
            scopes[sessionKey].selectors[allowedSelectors[i]] = true;
            grantedSelectors[sessionKey].push(allowedSelectors[i]);
        }
        scopeHashes[sessionKey] = scopeHash;

        emit SessionKeyGranted(sessionKey, validUntil, maxValuePerTx, nonceDomain, uint8(allowedTargets.length));
    }

    function revoke(address sessionKey) external override onlyAccount {
        _revoke(sessionKey, "account revoked");
    }

    function _revoke(address sessionKey, string memory reason) private {
        if (sessionKeys[sessionKey].validUntil == 0) revert SessionKeyUnknown();
        sessionKeys[sessionKey].active = false;
        emit SessionKeyRevoked(sessionKey, reason);
    }

    function selfRevoke(address sessionKey) external {
        // Only the key itself (or its account, via revoke) may deactivate it:
        // an open revocation lets anyone kill anyone else's delegation (M2).
        if (msg.sender != sessionKey) revert NotAuthorized();
        if (!sessionKeys[sessionKey].active) revert SessionKeyUnknown();
        sessionKeys[sessionKey].active = false;
        emit SessionKeyRevoked(sessionKey, "session key self-revoked");
    }

    /// @inheritdoc ISessionKeyRegistry
    function validate(address wallet, address sessionKey, address target, bytes4 selector, uint256 value)
        external
        override
        returns (uint256 spent)
    {
        return _validate(wallet, sessionKey, target, selector, value);
    }

    /// @notice Spend accounting for a call whose target/selector come from calldata.
    function spend(address wallet, address sessionKey, address target, bytes4 selector, uint256 value)
        external
        override
        returns (uint256 spent)
    {
        return _validate(wallet, sessionKey, target, selector, value);
    }

    function _validate(address wallet, address sessionKey, address target, bytes4 selector, uint256 value)
        private
        returns (uint256 spent)
    {
        if (msg.sender != account) revert NotAccount();
        if (wallet != account) revert NotAuthorized();

        SessionKey storage key = sessionKeys[sessionKey];
        if (key.validUntil == 0) revert SessionKeyUnknown();
        if (!key.active) revert SessionKeyInactive();
        if (block.timestamp > key.validUntil) revert SessionKeyExpired();

        Scope storage scope = scopes[sessionKey];
        if (!scope.allowAnyTarget && !scope.targets[target]) revert TargetNotAllowed();
        // No zero-selector bypass: every call must name an explicitly granted
        // selector, otherwise any unscoped function passes accounting (M2).
        if (!scope.selectors[selector]) revert SelectorNotAllowed();
        if (value > key.maxValuePerTx) revert ValueExceedsPerTxLimit();

        uint64 today = uint64(block.timestamp / 1 days);
        if (today != key.dayStamp) {
            key.dayStamp = today;
            key.spentToday = 0;
        }
        key.spentToday += value;
        key.spentTotal += value;
        if (key.spentToday > key.maxValuePerTx * DAILY_CAP_MULTIPLIER) revert ExceedsDailyCap();

        emit SessionKeySpent(sessionKey, target, value, key.spentToday);
        return key.spentToday;
    }

    function isValid(address sessionKey) external view returns (bool) {
        SessionKey storage key = sessionKeys[sessionKey];
        return key.active && block.timestamp <= key.validUntil;
    }

    function dailyCap(address sessionKey) external view returns (uint256) {
        return sessionKeys[sessionKey].maxValuePerTx * DAILY_CAP_MULTIPLIER;
    }

    function allowedTargets(address sessionKey, address target) external view returns (bool) {
        return scopes[sessionKey].allowAnyTarget || scopes[sessionKey].targets[target];
    }

    function allowedSelectors(address sessionKey, bytes4 selector) external view returns (bool) {
        return scopes[sessionKey].selectors[selector];
    }
}

