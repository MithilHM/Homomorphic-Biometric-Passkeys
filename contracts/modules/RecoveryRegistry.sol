// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IRecoveryRegistry} from "../interfaces/IAuthorizationVerifier.sol";

/**
 * @title RecoveryRegistry
 * @notice Timelocked recovery. Never a backdoor: a request must wait out the
 *         full delay, and the delay is bounded below by `MINIMUM_DELAY`.
 *
 * @dev Recovery states (PRD section 56):
 *      ACTIVE -> RECOVERY (pending, delay running, cancellable)
 *              -> ACTIVE (cancelled by the account)
 *              -> ACTIVE (executed after the delay with a new passkey)
 *
 *      The account refuses to validate UserOperations while a request is pending,
 *      so recovery can only lock an account, never spend from it. That is the
 *      property that stops it from being a hidden custodial backdoor.
 */
contract RecoveryRegistry is IRecoveryRegistry {
    /// @notice Recovery is never instant; the floor is 48 hours (PRD section 23).
    uint64 public constant MINIMUM_DELAY = 48 hours;

    struct Request {
        bytes32 newPasskeyHash;
        uint64 executableAt;
        bool pending;
        bool executed;
    }

    address public immutable account;

    /// @dev Active request id; zero when no recovery is pending.
    bytes32 public pendingRequestId;

    mapping(bytes32 => Request) public requests;

    event RecoveryInitiated(bytes32 indexed requestId, bytes32 newPasskeyHash, uint64 executableAt);
    event RecoveryCancelled(bytes32 indexed requestId);
    event RecoveryExecuted(bytes32 indexed requestId, bytes32 newPasskeyHash);

    error NotAccount();
    error DelayTooShort();
    error UnknownRequest();
    error RecoveryAlreadyPending();
    error RecoveryNotPending();
    error DelayNotElapsed();
    error AlreadyExecuted();
    error WrongPasskey();

    constructor(address account_) {
        account = account_;
    }

    /**
     * @notice Start recovery.
     * @dev Callable by anyone so a lost device is not a dead end. It can only
     *      lock the account until it is cancelled or the delay elapses.
     */
    function initiate(bytes32 newPasskeyHash, uint64 delay) external returns (bytes32 requestId) {
        if (delay < MINIMUM_DELAY) revert DelayTooShort();
        if (pendingRequestId != bytes32(0)) revert RecoveryAlreadyPending();

        requestId = keccak256(abi.encodePacked(account, newPasskeyHash, block.timestamp, msg.sender));
        requests[requestId] = Request({
            newPasskeyHash: newPasskeyHash,
            executableAt: uint64(block.timestamp) + delay,
            pending: true,
            executed: false
        });
        pendingRequestId = requestId;
        emit RecoveryInitiated(requestId, newPasskeyHash, uint64(block.timestamp) + delay);
    }

    function cancel(bytes32 requestId) external override {
        if (msg.sender != account) revert NotAccount();
        if (requestId != pendingRequestId) revert UnknownRequest();
        Request storage request = requests[requestId];
        if (!request.pending) revert RecoveryNotPending();

        request.pending = false;
        pendingRequestId = bytes32(0);
        emit RecoveryCancelled(requestId);
    }

    function finalize(bytes32 requestId, bytes32 newPasskeyHash) external override {
        if (requestId != pendingRequestId) revert UnknownRequest();
        Request storage request = requests[requestId];
        if (request.executed) revert AlreadyExecuted();
        if (!request.pending) revert RecoveryNotPending();
        if (block.timestamp < request.executableAt) revert DelayNotElapsed();
        if (newPasskeyHash != request.newPasskeyHash) revert WrongPasskey();

        request.pending = false;
        request.executed = true;
        pendingRequestId = bytes32(0);
        emit RecoveryExecuted(requestId, newPasskeyHash);
    }

    function isRecoveryPending(address wallet) external view override returns (bool) {
        if (wallet != account || pendingRequestId == bytes32(0)) return false;
        return requests[pendingRequestId].pending;
    }

    function pendingRequest()
        external
        view
        returns (bytes32 requestId, uint64 executableAt, bytes32 newPasskeyHash)
    {
        requestId = pendingRequestId;
        if (requestId == bytes32(0)) return (bytes32(0), 0, bytes32(0));
        Request storage request = requests[requestId];
        return (requestId, request.executableAt, request.newPasskeyHash);
    }
}

