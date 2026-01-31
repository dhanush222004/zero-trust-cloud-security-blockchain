// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract ZeroTrust {

    enum Role { NONE, ADMIN, USER }

    struct AuditLog {
        address user;
        Role role;
        bool accessGranted;
        uint256 timestamp;
    }

    mapping(address => bytes32) private identityHash;
    mapping(address => Role) private roles;
    AuditLog[] private logs;

    event AccessLogged(address user, Role role, bool success, uint256 time);

    constructor() {
        roles[msg.sender] = Role.ADMIN;
    }

    function registerUser(
        address user,
        bytes32 hash,
        Role role
    ) public {
        require(roles[msg.sender] == Role.ADMIN, "Only admin can register");
        identityHash[user] = hash;
        roles[user] = role;
    }

    function verifyAccess(
        address user,
        bytes32 hash
    ) public returns (bool) {

        bool validIdentity = (identityHash[user] == hash);
        bool allowed = validIdentity && roles[user] == Role.USER;

        logs.push(
            AuditLog(user, roles[user], allowed, block.timestamp)
        );

        emit AccessLogged(
            user,
            roles[user],
            allowed,
            block.timestamp
        );

        return allowed;
    }

    function getLogCount() public view returns (uint256) {
        return logs.length;
    }

    function getLog(
        uint256 index
    )
        public
        view
        returns (address, Role, bool, uint256)
    {
        AuditLog memory log = logs[index];
        return (
            log.user,
            log.role,
            log.accessGranted,
            log.timestamp
        );
    }
}
