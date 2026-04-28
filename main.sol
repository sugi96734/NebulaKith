// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/*
    NebulaKith — "talk light, match right"
    ------------------------------------
    A non-custodial on-chain social + bot-attestation layer for EVM mainnets.

    Concept:
      - Profiles are hash pointers (bio/media/extras are bytes32 digests).
      - Friend discovery is modeled with Like/Block edges and mutual Match edges.
      - Conversations are thread identifiers derived from the two participants.
      - Chat messages are emitted as events (content referenced by bytes32 hash).
      - A "bot concierge" lane supports prompt hashes and attested reply hashes.

    Safety:
      - Contract rejects ETH; no token custody.
      - Bounded loops on user-supplied arrays.
      - Role-based moderation and attestation.
      - Conservative defaults for launch on public networks.
*/

contract NebulaKith {
    // =============================================================
    // Errors (unique)
    // =============================================================
    error NBK__NotOwner();
    error NBK__NotRole(bytes32 role);
    error NBK__Paused();
    error NBK__EtherRejected();
    error NBK__BadInput();
    error NBK__NoProfile();
    error NBK__HandleTaken();
    error NBK__NotFound();
    error NBK__AlreadyExists();
    error NBK__Blocked();
    error NBK__TooLarge();
    error NBK__RateLimited();
    error NBK__Restricted();
    error NBK__Unauthorized();
    error NBK__Invariant();

    // =============================================================
    // Events (unique)
    // =============================================================
    event NBK_OwnerSet(address indexed prev, address indexed next);
    event NBK_Pause(bool paused);
    event NBK_RoleSet(bytes32 indexed role, address indexed account, bool enabled);

    event NBK_ProfileMinted(address indexed user, bytes32 indexed handleHash, uint64 at);
    event NBK_ProfilePatched(address indexed user, uint32 mask, uint64 at);
    event NBK_HandleMoved(address indexed user, bytes32 indexed oldHandleHash, bytes32 indexed newHandleHash, uint64 at);
    event NBK_Tagged(address indexed user, bytes32 indexed tagHash, bool present, uint64 at);

    event NBK_Block(address indexed by, address indexed target, bool blocked, uint64 at);
    event NBK_Like(address indexed by, address indexed target, bool liked, uint64 at);
    event NBK_Match(address indexed a, address indexed b, bytes32 indexed threadId, bool live, uint64 at);

    event NBK_Chat(address indexed from, bytes32 indexed threadId, uint40 seq, bytes32 payloadHash, uint64 at);
    event NBK_ThreadMeta(bytes32 indexed threadId, uint32 key, bytes32 value, uint64 at);

    event NBK_LaneOpen(address indexed user, bytes32 indexed laneId, uint64 at);
    event NBK_LanePrompt(address indexed user, bytes32 indexed laneId, uint40 indexed n, bytes32 promptHash, uint64 at);
    event NBK_LaneReply(address indexed attestor, address indexed user, bytes32 indexed laneId, uint40 n, bytes32 replyHash, uint64 at);
    event NBK_LaneNote(bytes32 indexed laneId, uint32 key, bytes32 value, uint64 at);

    event NBK_Report(address indexed reporter, address indexed accused, uint32 reason, bytes32 noteHash, uint64 at);
    event NBK_Moderation(address indexed mod, address indexed user, uint8 action, uint32 code, uint64 untilTs, uint64 at);

    // =============================================================
    // Identity salts (unique per output)
    // =============================================================
    bytes32 private constant _NBK_DOMAIN =
        hex"c4e2e611fdd6ab2f7d0c9a5b6df2af9a08c1f7cf7b2cb4b0d3c8d47c2e8a1f4b";
    bytes32 private constant _NBK_NOISE =
        hex"2f9a7c0d5b8e1a4c7d3b9e0f1a6d2c4b8e0d7a2c3b1f9e8d6c2a0f7b1c3e9d2a";

    // =============================================================
    // Generic immutable addresses (unique, no fund flows)
    // =============================================================
    address public immutable ADDRESS_A;
    address public immutable ADDRESS_B;
    address public immutable ADDRESS_C;

    // =============================================================
    // Ownership + pause
    // =============================================================
    address public owner;
    bool public paused;

    modifier onlyOwner() {
        if (msg.sender != owner) revert NBK__NotOwner();
        _;
    }

    modifier whenLive() {
        if (paused) revert NBK__Paused();
        _;
    }

    // =============================================================
    // Roles (lightweight)
    // =============================================================
    bytes32 public constant ROLE_MODERATOR = keccak256("NebulaKith.ROLE_MODERATOR");
    bytes32 public constant ROLE_ATTESTOR = keccak256("NebulaKith.ROLE_ATTESTOR");
    bytes32 public constant ROLE_CURATOR = keccak256("NebulaKith.ROLE_CURATOR");
    bytes32 public constant ROLE_RELAYER = keccak256("NebulaKith.ROLE_RELAYER");
    uint256 public constant VERSION = 2;

    mapping(bytes32 => mapping(address => bool)) private _role;

    modifier onlyRole(bytes32 r) {
        if (!_role[r][msg.sender]) revert NBK__NotRole(r);
        _;
    }

    function hasRole(bytes32 r, address a) external view returns (bool) {
        return _role[r][a];
    }

    function setRole(bytes32 r, address a, bool enabled) external onlyOwner {
        if (a == address(0)) revert NBK__BadInput();
        _role[r][a] = enabled;
        emit NBK_RoleSet(r, a, enabled);
    }

    // =============================================================
    // Moderation
