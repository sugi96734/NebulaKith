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
    // =============================================================
    enum ModFlag {
        None,
        Muted,
        ShadowBanned,
        Suspended
    }

    struct ModState {
        ModFlag flag;
        uint64 untilTs;
        uint32 code;
    }

    mapping(address => ModState) public modOf;

    function _restricted(address u) internal view returns (bool) {
        ModState memory m = modOf[u];
        if (m.flag == ModFlag.None) return false;
        if (m.untilTs == 0) return true;
        return block.timestamp < m.untilTs;
    }

    function setModeration(address user, uint8 action, uint32 code, uint64 untilTs) external onlyRole(ROLE_MODERATOR) {
        if (user == address(0)) revert NBK__BadInput();
        if (action > uint8(ModFlag.Suspended)) revert NBK__BadInput();
        modOf[user] = ModState({flag: ModFlag(action), untilTs: untilTs, code: code});
        emit NBK_Moderation(msg.sender, user, action, code, untilTs, uint64(block.timestamp));
    }

    // =============================================================
    // Profile model
    // =============================================================
    uint32 private constant _HANDLE_MIN = 3;
    uint32 private constant _HANDLE_MAX = 25; // different from V1 on purpose
    uint32 private constant _BIO_MAX = 256;
    uint32 private constant _MAX_TAGS = 14;
    uint32 private constant _MAX_TAGLEN = 20;

    struct Profile {
        bytes32 handleHash;
        bytes32 bioHash;
        bytes32 avatarHash;
        bytes32 extrasHash;
        uint64 createdAt;
        uint64 updatedAt;
        uint16 age;
        uint16 region;
        uint32 prefsBits;
        uint32 flairBits;
    }

    mapping(address => Profile) private _profile;
    mapping(bytes32 => address) public handleOwner;
    mapping(address => bytes32[]) private _tags;

    // =============================================================
    // Social edges
    // =============================================================
    mapping(address => mapping(address => bool)) public blocked;
    mapping(address => mapping(address => bool)) public liked;
    mapping(address => mapping(address => bool)) public matched;

    mapping(bytes32 => uint40) public threadSeq;
    mapping(bytes32 => mapping(uint32 => bytes32)) public threadMeta;

    // =============================================================
    // Rate limiter (bucket debt)
    // =============================================================
    struct Rate {
        uint64 lastTs;
        uint32 debt;
    }
    mapping(address => Rate) private _rate;

    uint32 private constant _RATE_QUANTA = 21;
    uint32 private constant _RATE_BURST = 49;

    function _rateTick(address u, uint32 cost) internal {
        if (cost == 0) return;
        Rate memory r = _rate[u];
        uint64 nowTs = uint64(block.timestamp);
        if (nowTs > r.lastTs) {
            uint64 dt = nowTs - r.lastTs;
            uint32 recover = uint32((dt * _RATE_QUANTA) / 60);
            r.debt = recover >= r.debt ? 0 : (r.debt - recover);
            r.lastTs = nowTs;
        }
        if (r.debt + cost > _RATE_BURST) revert NBK__RateLimited();
        r.debt += cost;
        _rate[u] = r;
    }

    // =============================================================
    // Bot concierge lane
    // =============================================================
    uint32 private constant _BOT_CAP = 3072;

    struct Lane {
        uint64 openedAt;
        uint40 prompts;
        uint40 replies;
        bytes32 salt;
        uint32 flags;
    }

    mapping(address => Lane) public laneOf;
    mapping(bytes32 => mapping(uint40 => bytes32)) public lanePrompt;
    mapping(bytes32 => mapping(uint40 => bytes32)) public laneReply;
    mapping(bytes32 => mapping(uint32 => bytes32)) public laneNote;

    function laneId(address user) public view returns (bytes32) {
        Lane memory l = laneOf[user];
        if (l.openedAt == 0) return bytes32(0);
        return keccak256(abi.encodePacked(_NBK_DOMAIN, _NBK_NOISE, block.chainid, address(this), user, l.salt));
    }

    // =============================================================
    // Reports
    // =============================================================
    struct Report {
        address reporter;
        address accused;
        uint32 reason;
        uint64 at;
        bytes32 noteHash;
    }

    uint64 public reportCount;
    mapping(uint64 => Report) public reportById;

    // =============================================================
    // Construction
    // =============================================================
    constructor() {
        owner = msg.sender;

        ADDRESS_A = 0x9aE4b6C7d8F1A2b3C4d5E6f7091a2B3c4D5e6F70;
        ADDRESS_B = 0x2B7cD8e9F0a1B2c3D4e5F607a8B9c0D1e2F3a4B5;
        ADDRESS_C = 0xF1a2B3c4D5e6F70819a2B3c4D5e6F70819A2b3C4;

        // baseline launch roles
        _role[ROLE_MODERATOR][msg.sender] = true;
        _role[ROLE_ATTESTOR][ADDRESS_A] = true;
        _role[ROLE_CURATOR][ADDRESS_B] = true;
        _role[ROLE_RELAYER][ADDRESS_C] = true;

        emit NBK_RoleSet(ROLE_MODERATOR, msg.sender, true);
        emit NBK_RoleSet(ROLE_ATTESTOR, ADDRESS_A, true);
        emit NBK_RoleSet(ROLE_CURATOR, ADDRESS_B, true);
        emit NBK_RoleSet(ROLE_RELAYER, ADDRESS_C, true);

        // bind identity (no state)
        keccak256(abi.encodePacked(_NBK_DOMAIN, _NBK_NOISE, block.chainid, address(this), msg.sender));
    }

    receive() external payable {
        revert NBK__EtherRejected();
    }

    fallback() external payable {
        revert NBK__EtherRejected();
    }

    // =============================================================
    // Admin
    // =============================================================
    function setPaused(bool v) external onlyOwner {
        paused = v;
        emit NBK_Pause(v);
    }

    function setOwner(address n) external onlyOwner {
        if (n == address(0)) revert NBK__BadInput();
        address p = owner;
        owner = n;
        emit NBK_OwnerSet(p, n);
    }

    // =============================================================
    // Profile reads
    // =============================================================
    function profileOf(address user) external view returns (Profile memory p, bytes32[] memory tags) {
        p = _profile[user];
        if (p.createdAt == 0) revert NBK__NoProfile();
        tags = _tags[user];
    }

    function profileExists(address user) external view returns (bool) {
        return _profile[user].createdAt != 0;
    }

