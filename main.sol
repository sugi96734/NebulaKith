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
