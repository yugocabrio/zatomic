// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {Pallas} from "./Pallas.sol";
import {PallasComb} from "./PallasComb.sol";
import {PallasCombTable4, PallasCombTables} from "./PallasCombTables.sol";

/// @notice ETH escrow v2 opened by a canonical RedPallas witness.
/// @dev Same rules as PointEscrow v1; storage and verifier differ. Unreviewed.
/// This contract does NOT verify Zcash funding or finality. Both clients
/// independently verify the agreed native transaction graph before locking.
///
/// One storage slot per order: orders[id] = commitment(order) | state, where
/// commitment(order) = keccak256(abi.encode(order)) with the low three bits
/// cleared. Claim, refund and withdraw take the order as calldata and proceed
/// only for the exact committed fields. States (low three bits):
///   0 (slot == 0)  Empty: never locked
///   LOCKED   1     funds held; claim before refundAt, refund from refundAt
///   CLAIMED  2     recipient credited (secret revealed)
///   REFUNDED 3     maker credited (no reveal through this escrow)
///   PAID     4     flag added to CLAIMED/REFUNDED when the credit is withdrawn
/// No transition leaves PAID, and a nonzero slot is never re-locked.
///
/// The witness is checked against the width-4 comb table that the constructor
/// deploys as its first CREATE (nonce 1). The table address is derived, not
/// stored, so every deployment has the same runtime code.
contract PointEscrowV2 {
    struct Order {
        address maker;
        address recipient;
        uint256 amount;
        uint64 refundAt;
        Pallas.Point point;
        bytes32 termsHash;
    }

    uint256 public constant VERSION = 2;
    uint256 public constant MIN_LOCK_SECONDS = 300;
    uint256 internal constant STATE_BITS = 7;
    uint256 internal constant LOCKED = 1;
    uint256 internal constant CLAIMED = 2;
    uint256 internal constant REFUNDED = 3;
    uint256 internal constant PAID = 4;

    /// id => commitment(order) | state; zero means the id was never locked.
    mapping(bytes32 => uint256) public orders;

    error InvalidOrder();
    error InvalidPoint();
    error OrderExists();
    error NotLocked();
    error ClaimExpired();
    error RefundNotReady();
    error InvalidWitness();
    error InvalidTable();
    error NothingToWithdraw();
    error NotCreditedOwner();
    error WithdrawFailed();

    event Locked(bytes32 indexed id, address indexed maker, address indexed recipient,
        uint256 amount, uint64 refundAt, uint256 x, uint256 y, bytes32 termsHash);
    event Claimed(bytes32 indexed id, uint256 witness);
    event Refunded(bytes32 indexed id);
    event Withdrawn(bytes32 indexed id, address indexed owner, address indexed to, uint256 amount);

    constructor() {
        address created = address(new PallasCombTable4());
        if (created != combTable() || created.codehash != PallasCombTables.CODEHASH_4) revert InvalidTable();
    }

    /// CREATE address of this contract's nonce 1, where the constructor put the table.
    function combTable() public view returns (address) {
        return address(uint160(uint256(keccak256(abi.encodePacked(bytes2(0xd694), address(this), bytes1(0x01))))));
    }

    function orderId(address maker, bytes32 salt) public view returns (bytes32) {
        return keccak256(abi.encode(block.chainid, address(this), maker, salt));
    }

    function commitment(Order memory order) public pure returns (uint256) {
        return uint256(keccak256(abi.encode(order))) & ~STATE_BITS;
    }

    function lock(bytes32 salt, address recipient, uint64 refundAt,
        Pallas.Point calldata point, bytes32 termsHash) external payable returns (bytes32 id)
    {
        if (recipient == address(0) || msg.value == 0 || termsHash == bytes32(0)
            || uint256(refundAt) < block.timestamp + MIN_LOCK_SECONDS) revert InvalidOrder();
        if (!Pallas.onCurve(point)) revert InvalidPoint();
        id = orderId(msg.sender, salt);
        if (orders[id] != 0) revert OrderExists();
        uint256 committed = commitment(Order(msg.sender, recipient, msg.value, refundAt, point, termsHash));
        // A zero commitment (probability 2^-253) would read as an empty slot.
        if (committed == 0) revert InvalidOrder();
        orders[id] = committed | LOCKED;
        emit Locked(id, msg.sender, recipient, msg.value, refundAt, point.x, point.y, termsHash);
    }

    /// Anyone may relay a witness; the order fields fix the recipient. A wrong
    /// field, an empty or settled id all fail the commitment check.
    function claim(bytes32 id, Order calldata order, uint256 witness) external {
        uint256 committed = commitment(order);
        if (orders[id] != (committed | LOCKED)) revert NotLocked();
        if (block.timestamp >= order.refundAt) revert ClaimExpired();
        address comb = combTable();
        if (comb.codehash != PallasCombTables.CODEHASH_4) revert InvalidTable();
        if (!PallasComb.opens(witness, order.point, PallasComb.comb4(comb))) revert InvalidWitness();
        orders[id] = committed | CLAIMED;
        emit Claimed(id, witness);
    }

    function refund(bytes32 id, Order calldata order) external {
        uint256 committed = commitment(order);
        if (orders[id] != (committed | LOCKED)) revert NotLocked();
        if (block.timestamp < order.refundAt) revert RefundNotReady();
        orders[id] = committed | REFUNDED;
        emit Refunded(id);
    }

    /// Credit then withdraw: only the credited owner (the recipient after a
    /// claim, the maker after a refund) moves the amount, to any address. A
    /// rejecting receiver cannot block the claim, and a failed transfer reverts
    /// with the credit intact.
    function withdraw(bytes32 id, Order calldata order, address payable to) external {
        uint256 committed = commitment(order);
        uint256 slot = orders[id];
        address owner;
        if (slot == (committed | CLAIMED)) owner = order.recipient;
        else if (slot == (committed | REFUNDED)) owner = order.maker;
        else revert NothingToWithdraw();
        if (msg.sender != owner) revert NotCreditedOwner();
        if (to == address(0)) revert InvalidOrder();
        orders[id] = slot | PAID;
        (bool ok,) = to.call{value: order.amount}("");
        if (!ok) revert WithdrawFailed();
        emit Withdrawn(id, owner, to, order.amount);
    }
}
