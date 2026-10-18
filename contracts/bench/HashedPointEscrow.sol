// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {Pallas} from "../src/Pallas.sol";
import {PallasComb} from "../src/PallasComb.sol";
import {PallasCombTables} from "../src/PallasCombTables.sol";

/// @notice BENCHMARK ONLY, not deployed. PointEscrowFast with one storage slot per
/// order: lock stores keccak256(abi.encode(Order)); claim and refund take the
/// order fields as calldata and must reproduce that hash. After settlement the
/// slot holds a CLAIMED or REFUNDED tombstone, so an id is never reused. The
/// Locked event still carries every field, so either party can rebuild the call.
contract HashedPointEscrow {
    struct Order {
        address maker;
        address recipient;
        uint256 amount;
        uint64 refundAt;
        Pallas.Point point;
        bytes32 termsHash;
    }
    bytes32 internal constant CLAIMED = bytes32(uint256(1));
    bytes32 internal constant REFUNDED = bytes32(uint256(2));
    /// id => order hash while locked, then CLAIMED or REFUNDED; zero means empty.
    mapping(bytes32 => bytes32) public orders;
    mapping(address => uint256) public credits;
    uint256 public constant MIN_LOCK_SECONDS = 300;
    address public immutable table;
    uint256 public immutable teeth;
    uint256 internal immutable spacing;
    uint256 internal immutable mask;
    uint256 internal immutable magic;
    uint256 internal immutable shift;

    error InvalidOrder();
    error InvalidPoint();
    error OrderExists();
    error NotLocked();
    error ClaimExpired();
    error RefundNotReady();
    error InvalidWitness();
    error WithdrawFailed();
    error InvalidTable();

    event Locked(bytes32 indexed id, address indexed maker, address indexed recipient,
        uint256 amount, uint64 refundAt, uint256 x, uint256 y, bytes32 termsHash);
    event Claimed(bytes32 indexed id, uint256 witness);
    event Refunded(bytes32 indexed id);
    event Withdrawn(address indexed owner, address indexed to, uint256 amount);

    /// The comb width is fixed at deployment; the table must be PallasCombTable{teeth_}.
    constructor(address table_, uint256 teeth_) {
        bytes32 expected = PallasCombTables.codehash(teeth_);
        if (expected == bytes32(0) || table_.codehash != expected) revert InvalidTable();
        PallasComb.Comb memory c = PallasComb.comb(table_, teeth_);
        (table, teeth, spacing, mask, magic, shift) = (table_, teeth_, c.spacing, c.mask, c.magic, c.shift);
    }

    function comb() internal view returns (PallasComb.Comb memory) {
        return PallasComb.Comb(table, teeth, spacing, mask, magic, shift);
    }

    function orderId(address maker, bytes32 salt) public view returns (bytes32) {
        return keccak256(abi.encode(block.chainid, address(this), maker, salt));
    }

    function orderHash(Order memory order) public pure returns (bytes32) {
        return keccak256(abi.encode(order));
    }

    function lock(bytes32 salt, address recipient, uint64 refundAt,
        Pallas.Point calldata point, bytes32 termsHash) external payable returns (bytes32 id)
    {
        if (recipient == address(0) || msg.value == 0 || termsHash == bytes32(0)
            || uint256(refundAt) < block.timestamp + MIN_LOCK_SECONDS) revert InvalidOrder();
        if (!Pallas.onCurve(point)) revert InvalidPoint();
        id = orderId(msg.sender, salt);
        if (orders[id] != bytes32(0)) revert OrderExists();
        orders[id] = orderHash(Order(msg.sender, recipient, msg.value, refundAt, point, termsHash));
        emit Locked(id, msg.sender, recipient, msg.value, refundAt, point.x, point.y, termsHash);
    }

    /// A wrong field, an empty id and a settled id all fail the hash check.
    function claim(bytes32 id, Order calldata order, uint256 witness) external {
        if (orders[id] != orderHash(order)) revert NotLocked();
        if (block.timestamp >= order.refundAt) revert ClaimExpired();
        if (!PallasComb.opens(witness, order.point, comb())) revert InvalidWitness();
        orders[id] = CLAIMED;
        credits[order.recipient] += order.amount;
        emit Claimed(id, witness);
    }

    function refund(bytes32 id, Order calldata order) external {
        if (orders[id] != orderHash(order)) revert NotLocked();
        if (block.timestamp < order.refundAt) revert RefundNotReady();
        orders[id] = REFUNDED;
        credits[order.maker] += order.amount;
        emit Refunded(id);
    }

    function withdraw(address payable to) external {
        uint256 amount = credits[msg.sender];
        if (to == address(0) || amount == 0) revert InvalidOrder();
        credits[msg.sender] = 0;
        (bool ok,) = to.call{value: amount}("");
        if (!ok) revert WithdrawFailed();
        emit Withdrawn(msg.sender, to, amount);
    }
}
