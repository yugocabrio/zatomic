// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {Pallas} from "./Pallas.sol";

/// @notice ETH escrow opened by a canonical RedPallas witness.
/// @dev This contract does NOT verify Zcash funding or finality. Both clients
/// independently verify the agreed native transaction graph before locking.
contract PointEscrow {
    enum State { Empty, Locked, Claimed, Refunded }
    struct Order {
        address maker;
        address recipient;
        uint256 amount;
        uint64 refundAt;
        State state;
        Pallas.Point point;
        bytes32 termsHash;
    }
    mapping(bytes32 => Order) public orders;
    mapping(address => uint256) public credits;
    uint256 public constant MIN_LOCK_SECONDS = 300;

    error InvalidOrder();
    error InvalidPoint();
    error OrderExists();
    error NotLocked();
    error ClaimExpired();
    error RefundNotReady();
    error InvalidWitness();
    error WithdrawFailed();

    event Locked(bytes32 indexed id, address indexed maker, address indexed recipient,
        uint256 amount, uint64 refundAt, uint256 x, uint256 y, bytes32 termsHash);
    event Claimed(bytes32 indexed id, uint256 witness);
    event Refunded(bytes32 indexed id);
    event Withdrawn(address indexed owner, address indexed to, uint256 amount);

    function orderId(address maker, bytes32 salt) public view returns (bytes32) {
        return keccak256(abi.encode(block.chainid, address(this), maker, salt));
    }

    function lock(bytes32 salt, address recipient, uint64 refundAt,
        Pallas.Point calldata point, bytes32 termsHash) external payable returns (bytes32 id)
    {
        if (recipient == address(0) || msg.value == 0 || termsHash == bytes32(0)
            || uint256(refundAt) < block.timestamp + MIN_LOCK_SECONDS) revert InvalidOrder();
        if (!Pallas.onCurve(point)) revert InvalidPoint();
        id = orderId(msg.sender, salt);
        if (orders[id].state != State.Empty) revert OrderExists();
        orders[id] = Order(msg.sender, recipient, msg.value, refundAt, State.Locked, point, termsHash);
        emit Locked(id, msg.sender, recipient, msg.value, refundAt, point.x, point.y, termsHash);
    }

    /// Anyone may relay a witness; they cannot replace the fixed recipient.
    /// Credit first, withdraw separately: a rejecting receiver cannot revert
    /// secret revelation after a valid claim has been included.
    function claim(bytes32 id, uint256 witness) external {
        Order storage order = orders[id];
        if (order.state != State.Locked) revert NotLocked();
        if (block.timestamp >= order.refundAt) revert ClaimExpired();
        if (!Pallas.opens(witness, order.point)) revert InvalidWitness();
        order.state = State.Claimed;
        credits[order.recipient] += order.amount;
        emit Claimed(id, witness);
    }

    function refund(bytes32 id) external {
        Order storage order = orders[id];
        if (order.state != State.Locked) revert NotLocked();
        if (block.timestamp < order.refundAt) revert RefundNotReady();
        order.state = State.Refunded;
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
