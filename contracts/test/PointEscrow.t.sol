// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;
import {Pallas} from "../src/Pallas.sol";
import {PointEscrow} from "../src/PointEscrow.sol";

interface Vm {
    function deal(address who, uint256 amount) external;
    function prank(address who) external;
    function warp(uint256 timestamp) external;
    function expectRevert(bytes4 selector) external;
    function chainId(uint256 newChainId) external;
}

contract RejectEther {
    receive() external payable { revert(); }
    function withdraw(PointEscrow escrow, address payable to) external { escrow.withdraw(to); }
}

contract PointEscrowTest {
    Vm constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));
    address constant BOB = address(0xb0b);
    address constant ALICE = address(0xa11ce);
    address constant RELAYER = address(0xcafe);
    PointEscrow escrow;
    uint64 expiry;

    function setUp() public {
        escrow = new PointEscrow();
        vm.warp(1_800_000_000);
        expiry = uint64(block.timestamp + 1800);
        vm.deal(BOB, 10 ether);
    }

    function lock(address recipient) internal returns (bytes32) {
        vm.prank(BOB);
        return escrow.lock{value: 1 ether}(bytes32(uint256(7)), recipient, expiry,
            Pallas.Point(Pallas.GX, Pallas.GY), keccak256("synthetic swap terms"));
    }

    function testRelayedClaimPaysOnlyAgreedRecipient() public {
        bytes32 id = lock(ALICE);
        vm.prank(RELAYER); escrow.claim(id, 1);
        require(escrow.credits(ALICE) == 1 ether && escrow.credits(RELAYER) == 0);
        vm.prank(ALICE); escrow.withdraw(payable(ALICE));
        require(ALICE.balance == 1 ether && address(escrow).balance == 0);
        vm.expectRevert(PointEscrow.NotLocked.selector); escrow.claim(id, 1);
        vm.warp(expiry); vm.expectRevert(PointEscrow.NotLocked.selector); escrow.refund(id);
    }

    function testRefundBoundaryAndExpiredClaim() public {
        bytes32 id = lock(ALICE);
        vm.warp(expiry - 1);
        vm.expectRevert(PointEscrow.RefundNotReady.selector); escrow.refund(id);
        vm.warp(expiry);
        vm.expectRevert(PointEscrow.ClaimExpired.selector); escrow.claim(id, 1);
        vm.prank(RELAYER); escrow.refund(id);
        require(escrow.credits(BOB) == 1 ether && escrow.credits(ALICE) == 0);
        vm.expectRevert(PointEscrow.NotLocked.selector); escrow.refund(id);
    }

    function testInvalidWitnessCannotConsumeEscrow() public {
        bytes32 id = lock(ALICE);
        vm.expectRevert(PointEscrow.InvalidWitness.selector); escrow.claim(id, 2);
        vm.expectRevert(PointEscrow.InvalidWitness.selector); escrow.claim(id, 0);
        vm.expectRevert(PointEscrow.InvalidWitness.selector); escrow.claim(id, Pallas.Q + 1);
        escrow.claim(id, 1);
        require(escrow.credits(ALICE) == 1 ether);
    }

    function testRejectingReceiverCannotBlockClaimAndCanWithdrawElsewhere() public {
        RejectEther receiver = new RejectEther();
        bytes32 id = lock(address(receiver));
        escrow.claim(id, 1);
        require(escrow.credits(address(receiver)) == 1 ether);
        vm.expectRevert(PointEscrow.WithdrawFailed.selector);
        receiver.withdraw(escrow, payable(receiver));
        require(escrow.credits(address(receiver)) == 1 ether);
        receiver.withdraw(escrow, payable(ALICE));
        require(ALICE.balance == 1 ether);
    }

    function testDomainSeparationAndOrderCannotBeOverwritten() public {
        bytes32 id = lock(ALICE);
        vm.prank(BOB); vm.expectRevert(PointEscrow.OrderExists.selector);
        escrow.lock{value: 1 ether}(bytes32(uint256(7)), RELAYER, expiry,
            Pallas.Point(Pallas.GX, Pallas.GY), bytes32(uint256(1)));
        require(id != escrow.orderId(RELAYER, bytes32(uint256(7))));
        PointEscrow other = new PointEscrow();
        require(id != other.orderId(BOB, bytes32(uint256(7))));
        vm.chainId(block.chainid + 1);
        require(id != escrow.orderId(BOB, bytes32(uint256(7))));
    }

    function testInvalidCurvePointAndShortDeadlineReject() public {
        vm.prank(BOB); vm.expectRevert(PointEscrow.InvalidPoint.selector);
        escrow.lock{value: 1 ether}(bytes32(uint256(1)), ALICE, expiry,
            Pallas.Point(0, 0), bytes32(uint256(1)));
        vm.prank(BOB); vm.expectRevert(PointEscrow.InvalidOrder.selector);
        escrow.lock{value: 1 ether}(bytes32(uint256(1)), ALICE, uint64(block.timestamp + 10),
            Pallas.Point(Pallas.GX, Pallas.GY), bytes32(uint256(1)));
    }
}
