// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;
import {Pallas} from "../src/Pallas.sol";
import {PointEscrowFast} from "../bench/PointEscrowFast.sol";
import {HashedPointEscrow} from "../bench/HashedPointEscrow.sol";

interface Vm {
    function deal(address who, uint256 amount) external;
    function prank(address who) external;
    function warp(uint256 timestamp) external;
    function expectRevert(bytes4 selector) external;
    function deployCode(string calldata artifactPath) external returns (address);
}

/// BENCHMARK ONLY. The gas-benchmark escrows keep PointEscrow's rules.
contract BenchEscrowsTest {
    Vm constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));
    address constant BOB = address(0xb0b);
    address constant ALICE = address(0xa11ce);
    address constant RELAYER = address(0xcafe);
    // pasta_curves vector (contracts/test/PallasVectors.t.sol, vector 3).
    uint256 constant K = 0x0c67421df8d3ae89643f1af5d0ab86613c17f2cda8835e3914efcaa5805b3611;
    uint256 constant KX = 0x027c4ff5156586fb9742a9faace499f6a14533f3c05119a27c8e0990d57a74f1;
    uint256 constant KY = 0x0e0d47ab8f5bc4f2666f7a4fac65c57c7e8a7ed7ebbb1b9a8a5ff479c93bf235;
    bytes32 constant TERMS = keccak256("synthetic swap terms");
    address table;
    PointEscrowFast fast;
    HashedPointEscrow hashed;
    uint64 expiry;

    function setUp() public {
        table = vm.deployCode("PallasCombTables.sol:PallasCombTable8");
        fast = new PointEscrowFast(table, 8);
        hashed = new HashedPointEscrow(table, 8);
        vm.warp(1_800_000_000);
        expiry = uint64(block.timestamp + 1800);
        vm.deal(BOB, 10 ether);
    }

    function order(address recipient) internal view returns (HashedPointEscrow.Order memory) {
        return HashedPointEscrow.Order(BOB, recipient, 1 ether, expiry, Pallas.Point(KX, KY), TERMS);
    }

    function lockHashed(address recipient) internal returns (bytes32) {
        vm.prank(BOB);
        return hashed.lock{value: 1 ether}(bytes32(uint256(7)), recipient, expiry, Pallas.Point(KX, KY), TERMS);
    }

    function testConstructorsRejectWrongTable() public {
        address table7 = vm.deployCode("PallasCombTables.sol:PallasCombTable7");
        vm.expectRevert(PointEscrowFast.InvalidTable.selector);
        new PointEscrowFast(table7, 8);
        vm.expectRevert(PointEscrowFast.InvalidTable.selector);
        new PointEscrowFast(table, 9);
        vm.expectRevert(HashedPointEscrow.InvalidTable.selector);
        new HashedPointEscrow(address(0), 8);
        vm.expectRevert(HashedPointEscrow.InvalidTable.selector);
        new HashedPointEscrow(table, 7);
    }

    /// Each width, shared by a fast and a hashed escrow, settles the same opening.
    function testEveryWidthSettles() public {
        string[4] memory names = ["PallasCombTables.sol:PallasCombTable4", "PallasCombTables.sol:PallasCombTable5",
            "PallasCombTables.sol:PallasCombTable6", "PallasCombTables.sol:PallasCombTable7"];
        for (uint256 i; i < names.length; ++i) {
            address shared = vm.deployCode(names[i]);
            PointEscrowFast f = new PointEscrowFast(shared, i + 4);
            HashedPointEscrow h = new HashedPointEscrow(shared, i + 4);
            vm.prank(BOB);
            bytes32 id = f.lock{value: 1 ether}(bytes32(i), ALICE, expiry, Pallas.Point(KX, KY), TERMS);
            vm.expectRevert(PointEscrowFast.InvalidWitness.selector); f.claim(id, K + 1);
            f.claim(id, K);
            vm.prank(BOB);
            id = h.lock{value: 1 ether}(bytes32(i), ALICE, expiry, Pallas.Point(KX, KY), TERMS);
            vm.expectRevert(HashedPointEscrow.InvalidWitness.selector); h.claim(id, order(ALICE), K + 1);
            h.claim(id, order(ALICE), K);
            require(f.credits(ALICE) == 1 ether && h.credits(ALICE) == 1 ether && f.teeth() == i + 4);
        }
    }

    function testFastClaimRefundAndReplay() public {
        vm.prank(BOB);
        bytes32 id = fast.lock{value: 1 ether}(bytes32(uint256(7)), ALICE, expiry, Pallas.Point(KX, KY), TERMS);
        vm.expectRevert(PointEscrowFast.InvalidWitness.selector); fast.claim(id, K + 1);
        vm.expectRevert(PointEscrowFast.InvalidWitness.selector); fast.claim(id, K + Pallas.Q);
        vm.expectRevert(PointEscrowFast.InvalidWitness.selector); fast.claim(id, 0);
        vm.prank(RELAYER); fast.claim(id, K);
        require(fast.credits(ALICE) == 1 ether && fast.credits(RELAYER) == 0);
        vm.expectRevert(PointEscrowFast.NotLocked.selector); fast.claim(id, K);
        vm.warp(expiry); vm.expectRevert(PointEscrowFast.NotLocked.selector); fast.refund(id);
        vm.prank(ALICE); fast.withdraw(payable(ALICE));
        require(ALICE.balance == 1 ether && address(fast).balance == 0);

        vm.prank(BOB);
        bytes32 other = fast.lock{value: 1 ether}(bytes32(uint256(8)), ALICE, uint64(block.timestamp + 1800),
            Pallas.Point(KX, KY), TERMS);
        vm.warp(block.timestamp + 1799);
        vm.expectRevert(PointEscrowFast.RefundNotReady.selector); fast.refund(other);
        vm.warp(block.timestamp + 1);
        vm.expectRevert(PointEscrowFast.ClaimExpired.selector); fast.claim(other, K);
        fast.refund(other);
        require(fast.credits(BOB) == 1 ether);
    }

    function testHashedClaimPaysOnlyAgreedRecipient() public {
        bytes32 id = lockHashed(ALICE);
        require(hashed.orders(id) == hashed.orderHash(order(ALICE)));
        vm.prank(RELAYER); hashed.claim(id, order(ALICE), K);
        require(hashed.credits(ALICE) == 1 ether && hashed.credits(RELAYER) == 0);
        vm.expectRevert(HashedPointEscrow.NotLocked.selector); hashed.claim(id, order(ALICE), K);
        vm.warp(expiry);
        vm.expectRevert(HashedPointEscrow.NotLocked.selector); hashed.refund(id, order(ALICE));
        vm.prank(ALICE); hashed.withdraw(payable(ALICE));
        require(ALICE.balance == 1 ether && address(hashed).balance == 0);
        vm.prank(BOB); vm.expectRevert(HashedPointEscrow.OrderExists.selector);
        hashed.lock{value: 1 ether}(bytes32(uint256(7)), ALICE, uint64(block.timestamp + 1800),
            Pallas.Point(KX, KY), TERMS);
    }

    function testHashedRejectsAnyAlteredField() public {
        bytes32 id = lockHashed(ALICE);
        HashedPointEscrow.Order memory o = order(ALICE);
        o.recipient = RELAYER;
        vm.expectRevert(HashedPointEscrow.NotLocked.selector); hashed.claim(id, o, K);
        o = order(ALICE); o.amount = 2 ether;
        vm.expectRevert(HashedPointEscrow.NotLocked.selector); hashed.claim(id, o, K);
        o = order(ALICE); o.refundAt = expiry + 1;
        vm.expectRevert(HashedPointEscrow.NotLocked.selector); hashed.claim(id, o, K);
        // A different point the claimer can open (1*G) does not match the stored hash.
        o = order(ALICE); o.point = Pallas.Point(Pallas.GX, Pallas.GY);
        vm.expectRevert(HashedPointEscrow.NotLocked.selector); hashed.claim(id, o, 1);
        o = order(ALICE); o.maker = ALICE;
        vm.warp(expiry);
        vm.expectRevert(HashedPointEscrow.NotLocked.selector); hashed.refund(id, o);
        vm.expectRevert(HashedPointEscrow.NotLocked.selector); hashed.refund(bytes32(uint256(1)), order(ALICE));
        hashed.refund(id, order(ALICE));
        require(hashed.credits(BOB) == 1 ether && hashed.credits(ALICE) == 0);
    }

    /// Non-canonical encodings of the same order (dirty high bits in an address or
    /// uint64 word) are rejected rather than cleaned.
    function testHashedRejectsDirtyOrderWords() public {
        bytes32 id = lockHashed(ALICE);
        bytes memory good = abi.encodeCall(HashedPointEscrow.claim, (id, order(ALICE), K));
        uint256[3] memory words = [uint256(1), 2, 4]; // maker, recipient, refundAt (after selector and id)
        for (uint256 i; i < words.length; ++i) {
            bytes memory bad = bytes.concat(good);
            uint256 at = 4 + 32 * words[i];
            assembly { let p := add(add(bad, 0x20), at) mstore(p, or(mload(p), shl(248, 1))) }
            (bool ok,) = address(hashed).call(bad);
            require(!ok, "dirty word accepted");
        }
        (bool fine,) = address(hashed).call(good);
        require(fine && hashed.credits(ALICE) == 1 ether);
    }

    function testHashedTimingAndWitness() public {
        bytes32 id = lockHashed(ALICE);
        vm.expectRevert(HashedPointEscrow.InvalidWitness.selector); hashed.claim(id, order(ALICE), K + 1);
        vm.expectRevert(HashedPointEscrow.InvalidWitness.selector); hashed.claim(id, order(ALICE), K + Pallas.Q);
        vm.warp(expiry - 1);
        vm.expectRevert(HashedPointEscrow.RefundNotReady.selector); hashed.refund(id, order(ALICE));
        vm.warp(expiry);
        vm.expectRevert(HashedPointEscrow.ClaimExpired.selector); hashed.claim(id, order(ALICE), K);
        hashed.refund(id, order(ALICE));
        vm.expectRevert(HashedPointEscrow.NotLocked.selector); hashed.refund(id, order(ALICE));
    }

    function testHashedLockValidation() public {
        vm.prank(BOB); vm.expectRevert(HashedPointEscrow.InvalidPoint.selector);
        hashed.lock{value: 1 ether}(bytes32(uint256(1)), ALICE, expiry, Pallas.Point(0, 0), TERMS);
        vm.prank(BOB); vm.expectRevert(HashedPointEscrow.InvalidOrder.selector);
        hashed.lock{value: 1 ether}(bytes32(uint256(1)), ALICE, uint64(block.timestamp + 10), Pallas.Point(KX, KY), TERMS);
        vm.prank(BOB); vm.expectRevert(HashedPointEscrow.InvalidOrder.selector);
        hashed.lock{value: 1 ether}(bytes32(uint256(1)), address(0), expiry, Pallas.Point(KX, KY), TERMS);
    }
}
