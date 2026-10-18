// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;
import {Pallas} from "../src/Pallas.sol";
import {PointEscrowV2} from "../src/PointEscrowV2.sol";
import {PallasCombTables} from "../src/PallasCombTables.sol";
import {PallasOracle} from "./PallasOracle.sol";

interface Vm {
    function deal(address who, uint256 amount) external;
    function prank(address who) external;
    function warp(uint256 timestamp) external;
    function expectRevert(bytes4 selector) external;
    function chainId(uint256 newChainId) external;
    function etch(address target, bytes calldata code) external;
}

/// Owner contract whose receive() reverts; it can still withdraw elsewhere.
contract RejectingOwner {
    receive() external payable { revert(); }
    function withdraw(PointEscrowV2 e, bytes32 id, PointEscrowV2.Order calldata o, address payable to) external {
        e.withdraw(id, o, to);
    }
}

/// Owner contract that tries to withdraw the same credit again from receive().
contract ReentrantOwner {
    PointEscrowV2 escrow;
    bytes32 id;
    PointEscrowV2.Order order;
    uint256 public reentered;
    bytes4 public reentryError;
    function withdraw(PointEscrowV2 e, bytes32 i, PointEscrowV2.Order calldata o) external {
        (escrow, id, order) = (e, i, o);
        e.withdraw(i, o, payable(address(this)));
    }
    receive() external payable {
        reentered += 1;
        try escrow.withdraw(id, order, payable(address(this))) {} catch (bytes memory reason) {
            reentryError = bytes4(reason);
        }
    }
}

contract PointEscrowV2Test is PallasOracle {
    Vm constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));
    address constant BOB = address(0xb0b);
    address constant ALICE = address(0xa11ce);
    address constant RELAYER = address(0xcafe);
    // pasta_curves vector (contracts/test/PallasVectors.t.sol, vector 3).
    uint256 constant K = 0x0c67421df8d3ae89643f1af5d0ab86613c17f2cda8835e3914efcaa5805b3611;
    uint256 constant KX = 0x027c4ff5156586fb9742a9faace499f6a14533f3c05119a27c8e0990d57a74f1;
    uint256 constant KY = 0x0e0d47ab8f5bc4f2666f7a4fac65c57c7e8a7ed7ebbb1b9a8a5ff479c93bf235;
    bytes32 constant TERMS = keccak256("synthetic swap terms");
    bytes32 constant SALT = bytes32(uint256(7));
    uint256 constant LOCKED = 1;
    uint256 constant CLAIMED = 2;
    uint256 constant REFUNDED = 3;
    uint256 constant PAID = 4;
    PointEscrowV2 escrow;
    uint64 expiry;

    event log_named_uint(string key, uint256 val);

    function setUp() public {
        escrow = new PointEscrowV2();
        vm.warp(1_800_000_000);
        expiry = uint64(block.timestamp + 1800);
        vm.deal(BOB, 10 ether);
    }

    // ---- helpers ----

    function order(address recipient) internal view returns (PointEscrowV2.Order memory) {
        return PointEscrowV2.Order(BOB, recipient, 1 ether, expiry, Pallas.Point(KX, KY), TERMS);
    }

    function lockFor(address recipient, uint256 x, uint256 y) internal returns (bytes32) {
        vm.prank(BOB);
        return escrow.lock{value: 1 ether}(SALT, recipient, expiry, Pallas.Point(x, y), TERMS);
    }

    function lock() internal returns (bytes32) {
        return lockFor(ALICE, KX, KY);
    }

    /// The same commitment computed outside the contract.
    function committed(PointEscrowV2.Order memory o) internal pure returns (uint256) {
        return uint256(keccak256(abi.encode(o.maker, o.recipient, o.amount, o.refundAt, o.point.x, o.point.y,
            o.termsHash))) & ~uint256(7);
    }

    /// A copy of o with exactly one field changed (0..6).
    function altered(PointEscrowV2.Order memory o, uint256 field) internal pure returns (PointEscrowV2.Order memory a) {
        a = PointEscrowV2.Order(o.maker, o.recipient, o.amount, o.refundAt, Pallas.Point(o.point.x, o.point.y), o.termsHash);
        if (field == 0) a.maker = address(uint160(o.maker) ^ 1);
        else if (field == 1) a.recipient = address(uint160(o.recipient) ^ 1);
        else if (field == 2) a.amount = o.amount + 1;
        else if (field == 3) a.refundAt = o.refundAt + 1;
        else if (field == 4) a.point.x = o.point.x ^ 1;
        else if (field == 5) a.point.y = o.point.y ^ 1;
        else a.termsHash = o.termsHash ^ bytes32(uint256(1));
    }

    // ---- deployment ----

    function testConstructorDeploysTheWidth4TableAtNonceOne() public {
        address t = escrow.combTable();
        require(t.codehash == PallasCombTables.CODEHASH_4 && t.code.length == PallasCombTables.SIZE_4);
        require(escrow.VERSION() == 2);
        // No immutables: every deployment has identical runtime code.
        PointEscrowV2 other = new PointEscrowV2();
        require(address(other).codehash == address(escrow).codehash && other.combTable() != t);
        require(other.combTable().codehash == PallasCombTables.CODEHASH_4);
    }

    function testRuntimeWithoutItsTableRejectsClaimsWithoutStateChange() public {
        // Runtime bytes placed without running the constructor: no table exists.
        address bare = address(0xbad);
        vm.etch(bare, address(escrow).code);
        PointEscrowV2 e = PointEscrowV2(bare);
        require(e.combTable().code.length == 0);
        vm.prank(BOB);
        bytes32 id = e.lock{value: 1 ether}(SALT, ALICE, expiry, Pallas.Point(KX, KY), TERMS);
        PointEscrowV2.Order memory o = PointEscrowV2.Order(BOB, ALICE, 1 ether, expiry, Pallas.Point(KX, KY), TERMS);
        vm.expectRevert(PointEscrowV2.InvalidTable.selector); e.claim(id, o, K);
        require(e.orders(id) == (committed(o) | LOCKED));
    }

    // ---- success path ----

    function testRelayedClaimCreditsOnlyTheFixedRecipient() public {
        bytes32 id = lock();
        PointEscrowV2.Order memory o = order(ALICE);
        require(escrow.orders(id) == (committed(o) | LOCKED) && escrow.commitment(o) == committed(o));
        vm.prank(RELAYER); escrow.claim(id, o, K);
        require(escrow.orders(id) == (committed(o) | CLAIMED));
        require(address(escrow).balance == 1 ether && ALICE.balance == 0);
        // Neither the relayer nor the maker can move Alice's credit.
        vm.prank(RELAYER); vm.expectRevert(PointEscrowV2.NotCreditedOwner.selector);
        escrow.withdraw(id, o, payable(RELAYER));
        vm.prank(BOB); vm.expectRevert(PointEscrowV2.NotCreditedOwner.selector);
        escrow.withdraw(id, o, payable(BOB));
        vm.prank(ALICE); escrow.withdraw(id, o, payable(ALICE));
        require(ALICE.balance == 1 ether && address(escrow).balance == 0);
        require(escrow.orders(id) == (committed(o) | CLAIMED | PAID));
        vm.prank(ALICE); vm.expectRevert(PointEscrowV2.NothingToWithdraw.selector);
        escrow.withdraw(id, o, payable(ALICE));
        vm.expectRevert(PointEscrowV2.NotLocked.selector); escrow.claim(id, o, K);
        vm.warp(expiry);
        vm.expectRevert(PointEscrowV2.NotLocked.selector); escrow.refund(id, o);
        vm.prank(BOB); vm.expectRevert(PointEscrowV2.OrderExists.selector);
        escrow.lock{value: 1 ether}(SALT, ALICE, uint64(block.timestamp + 1800), Pallas.Point(KX, KY), TERMS);
    }

    /// A front-runner who copies t from the pending claim can only complete the
    /// same order: Alice is credited and her own claim reverts harmlessly.
    function testFrontRunningCopiedWitnessStillPaysAlice() public {
        bytes32 id = lock();
        PointEscrowV2.Order memory o = order(ALICE);
        vm.prank(RELAYER); escrow.claim(id, o, K);
        vm.prank(ALICE); vm.expectRevert(PointEscrowV2.NotLocked.selector); escrow.claim(id, o, K);
        vm.prank(ALICE); escrow.withdraw(id, o, payable(ALICE));
        require(ALICE.balance == 1 ether);
    }

    /// A front-runner who alters the order data cannot redirect or settle it.
    function testFrontRunningWithAlteredOrderReverts() public {
        bytes32 id = lock();
        PointEscrowV2.Order memory o = order(ALICE);
        for (uint256 field; field < 7; ++field) {
            vm.prank(RELAYER); vm.expectRevert(PointEscrowV2.NotLocked.selector);
            escrow.claim(id, altered(o, field), K);
        }
        PointEscrowV2.Order memory redirected = order(RELAYER);
        vm.prank(RELAYER); vm.expectRevert(PointEscrowV2.NotLocked.selector); escrow.claim(id, redirected, K);
        // A point the front-runner can open (1*G) is not the committed point.
        PointEscrowV2.Order memory easy = order(ALICE);
        easy.point = Pallas.Point(Pallas.GX, Pallas.GY);
        vm.prank(RELAYER); vm.expectRevert(PointEscrowV2.NotLocked.selector); escrow.claim(id, easy, 1);
        require(escrow.orders(id) == (committed(o) | LOCKED));
        escrow.claim(id, o, K);
        require(escrow.orders(id) == (committed(o) | CLAIMED));
    }

    // ---- altered order data on every path ----

    function testAnyAlteredFieldRevertsOnClaimRefundAndWithdraw() public {
        bytes32 id = lock();
        PointEscrowV2.Order memory o = order(ALICE);
        for (uint256 field; field < 7; ++field) {
            vm.expectRevert(PointEscrowV2.NotLocked.selector); escrow.claim(id, altered(o, field), K);
        }
        escrow.claim(id, o, K);
        for (uint256 field; field < 7; ++field) {
            PointEscrowV2.Order memory a = altered(o, field);
            vm.prank(a.recipient); vm.expectRevert(PointEscrowV2.NothingToWithdraw.selector);
            escrow.withdraw(id, a, payable(a.recipient));
        }
        vm.prank(ALICE); escrow.withdraw(id, o, payable(ALICE));

        vm.prank(BOB);
        bytes32 other = escrow.lock{value: 1 ether}(bytes32(uint256(8)), ALICE, expiry, Pallas.Point(KX, KY), TERMS);
        vm.warp(expiry);
        for (uint256 field; field < 7; ++field) {
            vm.expectRevert(PointEscrowV2.NotLocked.selector); escrow.refund(other, altered(o, field));
        }
        vm.expectRevert(PointEscrowV2.NotLocked.selector); escrow.refund(bytes32(uint256(1)), o);
        escrow.refund(other, o);
        for (uint256 field; field < 7; ++field) {
            PointEscrowV2.Order memory a = altered(o, field);
            vm.prank(a.maker); vm.expectRevert(PointEscrowV2.NothingToWithdraw.selector);
            escrow.withdraw(other, a, payable(a.maker));
        }
        // The correct order on the wrong id is not a credit either.
        vm.prank(BOB); vm.expectRevert(PointEscrowV2.NothingToWithdraw.selector);
        escrow.withdraw(id, o, payable(BOB));
        vm.prank(BOB); escrow.withdraw(other, o, payable(BOB));
        require(BOB.balance == 9 ether && ALICE.balance == 1 ether && address(escrow).balance == 0);
    }

    /// Non-canonical encodings (dirty high bits in an address or uint64 word)
    /// revert on all three paths instead of being cleaned.
    function testDirtyOrderWordsRevertOnEveryPath() public {
        bytes32 id = lock();
        PointEscrowV2.Order memory o = order(ALICE);
        bytes[3] memory calls = [abi.encodeCall(PointEscrowV2.claim, (id, o, K)),
            abi.encodeCall(PointEscrowV2.refund, (id, o)),
            abi.encodeCall(PointEscrowV2.withdraw, (id, o, payable(ALICE)))];
        uint256[3] memory words = [uint256(1), 2, 4]; // maker, recipient, refundAt after the id word
        for (uint256 c; c < calls.length; ++c) {
            for (uint256 i; i < words.length; ++i) {
                bytes memory bad = bytes.concat(calls[c]);
                uint256 at = 4 + 32 * words[i];
                assembly { let p := add(add(bad, 0x20), at) mstore(p, or(mload(p), shl(248, 1))) }
                vm.prank(ALICE);
                (bool ok,) = address(escrow).call(bad);
                require(!ok, "dirty order word accepted");
            }
        }
        require(escrow.orders(id) == (committed(o) | LOCKED));
    }

    // ---- refund path and timing ----

    function testRefundOnlyFromExpiryAndClaimOnlyBefore() public {
        bytes32 id = lock();
        PointEscrowV2.Order memory o = order(ALICE);
        vm.warp(expiry - 1);
        vm.expectRevert(PointEscrowV2.RefundNotReady.selector); escrow.refund(id, o);
        vm.warp(expiry);
        vm.expectRevert(PointEscrowV2.ClaimExpired.selector); escrow.claim(id, o, K);
        vm.prank(RELAYER); escrow.refund(id, o);
        require(escrow.orders(id) == (committed(o) | REFUNDED));
        vm.expectRevert(PointEscrowV2.NotLocked.selector); escrow.refund(id, o);
        vm.expectRevert(PointEscrowV2.NotLocked.selector); escrow.claim(id, o, K);
        vm.prank(ALICE); vm.expectRevert(PointEscrowV2.NotCreditedOwner.selector);
        escrow.withdraw(id, o, payable(ALICE));
        vm.prank(RELAYER); vm.expectRevert(PointEscrowV2.NotCreditedOwner.selector);
        escrow.withdraw(id, o, payable(RELAYER));
        vm.prank(BOB); escrow.withdraw(id, o, payable(address(0xb0b2)));
        require(address(0xb0b2).balance == 1 ether && escrow.orders(id) == (committed(o) | REFUNDED | PAID));
    }

    /// An agreed order that was never locked stays empty, and after its expiry it
    /// can no longer be created, so Alice can safely take the native refund.
    function testNeverLockedOrderStaysEmptyAndCannotBeCreatedLate() public {
        bytes32 id = escrow.orderId(BOB, SALT);
        require(escrow.orders(id) == 0);
        PointEscrowV2.Order memory o = order(ALICE);
        vm.expectRevert(PointEscrowV2.NotLocked.selector); escrow.claim(id, o, K);
        vm.warp(expiry);
        vm.expectRevert(PointEscrowV2.NotLocked.selector); escrow.refund(id, o);
        vm.expectRevert(PointEscrowV2.NothingToWithdraw.selector); escrow.withdraw(id, o, payable(ALICE));
        vm.prank(BOB); vm.expectRevert(PointEscrowV2.InvalidOrder.selector);
        escrow.lock{value: 1 ether}(SALT, ALICE, expiry, Pallas.Point(KX, KY), TERMS);
        vm.warp(uint256(expiry) - 299);
        vm.prank(BOB); vm.expectRevert(PointEscrowV2.InvalidOrder.selector);
        escrow.lock{value: 1 ether}(SALT, ALICE, expiry, Pallas.Point(KX, KY), TERMS);
        require(escrow.orders(id) == 0);
    }

    // ---- witnesses ----

    function testWrongWitnessesNeverConsumeTheOrder() public {
        bytes32 id = lock();
        PointEscrowV2.Order memory o = order(ALICE);
        uint256[6] memory bad = [uint256(0), K + 1, K - 1, K + Q, Q - K, Q];
        for (uint256 i; i < bad.length; ++i) {
            vm.expectRevert(PointEscrowV2.InvalidWitness.selector); escrow.claim(id, o, bad[i]);
        }
        require(escrow.orders(id) == (committed(o) | LOCKED));
        escrow.claim(id, o, K);
    }

    function testFuzzClaimOpensExactlyTheLockedPoint(uint256 seed) public {
        uint256 k = 1 + seed % (Q - 1);
        (uint256 x, uint256 y) = mulG(k);
        bytes32 id = lockFor(ALICE, x, y);
        PointEscrowV2.Order memory o = PointEscrowV2.Order(BOB, ALICE, 1 ether, expiry, Pallas.Point(x, y), TERMS);
        if (k + 1 < Q) { vm.expectRevert(PointEscrowV2.InvalidWitness.selector); escrow.claim(id, o, k + 1); }
        vm.expectRevert(PointEscrowV2.InvalidWitness.selector); escrow.claim(id, o, k + Q);
        vm.expectRevert(PointEscrowV2.InvalidWitness.selector); escrow.claim(id, o, Q - k);
        escrow.claim(id, o, k);
        require(escrow.orders(id) == (committed(o) | CLAIMED));
    }

    // ---- credit then withdraw ----

    function testRejectingReceiverCannotBlockClaimAndCanWithdrawElsewhere() public {
        RejectingOwner owner = new RejectingOwner();
        bytes32 id = lockFor(address(owner), KX, KY);
        PointEscrowV2.Order memory o = order(address(owner));
        escrow.claim(id, o, K);
        vm.expectRevert(PointEscrowV2.WithdrawFailed.selector);
        owner.withdraw(escrow, id, o, payable(address(owner)));
        require(escrow.orders(id) == (committed(o) | CLAIMED));
        owner.withdraw(escrow, id, o, payable(ALICE));
        require(ALICE.balance == 1 ether && escrow.orders(id) == (committed(o) | CLAIMED | PAID));
    }

    function testReentrantWithdrawPaysOnce() public {
        ReentrantOwner owner = new ReentrantOwner();
        bytes32 id = lockFor(address(owner), KX, KY);
        PointEscrowV2.Order memory o = order(address(owner));
        vm.deal(address(escrow), address(escrow).balance + 5 ether); // other funds held by the escrow
        escrow.claim(id, o, K);
        owner.withdraw(escrow, id, o);
        require(owner.reentered() == 1 && owner.reentryError() == PointEscrowV2.NothingToWithdraw.selector);
        require(address(owner).balance == 1 ether && address(escrow).balance == 5 ether);
    }

    // ---- lock validation and domain separation ----

    function testLockValidation() public {
        vm.prank(BOB); vm.expectRevert(PointEscrowV2.InvalidPoint.selector);
        escrow.lock{value: 1 ether}(SALT, ALICE, expiry, Pallas.Point(0, 0), TERMS);
        vm.prank(BOB); vm.expectRevert(PointEscrowV2.InvalidPoint.selector);
        escrow.lock{value: 1 ether}(SALT, ALICE, expiry, Pallas.Point(KX + P, KY), TERMS);
        vm.prank(BOB); vm.expectRevert(PointEscrowV2.InvalidOrder.selector);
        escrow.lock{value: 1 ether}(SALT, address(0), expiry, Pallas.Point(KX, KY), TERMS);
        vm.prank(BOB); vm.expectRevert(PointEscrowV2.InvalidOrder.selector);
        escrow.lock{value: 0}(SALT, ALICE, expiry, Pallas.Point(KX, KY), TERMS);
        vm.prank(BOB); vm.expectRevert(PointEscrowV2.InvalidOrder.selector);
        escrow.lock{value: 1 ether}(SALT, ALICE, expiry, Pallas.Point(KX, KY), bytes32(0));
        vm.prank(BOB); vm.expectRevert(PointEscrowV2.InvalidOrder.selector);
        escrow.lock{value: 1 ether}(SALT, ALICE, uint64(block.timestamp + 299), Pallas.Point(KX, KY), TERMS);
        lock();
        vm.prank(BOB); vm.expectRevert(PointEscrowV2.OrderExists.selector);
        escrow.lock{value: 1 ether}(SALT, RELAYER, expiry, Pallas.Point(KX, KY), bytes32(uint256(1)));
    }

    function testOrderIdDomainSeparation() public {
        bytes32 id = escrow.orderId(BOB, SALT);
        require(id != escrow.orderId(RELAYER, SALT) && id != escrow.orderId(BOB, bytes32(uint256(8))));
        require(id != (new PointEscrowV2()).orderId(BOB, SALT));
        vm.chainId(block.chainid + 1);
        require(id != escrow.orderId(BOB, SALT));
    }

    // ---- gas ----

    function testGasClaimWorstCase() public {
        uint256 k = (1 << 254) - 1;
        (uint256 x, uint256 y) = mulG(k);
        bytes32 id = lockFor(ALICE, x, y);
        PointEscrowV2.Order memory o = PointEscrowV2.Order(BOB, ALICE, 1 ether, expiry, Pallas.Point(x, y), TERMS);
        uint256 g = gasleft();
        escrow.claim(id, o, k);
        emit log_named_uint("claim 2^254-1 (call frame, warm escrow)", g - gasleft());
    }
}
