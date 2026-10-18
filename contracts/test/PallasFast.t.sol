// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;
import {Pallas} from "../src/Pallas.sol";
import {PallasFast} from "../bench/PallasFast.sol";
import {PallasCombTables} from "../bench/PallasCombTables.sol";

interface Vm {
    function deployCode(string calldata artifactPath) external returns (address);
}

/// External entry points so `forge test --gas-report` lists both predicates.
contract PallasBenchHarness {
    address immutable table8;
    constructor(address table) { table8 = table; }
    function opensRef(uint256 k, uint256 x, uint256 y) external pure returns (bool) {
        return Pallas.opens(k, Pallas.Point(x, y));
    }
    function fast8(uint256 k, uint256 x, uint256 y) external view returns (bool) {
        return PallasFast.opens(k, Pallas.Point(x, y), PallasFast.comb(table8, 8));
    }
}

/// BENCHMARK ONLY. PallasFast (comb widths 4..8) must accept and reject exactly
/// what Pallas.opens does. Expected points come from a third, independent
/// affine double-and-add with modexp inversion.
contract PallasFastTest {
    Vm constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));
    uint256 constant P = Pallas.P;
    uint256 constant Q = Pallas.Q;
    address[9] tables;

    event log_named_uint(string key, uint256 val);

    function setUp() public {
        tables[4] = vm.deployCode("PallasCombTables.sol:PallasCombTable4");
        tables[5] = vm.deployCode("PallasCombTables.sol:PallasCombTable5");
        tables[6] = vm.deployCode("PallasCombTables.sol:PallasCombTable6");
        tables[7] = vm.deployCode("PallasCombTables.sol:PallasCombTable7");
        tables[8] = vm.deployCode("PallasCombTables.sol:PallasCombTable8");
        require(tables[4].codehash == PallasCombTables.CODEHASH_4 && tables[4].code.length == PallasCombTables.SIZE_4);
        require(tables[5].codehash == PallasCombTables.CODEHASH_5 && tables[5].code.length == PallasCombTables.SIZE_5);
        require(tables[6].codehash == PallasCombTables.CODEHASH_6 && tables[6].code.length == PallasCombTables.SIZE_6);
        require(tables[7].codehash == PallasCombTables.CODEHASH_7 && tables[7].code.length == PallasCombTables.SIZE_7);
        require(tables[8].codehash == PallasCombTables.CODEHASH_8 && tables[8].code.length == PallasCombTables.SIZE_8);
    }

    // ---- independent affine reference ----

    function inv(uint256 a) internal view returns (uint256 r) {
        require(a % P != 0);
        uint256 p = P;
        assembly {
            let m := mload(0x40)
            mstore(m, 0x20) mstore(add(m, 0x20), 0x20) mstore(add(m, 0x40), 0x20)
            mstore(add(m, 0x60), a) mstore(add(m, 0x80), sub(p, 2)) mstore(add(m, 0xa0), p)
            if iszero(staticcall(gas(), 5, m, 0xc0, m, 0x20)) { revert(0, 0) }
            r := mload(m)
        }
    }

    function affineDouble(uint256 x, uint256 y) internal view returns (uint256, uint256, bool) {
        if (y == 0) return (0, 0, true);
        uint256 m = mulmod(mulmod(3, mulmod(x, x, P), P), inv(addmod(y, y, P)), P);
        uint256 x3 = addmod(mulmod(m, m, P), P - addmod(x, x, P), P);
        return (x3, addmod(mulmod(m, addmod(x, P - x3, P), P), P - y, P), false);
    }

    function affineAdd(uint256 x1, uint256 y1, uint256 x2, uint256 y2) internal view returns (uint256, uint256, bool) {
        if (x1 == x2) return y1 == y2 ? affineDouble(x1, y1) : (0, 0, true);
        uint256 m = mulmod(addmod(y2, P - y1, P), inv(addmod(x2, P - x1, P)), P);
        uint256 x3 = addmod(addmod(mulmod(m, m, P), P - x1, P), P - x2, P);
        return (x3, addmod(mulmod(m, addmod(x1, P - x3, P), P), P - y1, P), false);
    }

    function mulG(uint256 k) internal view returns (uint256 x, uint256 y) {
        bool inf = true;
        for (uint256 bit = 256; bit > 0;) {
            --bit;
            if (!inf) (x, y, inf) = affineDouble(x, y);
            if ((k >> bit) & 1 == 1) {
                if (inf) (x, y, inf) = (Pallas.GX, Pallas.GY, false);
                else (x, y, inf) = affineAdd(x, y, Pallas.GX, Pallas.GY);
            }
        }
        require(!inf && x < P && y < P && mulmod(y, y, P) == addmod(mulmod(mulmod(x, x, P), x, P), 5, P));
    }

    // ---- agreement ----

    /// Returns the common verdict; reverts if any comb width disagrees with Pallas.opens.
    function agree(uint256 k, uint256 x, uint256 y) internal view returns (bool r) {
        r = Pallas.opens(k, Pallas.Point(x, y));
        for (uint256 t = 4; t <= 8; ++t) {
            require(PallasFast.opens(k, Pallas.Point(x, y), PallasFast.comb(tables[t], t)) == r, "disagree");
        }
    }

    /// k*G == T is accepted; every mutation of scalar, point or encoding is rejected.
    function checkScalar(uint256 k) internal view {
        (uint256 x, uint256 y) = mulG(k);
        require(agree(k, x, y), "valid opening rejected");
        require(!agree(k, x, P - y), "negated point accepted");
        require(!agree(k, x ^ 1, y), "x mutation accepted");
        require(!agree(k, x, y ^ 1), "y mutation accepted");
        require(!agree(k + 1, x, y), "k+1 accepted");
        require(!agree(k - 1, x, y), "k-1 accepted");
        require(!agree(Q - k, x, y), "Q-k accepted");
        require(!agree(k + Q, x, y), "scalar alias accepted");
        require(!agree(k, x + P, y), "x alias accepted");
        require(!agree(k, x, y + P), "y alias accepted");
    }

    function testEveryTableEntryIsTheIntendedMultiple() public view {
        for (uint256 t = 4; t <= 8; ++t) {
            uint256 d = (255 + t - 1) / t;
            PallasFast.Comb memory c = PallasFast.comb(tables[t], t);
            for (uint256 idx = 1; idx < uint256(1) << t; ++idx) {
                uint256 s;
                for (uint256 i; i < t; ++i) if ((idx >> i) & 1 == 1) s |= uint256(1) << (d * i);
                uint256 x;
                uint256 y;
                address table = tables[t];
                assembly {
                    extcodecopy(table, 0, sub(shl(6, idx), 63), 0x40)
                    x := mload(0)
                    y := mload(0x20)
                }
                require(Pallas.opens(s, Pallas.Point(x, y)), "table entry");
                require(PallasFast.opens(s, Pallas.Point(x, y), c), "fast table entry");
            }
        }
    }

    function testEdgeScalars() public view {
        uint256[24] memory small = [uint256(1), 2, 3, 4, 5, 7, 8, 15, 16, 255, 256, 257,
            0xffffffff, 1 << 32, (1 << 32) + 1, (1 << 64) - 1, 1 << 64, (1 << 128) - 1, 1 << 128,
            (1 << 200) - 1, (1 << 224) | 1, (Q - 1) / 2, (Q + 1) / 2, 0x8000000000000000];
        for (uint256 i; i < small.length; ++i) checkScalar(small[i]);
        uint256[10] memory high = [Q - 1, Q - 2, Q - 3, (1 << 254) - 1, 1 << 254, (1 << 254) + 1,
            1 << 253, (1 << 253) - 1, (1 << 252) + (1 << 251), Q - (1 << 128)];
        for (uint256 i; i < high.length; ++i) checkScalar(high[i]);
    }

    /// Powers of two at and around every comb column boundary d*i, for each width.
    function testColumnBoundaries() public view {
        uint8[5] memory spacing = [64, 51, 43, 37, 32];
        for (uint256 w; w < spacing.length; ++w) {
            for (uint256 bit = spacing[w]; bit < 255; bit += spacing[w]) {
                checkScalar(uint256(1) << bit);
                checkScalar((uint256(1) << bit) - 1);
                checkScalar((uint256(1) << bit) + 1);
            }
        }
    }

    function testRejectsWhatOpensRejects() public view {
        uint256[6] memory badScalars = [uint256(0), Q, Q + 1, 1 << 255, type(uint256).max, Q + Q - 1];
        for (uint256 i; i < badScalars.length; ++i) {
            require(!agree(badScalars[i], Pallas.GX, Pallas.GY));
        }
        require(!agree(1, 0, 0));
        require(!agree(1, 0, 1));
        require(!agree(1, P, Pallas.GY));
        require(!agree(1, Pallas.GX, P - Pallas.GY));
        require(!agree(1, type(uint256).max, type(uint256).max));
        require(agree(1, Pallas.GX, Pallas.GY));
        require(agree(Q - 1, Pallas.GX, P - Pallas.GY));
    }

    function testFuzzAcceptsExactly(uint256 seed) public view {
        checkScalar(1 + seed % (Q - 1));
    }

    function testFuzzWrongPoint(uint256 a, uint256 b) public view {
        uint256 ka = 1 + a % (Q - 1);
        uint256 kb = 1 + b % (Q - 1);
        (uint256 x, uint256 y) = mulG(kb);
        require(agree(ka, x, y) == (ka == kb));
        require(agree(kb, x, y));
    }

    function testFuzzArbitraryInputs(uint256 k, uint256 x, uint256 y) public view {
        agree(k, x, y);
        agree(k, x % P, y % P);
    }

    // ---- gas ----

    function measure(string memory label, uint256 k) internal {
        (uint256 x, uint256 y) = mulG(k);
        Pallas.Point memory point = Pallas.Point(x, y);
        uint256 g = gasleft();
        bool ok = Pallas.opens(k, point);
        g -= gasleft();
        require(ok);
        emit log_named_uint(string.concat(label, " Pallas.opens"), g);
        for (uint256 t = 4; t <= 8; ++t) {
            PallasFast.Comb memory c = PallasFast.comb(tables[t], t);
            g = gasleft();
            ok = PallasFast.opens(k, point, c);
            g -= gasleft();
            require(ok);
            emit log_named_uint(string.concat(label, " PallasFast t=", string(abi.encodePacked(bytes1(uint8(48 + t))))), g);
        }
    }

    /// Run with -vv. Same-transaction gasleft() deltas around the internal call.
    function testGasVerification() public {
        measure("k=1", 1);
        measure("k=2^254-1", (1 << 254) - 1);
        measure("k=Q-1", Q - 1);
        measure("k=random1", uint256(keccak256("random scalar 1")) % (Q - 1) + 1);
        measure("k=random2", uint256(keccak256("random scalar 2")) % (Q - 1) + 1);
        measure("k=random3", uint256(keccak256("random scalar 3")) % (Q - 1) + 1);
    }

    /// External calls, reported by `forge test --gas-report` (PallasBenchHarness).
    function testGasHarness() public {
        PallasBenchHarness h = new PallasBenchHarness(tables[8]);
        uint256[4] memory ks = [(1 << 254) - 1, uint256(keccak256("random scalar 1")) % (Q - 1) + 1,
            uint256(keccak256("random scalar 2")) % (Q - 1) + 1, uint256(keccak256("random scalar 3")) % (Q - 1) + 1];
        for (uint256 i; i < ks.length; ++i) {
            (uint256 x, uint256 y) = mulG(ks[i]);
            require(h.opensRef(ks[i], x, y) && h.fast8(ks[i], x, y));
        }
    }
}
