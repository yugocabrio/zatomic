// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {Pallas} from "../src/Pallas.sol";

/// @notice BENCHMARK ONLY, not deployed. Same predicate as Pallas.opens:
/// 0 < scalar < Q, T on curve with canonical coordinates, and scalar*G == T for
/// the RedPallas SpendAuth base G. Fixed-base comb (Lim-Lee, one table): with t
/// teeth and spacing d = ceil(255/t), column j of the scalar selects
/// idx = sum_i bit(j + d*i) << i, and the loop is d-1 doublings plus up to d mixed
/// additions of table[idx] = sum_{bits i of idx} 2^(d*i) G, read with EXTCODECOPY
/// from a PallasCombTable* data contract. Variable-time on PUBLIC input only.
/// Doubling: dbl-2009-l with D = (2X)(2Y^2); addition: madd-2007-bl with
/// Z3 = 2*Z1*H (EFD, a = 0). Values below 2^256 are fed to mulmod unreduced.
/// For 0 < scalar < Q the H == 0 branch is unreachable (docs/gas-optimization.md);
/// it is still handled exactly (double, or infinity).
library PallasFast {
    struct Comb {
        address table;
        uint256 teeth;
        uint256 spacing;
        uint256 mask;
        uint256 magic;
        uint256 shift;
    }

    /// Bit-gather constants for t teeth: ((scalar >> j) & mask) * magic >> shift
    /// puts bit j + d*i at position i (no carry reaches the target bits for t < d).
    function comb(address table, uint256 teeth) internal pure returns (Comb memory c) {
        require(teeth >= 4 && teeth <= 8);
        uint256 d = (255 + teeth - 1) / teeth;
        uint256 shift = (d - 1) * (teeth - 1);
        uint256 mask;
        uint256 magic;
        for (uint256 i; i < teeth; ++i) {
            mask |= uint256(1) << (d * i);
            magic |= uint256(1) << (shift - (d - 1) * i);
        }
        c = Comb(table, teeth, d, mask, magic, shift);
    }

    function opens(uint256 scalar, Pallas.Point memory t, Comb memory c) internal view returns (bool) {
        return opensWith(scalar, t.x, t.y, c.table, (uint256(1) << c.teeth) - 1, c.spacing, c.mask, c.magic, c.shift);
    }

    function opensWith(uint256 scalar, uint256 tx_, uint256 ty, address table, uint256 top, uint256 spacing,
        uint256 mask, uint256 magic, uint256 shift) private view returns (bool ok)
    {
        assembly ("memory-safe") {
            function dbl(x, y, z) -> x3, y3, z3 {
                let p := 0x40000000000000000000000000000000224698fc094cf91b992d30ed00000001
                let b := mulmod(y, y, p)
                let d := mulmod(add(x, x), add(b, b), p)            // 4 X Y^2
                let e := mul(3, mulmod(x, x, p))                     // 3 X^2 < 3p < 2^256
                x3 := addmod(mulmod(e, e, p), sub(add(p, p), add(d, d)), p)
                let c8 := mulmod(add(b, b), add(b, b), p)            // 4 Y^4
                c8 := addmod(c8, c8, p)                              // 8 Y^4
                y3 := addmod(mulmod(e, add(d, sub(p, x3)), p), sub(p, c8), p)
                z3 := mulmod(add(y, y), z, p)                        // Z3 = 0 encodes infinity
            }
            function madd(x1, y1, z1, x2, y2) -> x3, y3, z3 {
                let p := 0x40000000000000000000000000000000224698fc094cf91b992d30ed00000001
                let zz := mulmod(z1, z1, p)
                let h := addmod(mulmod(x2, zz, p), sub(p, x1), p)
                let r := addmod(mulmod(y2, mulmod(z1, zz, p), p), sub(p, y1), p)
                if iszero(h) {
                    if iszero(r) { x3, y3, z3 := dbl(x1, y1, z1) }
                    leave                                            // opposite points: infinity
                }
                let i := mulmod(add(h, h), add(h, h), p)             // 4 H^2
                let j := mulmod(h, i, p)
                let v := mulmod(x1, i, p)
                r := add(r, r)                                       // 2 (S2 - Y1) < 2p
                // 3p - (J + 2V) > 0 since J + 2V < 3p.
                x3 := addmod(mulmod(r, r, p),
                    sub(0xc000000000000000000000000000000066d3caf41be6eb52cb8792c700000003, add(j, add(v, v))), p)
                y3 := addmod(mulmod(r, add(v, sub(p, x3)), p), sub(p, mulmod(add(y1, y1), j, p)), p)
                z3 := mulmod(add(z1, z1), h, p)
            }
            let p := 0x40000000000000000000000000000000224698fc094cf91b992d30ed00000001
            for {} 1 {} {
                if or(iszero(scalar), iszero(lt(scalar, 0x40000000000000000000000000000000224698fc0994a8dd8c46eb2100000001))) { break }
                if or(iszero(lt(tx_, p)), iszero(lt(ty, p))) { break }
                if iszero(eq(mulmod(ty, ty, p), addmod(mulmod(mulmod(tx_, tx_, p), tx_, p), 5, p))) { break }
                let x := 0
                let y := 0
                let z := 0
                for { let j := spacing } j {} {
                    j := sub(j, 1)
                    if z { x, y, z := dbl(x, y, z) }
                    let idx := and(shr(shift, mul(and(shr(j, scalar), mask), magic)), top)
                    if idx {
                        extcodecopy(table, 0, sub(shl(6, idx), 63), 0x40)
                        switch z
                        case 0 { x := mload(0) y := mload(0x20) z := 1 }
                        default { x, y, z := madd(x, y, z, mload(0), mload(0x20)) }
                    }
                }
                if iszero(z) { break }
                let zz := mulmod(z, z, p)
                ok := and(eq(x, mulmod(tx_, zz, p)), eq(y, mulmod(ty, mulmod(zz, z, p), p)))
                break
            }
        }
    }
}
