// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;
import {Pallas} from "../src/Pallas.sol";

/// Independent reference for tests: affine double-and-add on Pallas with
/// modexp inversion. Shares no code with Pallas.sol or PallasComb.sol.
abstract contract PallasOracle {
    uint256 constant P = Pallas.P;
    uint256 constant Q = Pallas.Q;

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

}
