// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

/// @notice Public-witness verification for the exact RedPallas SpendAuth base.
/// @dev Unreviewed implementation. Variable-time arithmetic handles PUBLIC input.
/// Jacobian a=0 doubling and mixed addition: EFD dbl-2009-l / madd-2007-bl.
/// https://www.hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-0.html
library Pallas {
    uint256 internal constant P = 0x40000000000000000000000000000000224698fc094cf91b992d30ed00000001;
    uint256 internal constant Q = 0x40000000000000000000000000000000224698fc0994a8dd8c46eb2100000001;
    uint256 internal constant GX = 0x375523b328f1d6063b8d187c3e5f445f0c7f0ce37b70a10c8d1a7284b875c963;
    uint256 internal constant GY = 0x1ad0357fdf1a66db7b10bcfcfed624fbdfc914fec005bdd84ce33e817b0c3bc9;

    struct Point { uint256 x; uint256 y; }
    struct Jacobian { uint256 x; uint256 y; uint256 z; }

    function onCurve(Point memory t) internal pure returns (bool) {
        return t.x < P && t.y < P
            && mulmod(t.y, t.y, P) == addmod(mulmod(mulmod(t.x, t.x, P), t.x, P), 5, P);
    }

    function opens(uint256 scalar, Point memory t) internal pure returns (bool) {
        if (scalar == 0 || scalar >= Q || !onCurve(t)) return false;
        Jacobian memory r;
        // MSB-first; nonzero scalar is at most 255 bits. No modular alias accepted.
        for (uint256 bit = 255; bit > 0;) {
            unchecked { --bit; }
            r = twice(r);
            if ((scalar >> bit) & 1 == 1) r = addGenerator(r);
        }
        if (r.z == 0) return false;
        uint256 z2 = mulmod(r.z, r.z, P);
        return r.x == mulmod(t.x, z2, P) && r.y == mulmod(t.y, mulmod(z2, r.z, P), P);
    }

    function sub(uint256 a, uint256 b) private pure returns (uint256) {
        return addmod(a, P - b, P);
    }

    function twice(Jacobian memory p) private pure returns (Jacobian memory r) {
        if (p.z == 0 || p.y == 0) return r;
        uint256 a = mulmod(p.x, p.x, P);
        uint256 b = mulmod(p.y, p.y, P);
        uint256 c = mulmod(b, b, P);
        uint256 d = mulmod(2, sub(sub(mulmod(addmod(p.x, b, P), addmod(p.x, b, P), P), a), c), P);
        uint256 e = mulmod(3, a, P);
        r.x = sub(mulmod(e, e, P), mulmod(2, d, P));
        r.y = sub(mulmod(e, sub(d, r.x), P), mulmod(8, c, P));
        r.z = mulmod(2, mulmod(p.y, p.z, P), P);
    }

    function addGenerator(Jacobian memory p) private pure returns (Jacobian memory r) {
        if (p.z == 0) return Jacobian(GX, GY, 1);
        uint256 z2 = mulmod(p.z, p.z, P);
        uint256 u2 = mulmod(GX, z2, P);
        uint256 s2 = mulmod(GY, mulmod(p.z, z2, P), P);
        if (u2 == p.x) {
            if (s2 == p.y) return twice(p);
            return r;
        }
        uint256 h = sub(u2, p.x);
        uint256 hh = mulmod(h, h, P);
        uint256 i = mulmod(4, hh, P);
        uint256 j = mulmod(h, i, P);
        uint256 rr = mulmod(2, sub(s2, p.y), P);
        uint256 v = mulmod(p.x, i, P);
        r.x = sub(sub(mulmod(rr, rr, P), j), mulmod(2, v, P));
        r.y = sub(mulmod(rr, sub(v, r.x), P), mulmod(2, mulmod(p.y, j, P), P));
        r.z = sub(sub(mulmod(addmod(p.z, h, P), addmod(p.z, h, P), P), z2), hh);
    }
}
