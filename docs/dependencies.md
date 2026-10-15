# Dependencies and attribution

Original Latch code is MIT licensed. No third-party implementation is claimed as
our invention. Cargo.lock and package-lock.json pin the resolved dependencies.
The recorded Rust metadata inventory contains 213 packages with declared license
metadata: `evidence/dependency-licenses.json`. This is an inventory, not legal
advice or a security audit.

| Component | Pin / provenance | Role and license |
|---|---|---|
| librustzcash | `9c5705f56517c040c50f96d29f1ff15a9383f3e0` | Native v6/NU7/PCZT; MIT OR Apache-2.0 |
| orchard | `0.16.0` | Ironwood proofs, notes and keys; MIT OR Apache-2.0 |
| reddsa | `0.6.1` | Current native signature verifier; MIT OR Apache-2.0 |
| reddsa FROST git dependency | `ed49e9ca0699a6450f6d4a9fe62ff168f5ea1ead` | Threshold DKG/signing primitives; MIT OR Apache-2.0 |
| frost-core | `2.2.0` | FROST internals; MIT OR Apache-2.0 |
| pasta_curves | `0.6.0` and `0.5.2` through separate compatibility dependencies | Exact curve arithmetic; MIT OR Apache-2.0 |
| Zebra | official `7.0.0-rc.0` ARM64 release archive | Owned isolated node; MIT OR Apache-2.0 |
| solc-js | `0.8.25` | Pinned npm solc-js package declares MIT; build tool only |
| Foundry | tested `1.3.1` | Local EVM/contract tools; MIT OR Apache-2.0 |

The modified adaptor construction is **our unaudited extension**. Upstream
FROST's guarantees do not automatically cover it. The EVM Pallas implementation
uses standard Jacobian formulas, cross-checked against Rust curve vectors; see
protocol references and the contract tests.

The Zebra archive is SHA-256 checked before extraction. Its original
`LICENSE-APACHE` and `LICENSE-MIT` are retained alongside the local executable.
The Ubuntu container is digest pinned. These downloaded artifacts are ignored
by Git; reproduction fetches them from the official source. There is no bundled
mainnet wallet, private key or hosted service dependency.

The read-only public testnet probe follows field numbers in the pinned
lightwallet-protocol schemas. It uses Node's built-in TLS/HTTP2, sends no wallet
information and cannot broadcast. Primary schema source:
[lightwallet-protocol](https://github.com/zcash/lightwallet-protocol).

The optional authenticated signer fixture uses Python's standard `ssl` module
and the local OpenSSL executable for disposable P-256 certificates (tested
OpenSSL 3.6.3 / TLS 1.3). It adds no runtime package download or custom TLS
implementation. Default browser operation does not require these certificates.
