# blake512-hash

[![Crates.io](https://img.shields.io/crates/v/blake512-hash.svg)](https://crates.io/crates/blake512-hash)
[![Documentation](https://docs.rs/blake512-hash/badge.svg)](https://docs.rs/blake512-hash)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Build Status](https://github.com/bshuler/blake512-hash/actions/workflows/ci.yml/badge.svg)](https://github.com/bshuler/blake512-hash/actions)
[![no_std](https://img.shields.io/badge/no__std-compatible-green.svg)](https://docs.rs/blake512-hash)

Pure Rust implementation of the **BLAKE-512** cryptographic hash function.

BLAKE was one of the five finalists in the [NIST SHA-3 competition](https://en.wikipedia.org/wiki/NIST_hash_function_competition). This is the *original* BLAKE algorithm -- **not** [BLAKE2](https://www.blake2.net/) or [BLAKE3](https://github.com/BLAKE3-team/BLAKE3). BLAKE-512 is used in the [Quark](https://en.wikipedia.org/wiki/Quark_(hash_function)) hash chain found in Divi, PIVX, and other cryptocurrencies.

## Features

- **Pure Rust** -- no C dependencies, no FFI, no `unsafe` code
- **`no_std` compatible** -- works in embedded and WASM environments
- **RustCrypto ecosystem** -- implements the [`digest::Digest`](https://docs.rs/digest/0.10) trait (v0.10)
- **Verified** -- 13 test vectors validated against the [sphlib](https://github.com/aidansteele/sphlib) C reference implementation

## Usage

Add to your `Cargo.toml`:

```toml
[dependencies]
blake512-hash = "0.1"
```

### One-shot hashing

```rust
use blake512_hash::{Blake512, Digest};

let hash = Blake512::digest(b"Hello, World!");
println!("{:x}", hash);
```

### Incremental hashing

```rust
use blake512_hash::{Blake512, Digest};

let mut hasher = Blake512::new();
hasher.update(b"Hello, ");
hasher.update(b"World!");
let hash = hasher.finalize();
```

### In a Quark hash chain

```rust
use blake512_hash::Blake512;
use bmw_hash::Bmw512;
use groestl::Groestl512;
use jh::Jh512;
use sha3::Keccak512;
use skein::Skein512;
use digest::{Digest, consts::U64};

fn quark_step(data: &[u8]) -> Vec<u8> {
    let h = Blake512::digest(data);
    let h = Bmw512::digest(&h);
    let h = Groestl512::digest(&h);
    // ... (full Quark chain has 9 rounds with conditional branching)
    h.to_vec()
}
```

## Algorithm

BLAKE-512 operates on 128-byte message blocks using 16 rounds of the G mixing function over a 16-word working vector. It uses the Merkle-Damgard construction with a HAIFA counter for length padding.

Key parameters:
- **Output size**: 512 bits (64 bytes)
- **Block size**: 128 bytes
- **Rounds**: 16
- **Word size**: 64 bits

This implementation is a direct port of the `blake64` functions from [sphlib](https://github.com/aidansteele/sphlib/blob/master/c/blake.c) (MIT license, Thomas Pornin / Projet RNRT SAPHIR).

## Test Vectors

All test vectors are validated against the sphlib C reference implementation:

| Input | BLAKE-512 (first 32 hex chars) |
|-------|-------------------------------|
| `""` (empty) | `a8cfbbd73726062df0c6864dda65defe...` |
| `"\x00"` | `97961587f6d970faba6d2478045de6d1...` |
| `"abc"` | `14266c7c704a3b58fb421ee69fd005fc...` |
| 80 zero bytes | `13cee4afd536f7ed6aa3f7fc90e00050...` |
| 128 x `0x41` | `ab691f6ae2543e81bf3276c7ea463212...` |
| 129 x `0x42` | `f643396476f2436066dec3e9c505eb74...` |

## Reference

- [BLAKE specification](https://131002.net/blake/) (original submission site)
- [sphlib C implementation](https://github.com/aidansteele/sphlib) by Thomas Pornin
- [NIST SHA-3 competition](https://csrc.nist.gov/projects/hash-functions/sha-3-project)

## License

[MIT](LICENSE)
