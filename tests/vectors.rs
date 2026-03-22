// Comprehensive test suite for blake512-hash.
// All exact hash values verified against the sphlib C reference implementation
// (Thomas Pornin, Projet RNRT SAPHIR, MIT license).

use blake512_hash::{Blake512, Digest};
use hex_literal::hex;

// ==========================================================================
// Section 1: Exact test vectors against sphlib C reference
// ==========================================================================

#[test]
fn empty_message() {
    let hash = Blake512::digest(b"");
    assert_eq!(
        hash[..],
        hex!(
            "a8cfbbd73726062df0c6864dda65defe"
            "58ef0cc52a5625090fa17601e1eecd1b"
            "628e94f396ae402a00acc9eab77b4d4c"
            "2e852aaaa25a636d80af3fc7913ef5b8"
        )
    );
}

#[test]
fn single_zero_byte() {
    let hash = Blake512::digest([0u8]);
    assert_eq!(
        hash[..],
        hex!(
            "97961587f6d970faba6d2478045de6d1"
            "fabd09b61ae50932054d52bc29d31be4"
            "ff9102b9f69e2bbdb83be13d4b9c0609"
            "1e5fa0b48bd081b634058be0ec49beb3"
        )
    );
}

#[test]
fn single_byte_0xff() {
    let hash = Blake512::digest([0xffu8]);
    assert_eq!(
        hash[..],
        hex!(
            "e863881eb834107132be4b3a3af6560b"
            "cc1b64aa55628daf19464c210bb726c0"
            "6bdaf2e7c2a81c58d79696c14eefc4f7"
            "891cbb2afa56635e06f96874cf8cf4e4"
        )
    );
}

#[test]
fn two_bytes() {
    let hash = Blake512::digest([0xabu8; 2]);
    assert_eq!(
        hash[..],
        hex!(
            "48c39990b5e58456559ec9610bbaaa3e"
            "eadd05fe92c27b86127fc451a8a244e1"
            "4d22e699f598d27a0c0bcc981fd68bdc"
            "285bb3d93a498234d206752d097063d0"
        )
    );
}

#[test]
fn abc() {
    let hash = Blake512::digest(b"abc");
    assert_eq!(
        hash[..],
        hex!(
            "14266c7c704a3b58fb421ee69fd005fc"
            "c6eeff742136be67435df995b7c986e7"
            "cbde4dbde135e7689c354d2bc5b8d260"
            "536c554b4f84c118e61efc576fed7cd3"
        )
    );
}

#[test]
fn quick_brown_fox() {
    let hash = Blake512::digest(b"The quick brown fox jumps over the lazy dog");
    assert_eq!(
        hash[..],
        hex!(
            "1f7e26f63b6ad25a0896fd978fd050a1"
            "766391d2fd0471a77afb975e5034b7ad"
            "2d9ccf8dfb47abbbe656e1b82fbc634b"
            "a42ce186e8dc5e1ce09a885d41f43451"
        )
    );
}

#[test]
fn sixty_four_zero_bytes() {
    // Half a block (64 bytes).
    let hash = Blake512::digest([0u8; 64]);
    assert_eq!(
        hash[..],
        hex!(
            "2d5368f488178be0b4bcb37501916049"
            "381cfcf82615de91f121d4a04e572423"
            "dbcac515472da296160947a132cd1668"
            "5e2363b9ec7a63892e2bc3eb3daa16f5"
        )
    );
}

#[test]
fn eighty_zero_bytes() {
    // 80 bytes of zeros (cryptocurrency block header size).
    let hash = Blake512::digest([0u8; 80]);
    assert_eq!(
        hash[..],
        hex!(
            "13cee4afd536f7ed6aa3f7fc90e00050"
            "4bf01dd041a8a3c1f38f0bfa14258308"
            "384b6c5c75d2ab528277de92a0968b66"
            "50fcb80687a4eab0dcd87216bc522dc6"
        )
    );
}

// ==========================================================================
// Section 2: Padding boundary tests (critical correctness paths)
// ==========================================================================

#[test]
fn padding_109_bytes() {
    // 109 bytes: bit_len=872, well within single-block pad.
    let hash = Blake512::digest([0x46u8; 109]);
    assert_eq!(
        hash[..],
        hex!(
            "6d98cfdb873540847824cc3d2edf2e1e"
            "42a4d756a5225575b13e24f1be458575"
            "83f865bf0d2541a1ebc2f82fe21e674d"
            "014a47304b91e0c66bf1e4bba6ff1b09"
        )
    );
}

#[test]
fn padding_110_bytes() {
    // 110 bytes: bit_len=880, last size where zero-fill loop writes to buf[111-1].
    let hash = Blake512::digest([0x47u8; 110]);
    assert_eq!(
        hash[..],
        hex!(
            "60c3233142c749d850e8743c146dec6a"
            "e96e26b07e2b5987107d4b7f25e332b2"
            "d2f20a3d56bc2357eacdce6994357214"
            "2989f0b3cdb7c7accc4af6c23a295925"
        )
    );
}

#[test]
fn padding_111_bytes_critical() {
    // 111 bytes: bit_len=888, the CRITICAL boundary.
    // The 0x80 start-bit lands at buf[111] — same position as the 0x01 marker.
    // The correct byte at position 111 is 0x81 (0x80 | 0x01).
    let hash = Blake512::digest([0x45u8; 111]);
    assert_eq!(
        hash[..],
        hex!(
            "5eea0d830afa642e21c3345dd3f97e44"
            "bc593a8718c639cede015e6f327a321f"
            "7268fd35f8f8a3fc34085c7b2b57ad9f"
            "e705b94941033b3021408f330dbe5ef4"
        )
    );
}

#[test]
fn padding_112_bytes_two_block() {
    // 112 bytes: bit_len=896 > 894, first size that triggers two-block padding.
    let hash = Blake512::digest([0x44u8; 112]);
    assert_eq!(
        hash[..],
        hex!(
            "121ed015f230810f288867bc52fc05a8"
            "14827e28248ec6a247febde4c023f283"
            "868b5970d8b3fda113078784c170329e"
            "81ec352cfa67136d8f28fda06edfb38e"
        )
    );
}

#[test]
fn padding_113_bytes() {
    // 113 bytes: inside the two-block padding region.
    let hash = Blake512::digest([0x48u8; 113]);
    assert_eq!(
        hash[..],
        hex!(
            "1a476273be14b301193dfca2e5d9c97d"
            "893b7804e9078a1bc30b1ba5266e9dc3"
            "c057483137a9e91746f46ba2557299c1"
            "7c87344fa1a308ac343e3712624e422f"
        )
    );
}

#[test]
fn padding_127_bytes() {
    // 127 bytes: maximum size in the two-block padding region before block boundary.
    let hash = Blake512::digest([0x49u8; 127]);
    assert_eq!(
        hash[..],
        hex!(
            "7fba61c9045f5ecee74b68c4c7b80f58"
            "a710f7fde88b99dd19817e327b370fac"
            "882eac7ad58d02e32a18fa4ca699098a"
            "f95a1342c6884722db54765361052837"
        )
    );
}

// ==========================================================================
// Section 3: Block boundary tests (counter and sentinel paths)
// ==========================================================================

#[test]
fn exactly_one_block_128() {
    // 128 bytes: exactly one full block compressed during update.
    // Finalize sees ptr=0, triggering the sentinel counter path.
    let hash = Blake512::digest([0x41u8; 128]);
    assert_eq!(
        hash[..],
        hex!(
            "ab691f6ae2543e81bf3276c7ea463212"
            "cdeff7b00fdc804e6f07965e1e134364"
            "0f60d0e7174438c6d67eb76b900ceb6b"
            "1fed7d9bcf51356cb55e59891ed8fc6a"
        )
    );
}

#[test]
fn exactly_one_block_zeros() {
    // 128 zero bytes — same ptr=0 sentinel path, different data.
    let hash = Blake512::digest([0u8; 128]);
    assert_eq!(
        hash[..],
        hex!(
            "0f6f3a3a91f752d37e3d37141d5459ac"
            "a9a88ed2d5b88f71120fbe39387b635e"
            "cf6402a5bcb7b18f216ea9a8137d2895"
            "4098e586014c4d435c979d8860d3a977"
        )
    );
}

#[test]
fn one_block_plus_one_129() {
    // 129 bytes: one full block compressed, then 1 byte in buffer.
    let hash = Blake512::digest([0x42u8; 129]);
    assert_eq!(
        hash[..],
        hex!(
            "f643396476f2436066dec3e9c505eb74"
            "8fd068f2657b383b4d9f7bf31d97821b"
            "0517cf562923e794f2843109ce8d0603"
            "e7a52ee2f673870b4e82b0b566f78cd7"
        )
    );
}

#[test]
fn two_blocks_256() {
    // 256 bytes: two full blocks compressed.
    let hash = Blake512::digest([0x43u8; 256]);
    assert_eq!(
        hash[..],
        hex!(
            "7b273bb2e25e592e63c725cc2482a4dd"
            "43e1a23b424698a90ec4b47b8b8fbfc0"
            "042d046e2857a9dc0125a91ba679476a"
            "4b998bde26eb9473303b11cbed06ea66"
        )
    );
}

// ==========================================================================
// Section 4: Multi-block padding boundary (second block ptr==111)
// ==========================================================================

#[test]
fn multiblock_239_bytes() {
    // 239 = 128 + 111: after one block compression, ptr=111 in finalize.
    // Tests the critical 0x81 boundary on a multi-block message.
    let hash = Blake512::digest([0x50u8; 239]);
    assert_eq!(
        hash[..],
        hex!(
            "d7cce0e27bed2729d943599ae1896366"
            "d5a38e175af5ca50ddaf543fe3de219f"
            "7f35309bc7ed5b725b77f336e2b09bd0"
            "9a1d71c66ec14aaefa59f2013faccae4"
        )
    );
}

#[test]
fn multiblock_240_bytes() {
    // 240 = 128 + 112: after one block, ptr=112 triggers two-block padding.
    let hash = Blake512::digest([0x51u8; 240]);
    assert_eq!(
        hash[..],
        hex!(
            "2e63fbf9340a34f8082df5ece9905d97"
            "cf4e78efd270b3e43cbf1bf86ce6a6f0"
            "0791337c201eaafdca315588f5508a64"
            "f74d31ffc88d4c227f54b53635c99350"
        )
    );
}

#[test]
fn multiblock_255_bytes() {
    let hash = Blake512::digest([0x52u8; 255]);
    assert_eq!(
        hash[..],
        hex!(
            "b9346f2137e6d0b754192040f549060b"
            "95860615352ce98f97e29fc622e330b2"
            "c5320a87c4a05d8e455e0db72cc8dd19"
            "509d75cafbbddcdec77e42b21f92248b"
        )
    );
}

#[test]
fn multiblock_1000_bytes() {
    let hash = Blake512::digest([0x53u8; 1000]);
    assert_eq!(
        hash[..],
        hex!(
            "e444395b4e1dae055e4717e8557adc72"
            "61816ebea78134e5adc1a9f21218a927"
            "cd0c181e31d9bedc175813821c294ae5"
            "e31c2bd2de9fb7c19f7f08546caaa7ca"
        )
    );
}

// ==========================================================================
// Section 5: Incremental / streaming API tests
// ==========================================================================

#[test]
fn incremental_vs_oneshot() {
    let data = b"The quick brown fox jumps over the lazy dog";

    let oneshot = Blake512::digest(&data[..]);

    let mut hasher = Blake512::new();
    Digest::update(&mut hasher, &data[..10]);
    Digest::update(&mut hasher, &data[10..20]);
    Digest::update(&mut hasher, &data[20..]);
    let incremental = hasher.finalize();

    assert_eq!(oneshot[..], incremental[..]);
}

#[test]
fn byte_by_byte() {
    let data = b"BLAKE-512 test vector for byte-by-byte processing";

    let oneshot = Blake512::digest(&data[..]);

    let mut hasher = Blake512::new();
    for &byte in data.iter() {
        Digest::update(&mut hasher, [byte]);
    }
    let incremental = hasher.finalize();

    assert_eq!(oneshot[..], incremental[..]);
}

#[test]
fn incremental_cross_block_boundary() {
    // Feed data that crosses the 128-byte block boundary in various chunk sizes.
    let data = [0x53u8; 1000];
    let reference = Blake512::digest(data);

    // Chunk size 1 (byte-by-byte)
    let mut h = Blake512::new();
    for &b in data.iter() {
        Digest::update(&mut h, [b]);
    }
    assert_eq!(h.finalize()[..], reference[..]);

    // Chunk size 7 (misaligned with block size)
    let mut h = Blake512::new();
    for chunk in data.chunks(7) {
        Digest::update(&mut h, chunk);
    }
    assert_eq!(h.finalize()[..], reference[..]);

    // Chunk size 64 (half-block)
    let mut h = Blake512::new();
    for chunk in data.chunks(64) {
        Digest::update(&mut h, chunk);
    }
    assert_eq!(h.finalize()[..], reference[..]);

    // Chunk size 127 (one less than block)
    let mut h = Blake512::new();
    for chunk in data.chunks(127) {
        Digest::update(&mut h, chunk);
    }
    assert_eq!(h.finalize()[..], reference[..]);

    // Chunk size 128 (exact block)
    let mut h = Blake512::new();
    for chunk in data.chunks(128) {
        Digest::update(&mut h, chunk);
    }
    assert_eq!(h.finalize()[..], reference[..]);

    // Chunk size 129 (one more than block)
    let mut h = Blake512::new();
    for chunk in data.chunks(129) {
        Digest::update(&mut h, chunk);
    }
    assert_eq!(h.finalize()[..], reference[..]);

    // Chunk size 256 (two blocks)
    let mut h = Blake512::new();
    for chunk in data.chunks(256) {
        Digest::update(&mut h, chunk);
    }
    assert_eq!(h.finalize()[..], reference[..]);
}

#[test]
fn empty_update_is_noop() {
    let data = b"abc";

    let mut h1 = Blake512::new();
    Digest::update(&mut h1, &data[..]);

    let mut h2 = Blake512::new();
    Digest::update(&mut h2, b"");
    Digest::update(&mut h2, &data[..]);
    Digest::update(&mut h2, b"");

    assert_eq!(h1.finalize()[..], h2.finalize()[..]);
}

#[test]
fn update_with_exact_buffer_fill() {
    // Feed exactly 128 bytes in one update (fills buffer and triggers compress).
    let data = [0x41u8; 128];
    let reference = Blake512::digest(data);

    let mut h = Blake512::new();
    Digest::update(&mut h, data);
    assert_eq!(h.finalize()[..], reference[..]);
}

// ==========================================================================
// Section 6: Reset, Clone, Default trait tests
// ==========================================================================

#[test]
fn reset_produces_fresh_state() {
    let data = b"test reset";
    let reference = Blake512::digest(&data[..]);

    let mut hasher = Blake512::new();
    Digest::update(&mut hasher, b"garbage data that should be discarded");
    Digest::reset(&mut hasher);
    Digest::update(&mut hasher, &data[..]);
    let result = hasher.finalize();

    assert_eq!(reference[..], result[..]);
}

#[test]
fn reset_after_finalize_via_new() {
    // Ensure we can reuse after calling new() again.
    let mut hasher = Blake512::new();
    Digest::update(&mut hasher, b"first");
    let _ = hasher.finalize();

    // Create fresh and verify it works
    let mut hasher = Blake512::new();
    Digest::update(&mut hasher, b"abc");
    let result = hasher.finalize();

    assert_eq!(result[..], Blake512::digest(b"abc")[..]);
}

#[test]
fn clone_and_diverge() {
    let mut hasher = Blake512::new();
    Digest::update(&mut hasher, b"shared prefix ");

    let mut clone_a = hasher.clone();
    let mut clone_b = hasher.clone();

    Digest::update(&mut clone_a, b"path A");
    Digest::update(&mut clone_b, b"path B");

    let hash_a = clone_a.finalize();
    let hash_b = clone_b.finalize();

    // Different suffixes must produce different hashes.
    assert_ne!(hash_a, hash_b);

    // Each must match the one-shot result.
    assert_eq!(hash_a[..], Blake512::digest(b"shared prefix path A")[..]);
    assert_eq!(hash_b[..], Blake512::digest(b"shared prefix path B")[..]);
}

#[test]
fn default_matches_new() {
    let from_new = Blake512::new();
    let from_default: Blake512 = Default::default();

    let h1 = Digest::chain_update(from_new, b"test").finalize();
    let h2 = Digest::chain_update(from_default, b"test").finalize();
    assert_eq!(h1, h2);
}

// ==========================================================================
// Section 7: Comprehensive boundary sweep (0..256 bytes)
// ==========================================================================

#[test]
fn boundary_sweep_incremental_consistency() {
    // For every size from 0 to 256, verify that one-shot and incremental
    // (byte-by-byte) produce the same hash. This exercises all padding paths.
    for size in 0..=256 {
        let data: Vec<u8> = (0..size).map(|i| (i & 0xFF) as u8).collect();
        let oneshot = Blake512::digest(&data);

        let mut hasher = Blake512::new();
        for &b in &data {
            Digest::update(&mut hasher, [b]);
        }
        let incremental = hasher.finalize();

        assert_eq!(
            oneshot[..],
            incremental[..],
            "Mismatch at size={size}: one-shot vs byte-by-byte"
        );
    }
}

// ==========================================================================
// Section 8: Output properties
// ==========================================================================

#[test]
fn output_is_64_bytes() {
    assert_eq!(Blake512::digest(b"").len(), 64);
    assert_eq!(Blake512::digest(b"x").len(), 64);
    assert_eq!(Blake512::digest([0u8; 1000]).len(), 64);
}

#[test]
fn different_inputs_different_hashes() {
    let h1 = Blake512::digest(b"input one");
    let h2 = Blake512::digest(b"input two");
    assert_ne!(h1, h2);
}

#[test]
fn deterministic() {
    let data = b"determinism check";
    let h1 = Blake512::digest(&data[..]);
    let h2 = Blake512::digest(&data[..]);
    assert_eq!(h1, h2);
}

#[test]
fn no_trivial_collisions_small_inputs() {
    // Verify that all single-byte inputs produce unique hashes.
    let mut hashes: Vec<[u8; 64]> = Vec::new();
    for b in 0..=255u8 {
        let h = Blake512::digest([b]);
        let arr: [u8; 64] = h.into();
        assert!(
            !hashes.contains(&arr),
            "Collision found for single byte {b:#04x}"
        );
        hashes.push(arr);
    }
}

// ==========================================================================
// Section 9: Large / stress inputs
// ==========================================================================

// ==========================================================================
// Section 9a: NIST submission test vectors
// ==========================================================================

#[test]
fn nist_vector_72_bytes() {
    // From the BLAKE NIST SHA-3 submission: 72 sequential bytes (0x00..0x47).
    let data: Vec<u8> = (0u8..72).collect();
    let hash = Blake512::digest(&data);
    assert_eq!(
        hash[..],
        hex!(
            "180cefaba3f6408d6dc8576fbb24ab90"
            "058b9b6abf8f6cdb5a37edbc4a061623"
            "11ea8ebbac8faa40612522a08a565071"
            "71a6f86864a11ee4f17f2e9caf9ab0a0"
        )
    );
}

#[test]
fn nist_vector_144_bytes() {
    // From the BLAKE NIST SHA-3 submission: 144 sequential bytes (0x00..0x8F).
    // Crosses the 128-byte block boundary.
    let data: Vec<u8> = (0u8..144).collect();
    let hash = Blake512::digest(&data);
    assert_eq!(
        hash[..],
        hex!(
            "222b2ea94aa00b81582757382164bcf6"
            "1570744e38421a3086ea0a40e6411c44"
            "f09dad7bb4c6773ba2b05e5f90cb8564"
            "8478db57a5fdba03c01cff22e3d84e7a"
        )
    );
}

// ==========================================================================
// Section 9b: Trait API tests
// ==========================================================================

#[test]
fn output_size_user_returns_64() {
    use digest::OutputSizeUser;
    assert_eq!(<Blake512 as OutputSizeUser>::output_size(), 64);
}

#[test]
fn finalize_into_direct() {
    use digest::generic_array::GenericArray;

    let mut hasher = Blake512::new();
    Digest::update(&mut hasher, b"abc");
    let mut out = GenericArray::default();
    digest::FixedOutput::finalize_into(hasher, &mut out);

    assert_eq!(
        out[..],
        hex!(
            "14266c7c704a3b58fb421ee69fd005fc"
            "c6eeff742136be67435df995b7c986e7"
            "cbde4dbde135e7689c354d2bc5b8d260"
            "536c554b4f84c118e61efc576fed7cd3"
        )
    );
}

#[test]
fn hash_marker_compiles() {
    // Verify Blake512 satisfies the full Digest trait bound (which requires HashMarker).
    fn requires_digest<H: Digest>(data: &[u8]) -> Vec<u8> {
        H::digest(data).to_vec()
    }
    let result = requires_digest::<Blake512>(b"abc");
    assert_eq!(result.len(), 64);
}

// ==========================================================================
// Section 9c: Large / stress inputs
// ==========================================================================

#[test]
fn large_input_10000_bytes() {
    // 10000 x 0xFF — exercises 78 block compressions.
    // Verified against sphlib C reference.
    let data = [0xFFu8; 10000];
    let hash = Blake512::digest(data);
    assert_eq!(
        hash[..],
        hex!(
            "c0feced3710b093be08337e831205fc8"
            "caf82dcdd3d5650a75c19d1c6b0183f7"
            "c381c52d87299366c85f4c30592a2307"
            "f7f969b4682dd0d8b27012813186c108"
        )
    );
}

#[test]
fn large_input_incremental_consistency() {
    // 100KB input: verify one-shot matches incremental with 4KB chunks.
    let data = vec![0xABu8; 100_000];
    let oneshot = Blake512::digest(&data);

    let mut hasher = Blake512::new();
    for chunk in data.chunks(4096) {
        Digest::update(&mut hasher, chunk);
    }
    let incremental = hasher.finalize();

    assert_eq!(oneshot[..], incremental[..]);
}
