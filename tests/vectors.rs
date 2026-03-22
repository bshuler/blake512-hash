// Test vectors validated against the sphlib C reference implementation.

use blake512_hash::{Blake512, Digest};
use hex_literal::hex;

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

#[test]
fn exactly_one_block() {
    // 128 bytes (one full block, padding goes to second block).
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
fn just_over_one_block() {
    // 129 bytes (one full block + 1 byte partial).
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
fn reset() {
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
fn different_inputs() {
    let h1 = Blake512::digest(b"input one");
    let h2 = Blake512::digest(b"input two");
    assert_ne!(h1, h2);
}

#[test]
fn padding_boundary_111_bytes() {
    // 111 bytes: bit_len = 888 <= 894, single padding block.
    // The 0x80 start-bit lands at buf[111] — same position as the 0x01 marker.
    // The correct byte at position 111 is 0x81 (0x80 | 0x01).
    // Verified against sphlib C reference.
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
fn padding_boundary_112_bytes() {
    // 112 bytes: bit_len = 896 > 894, so padding needs two blocks.
    // Verified against sphlib C reference.
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
fn large_input() {
    // 10000 bytes exercises multiple block compressions.
    let data = [0xFFu8; 10000];
    let hash = Blake512::digest(data);
    assert_eq!(hash.len(), 64);
    assert_ne!(&hash[..], &[0u8; 64][..]);
}

#[test]
fn clone_and_continue() {
    let data = b"The quick brown fox jumps over the lazy dog";

    let mut hasher = Blake512::new();
    Digest::update(&mut hasher, &data[..20]);

    // Clone the state, then continue both independently.
    let mut cloned = hasher.clone();

    Digest::update(&mut hasher, &data[20..]);
    Digest::update(&mut cloned, &data[20..]);

    let h1 = hasher.finalize();
    let h2 = cloned.finalize();
    assert_eq!(h1, h2);
}
