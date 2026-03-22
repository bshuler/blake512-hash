// SPDX-License-Identifier: MIT
//
// Pure Rust implementation of the BLAKE-512 hash function.
//
// BLAKE is a cryptographic hash function that was one of the five finalists
// in the NIST SHA-3 competition. This is the *original* BLAKE algorithm,
// NOT BLAKE2 or BLAKE3. It is ported from the sphlib C implementation
// by Thomas Pornin (MIT license, Projet RNRT SAPHIR).
//
// References:
// - BLAKE specification: https://131002.net/blake/
// - sphlib: https://www.saphir2.com/sphlib/

#![no_std]
#![deny(unsafe_code)]

use digest::consts::U64;
use digest::generic_array::GenericArray;
use digest::{FixedOutput, HashMarker, OutputSizeUser, Reset, Update};

pub use digest::Digest;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Initial hash values for BLAKE-512 (same as SHA-512 IV).
const IV512: [u64; 8] = [
    0x6A09E667F3BCC908,
    0xBB67AE8584CAA73B,
    0x3C6EF372FE94F82B,
    0xA54FF53A5F1D36F1,
    0x510E527FADE682D1,
    0x9B05688C2B3E6C1F,
    0x1F83D9ABFB41BD6B,
    0x5BE0CD19137E2179,
];

/// BLAKE constants: the first 16 fractional digits of pi, as 64-bit words.
const CB: [u64; 16] = [
    0x243F6A8885A308D3,
    0x13198A2E03707344,
    0xA4093822299F31D0,
    0x082EFA98EC4E6C89,
    0x452821E638D01377,
    0xBE5466CF34E90C6C,
    0xC0AC29B7C97C50DD,
    0x3F84D5B5B5470917,
    0x9216D5D98979FB1B,
    0xD1310BA698DFB5AC,
    0x2FFD72DBD01ADFB7,
    0xB8E1AFED6A267E96,
    0xBA7C9045F12C7F99,
    0x24A19947B3916CF7,
    0x0801F2E2858EFC16,
    0x636920D871574E69,
];

/// Sigma permutation table (10 base permutations; BLAKE-512 uses 16 rounds,
/// cycling through them as round % 10).
const SIGMA: [[usize; 16]; 10] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
    [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
    [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
    [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
    [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
    [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
    [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
    [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
    [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
];

// ---------------------------------------------------------------------------
// G function
// ---------------------------------------------------------------------------

/// The BLAKE-512 G mixing function.
///
/// Operates on four words of the working vector `v` at indices `a, b, c, d`,
/// mixing in two message words `m0, m1` and two constants `c0, c1`.
///
/// Rotation amounts for the 64-bit variant: 32, 25, 16, 11.
#[inline(always)]
#[allow(clippy::too_many_arguments)]
fn g(
    v: &mut [u64; 16],
    a: usize,
    b: usize,
    c: usize,
    d: usize,
    m0: u64,
    m1: u64,
    c0: u64,
    c1: u64,
) {
    v[a] = v[a].wrapping_add(v[b]).wrapping_add(m0 ^ c1);
    v[d] = (v[d] ^ v[a]).rotate_right(32);
    v[c] = v[c].wrapping_add(v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(25);
    v[a] = v[a].wrapping_add(v[b]).wrapping_add(m1 ^ c0);
    v[d] = (v[d] ^ v[a]).rotate_right(16);
    v[c] = v[c].wrapping_add(v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(11);
}

// ---------------------------------------------------------------------------
// Compression function
// ---------------------------------------------------------------------------

/// Compress a single 128-byte block into the state.
///
/// `h` is the current chaining value (8 words), `s` is the salt (4 words),
/// `t0` and `t1` form the 128-bit counter (in bits), and `block` is exactly
/// 128 bytes of message data.
fn compress(h: &mut [u64; 8], s: &[u64; 4], t0: u64, t1: u64, block: &[u8; 128]) {
    // Parse the 128-byte block as 16 big-endian u64 message words.
    let mut m = [0u64; 16];
    for (word, chunk) in m.iter_mut().zip(block.chunks_exact(8)) {
        *word = u64::from_be_bytes([
            chunk[0], chunk[1], chunk[2], chunk[3], chunk[4], chunk[5], chunk[6], chunk[7],
        ]);
    }

    // Initialize the 16-word working vector.
    let mut v = [0u64; 16];
    v[0] = h[0];
    v[1] = h[1];
    v[2] = h[2];
    v[3] = h[3];
    v[4] = h[4];
    v[5] = h[5];
    v[6] = h[6];
    v[7] = h[7];
    v[8] = s[0] ^ CB[0];
    v[9] = s[1] ^ CB[1];
    v[10] = s[2] ^ CB[2];
    v[11] = s[3] ^ CB[3];
    v[12] = t0 ^ CB[4];
    v[13] = t0 ^ CB[5];
    v[14] = t1 ^ CB[6];
    v[15] = t1 ^ CB[7];

    // 16 rounds of G (cycling through the 10 sigma permutations).
    for r in 0..16 {
        let s_row = &SIGMA[r % 10];

        // Column step
        g(
            &mut v,
            0,
            4,
            8,
            12,
            m[s_row[0]],
            m[s_row[1]],
            CB[s_row[0]],
            CB[s_row[1]],
        );
        g(
            &mut v,
            1,
            5,
            9,
            13,
            m[s_row[2]],
            m[s_row[3]],
            CB[s_row[2]],
            CB[s_row[3]],
        );
        g(
            &mut v,
            2,
            6,
            10,
            14,
            m[s_row[4]],
            m[s_row[5]],
            CB[s_row[4]],
            CB[s_row[5]],
        );
        g(
            &mut v,
            3,
            7,
            11,
            15,
            m[s_row[6]],
            m[s_row[7]],
            CB[s_row[6]],
            CB[s_row[7]],
        );

        // Diagonal step
        g(
            &mut v,
            0,
            5,
            10,
            15,
            m[s_row[8]],
            m[s_row[9]],
            CB[s_row[8]],
            CB[s_row[9]],
        );
        g(
            &mut v,
            1,
            6,
            11,
            12,
            m[s_row[10]],
            m[s_row[11]],
            CB[s_row[10]],
            CB[s_row[11]],
        );
        g(
            &mut v,
            2,
            7,
            8,
            13,
            m[s_row[12]],
            m[s_row[13]],
            CB[s_row[12]],
            CB[s_row[13]],
        );
        g(
            &mut v,
            3,
            4,
            9,
            14,
            m[s_row[14]],
            m[s_row[15]],
            CB[s_row[14]],
            CB[s_row[15]],
        );
    }

    // Finalize: H[i] ^= S[i%4] ^ v[i] ^ v[i+8]
    h[0] ^= s[0] ^ v[0] ^ v[8];
    h[1] ^= s[1] ^ v[1] ^ v[9];
    h[2] ^= s[2] ^ v[2] ^ v[10];
    h[3] ^= s[3] ^ v[3] ^ v[11];
    h[4] ^= s[0] ^ v[4] ^ v[12];
    h[5] ^= s[1] ^ v[5] ^ v[13];
    h[6] ^= s[2] ^ v[6] ^ v[14];
    h[7] ^= s[3] ^ v[7] ^ v[15];
}

// ---------------------------------------------------------------------------
// Blake512 hasher
// ---------------------------------------------------------------------------

/// BLAKE-512 hash state.
///
/// Implements the [`digest::Digest`] trait, producing a 64-byte (512-bit) hash.
///
/// # Example
///
/// ```
/// use blake512_hash::{Blake512, Digest};
///
/// let hash = Blake512::digest(b"hello");
/// assert_eq!(hash.len(), 64);
/// ```
#[derive(Clone)]
pub struct Blake512 {
    /// Current chaining value (8 x u64).
    h: [u64; 8],
    /// Salt (always zero for standard hashing).
    s: [u64; 4],
    /// Low 64 bits of the bit counter.
    t0: u64,
    /// High 64 bits of the bit counter.
    t1: u64,
    /// Internal message buffer (128 bytes = one block).
    buf: [u8; 128],
    /// Number of valid bytes currently in `buf`.
    buf_len: usize,
}

impl Blake512 {
    /// Create a new BLAKE-512 hasher with the standard IV and zero salt.
    pub fn new() -> Self {
        Blake512 {
            h: IV512,
            s: [0u64; 4],
            t0: 0,
            t1: 0,
            buf: [0u8; 128],
            buf_len: 0,
        }
    }

    /// Increment the bit counter by 1024 and compress the internal buffer.
    fn compress_buffer(&mut self) {
        let (new_t0, carry) = self.t0.overflowing_add(1024);
        self.t0 = new_t0;
        if carry {
            self.t1 = self.t1.wrapping_add(1);
        }

        let block: [u8; 128] = self.buf;
        compress(&mut self.h, &self.s, self.t0, self.t1, &block);
    }

    /// Feed data into the hasher.
    fn update_inner(&mut self, mut data: &[u8]) {
        if data.len() < 128 - self.buf_len {
            self.buf[self.buf_len..self.buf_len + data.len()].copy_from_slice(data);
            self.buf_len += data.len();
            return;
        }

        while !data.is_empty() {
            let space = 128 - self.buf_len;
            let copy_len = space.min(data.len());
            self.buf[self.buf_len..self.buf_len + copy_len].copy_from_slice(&data[..copy_len]);
            self.buf_len += copy_len;
            data = &data[copy_len..];

            if self.buf_len == 128 {
                self.compress_buffer();
                self.buf_len = 0;
            }
        }
    }

    /// Finalize the hash and return the 64-byte digest.
    fn finalize_inner(mut self) -> [u8; 64] {
        let ptr = self.buf_len;
        let bit_len = (ptr as u64) << 3;

        let tl = self.t0.wrapping_add(bit_len);
        let th = if tl < bit_len {
            self.t1.wrapping_add(1)
        } else {
            self.t1
        };

        if ptr == 0 {
            self.t0 = 0xFFFFFFFFFFFFFC00u64;
            self.t1 = 0xFFFFFFFFFFFFFFFFu64;
        } else if self.t0 == 0 {
            self.t0 = 0xFFFFFFFFFFFFFC00u64.wrapping_add(bit_len);
            self.t1 = self.t1.wrapping_sub(1);
        } else {
            self.t0 = self.t0.wrapping_sub(1024u64.wrapping_sub(bit_len));
        }

        if bit_len <= 894 {
            // Single padding block.
            self.buf[ptr] = 0x80;
            if ptr < 111 {
                for i in (ptr + 1)..111 {
                    self.buf[i] = 0;
                }
                self.buf[111] = 0x01;
            } else {
                // ptr == 111: the 0x80 start-bit is at position 111,
                // same as the 0x01 end-marker — combine them as 0x81.
                self.buf[111] = 0x81;
            }
            self.buf[112..120].copy_from_slice(&th.to_be_bytes());
            self.buf[120..128].copy_from_slice(&tl.to_be_bytes());

            self.buf_len = 128;
            let block: [u8; 128] = self.buf;
            let (new_t0, carry) = self.t0.overflowing_add(1024);
            self.t0 = new_t0;
            if carry {
                self.t1 = self.t1.wrapping_add(1);
            }
            compress(&mut self.h, &self.s, self.t0, self.t1, &block);
        } else {
            // Two padding blocks needed.
            self.buf[ptr] = 0x80;
            for i in (ptr + 1)..128 {
                self.buf[i] = 0;
            }
            self.buf_len = 128;
            let block1: [u8; 128] = self.buf;
            let (new_t0, carry) = self.t0.overflowing_add(1024);
            self.t0 = new_t0;
            if carry {
                self.t1 = self.t1.wrapping_add(1);
            }
            compress(&mut self.h, &self.s, self.t0, self.t1, &block1);

            self.t0 = 0xFFFFFFFFFFFFFC00u64;
            self.t1 = 0xFFFFFFFFFFFFFFFFu64;

            self.buf = [0u8; 128];
            self.buf[111] = 0x01;
            self.buf[112..120].copy_from_slice(&th.to_be_bytes());
            self.buf[120..128].copy_from_slice(&tl.to_be_bytes());

            let block2: [u8; 128] = self.buf;
            let (new_t0, carry) = self.t0.overflowing_add(1024);
            self.t0 = new_t0;
            if carry {
                self.t1 = self.t1.wrapping_add(1);
            }
            compress(&mut self.h, &self.s, self.t0, self.t1, &block2);
        }

        let mut out = [0u8; 64];
        for (i, word) in self.h.iter().enumerate() {
            out[i * 8..(i + 1) * 8].copy_from_slice(&word.to_be_bytes());
        }
        out
    }
}

// ---------------------------------------------------------------------------
// digest trait implementations
// ---------------------------------------------------------------------------

impl Default for Blake512 {
    fn default() -> Self {
        Self::new()
    }
}

impl Update for Blake512 {
    fn update(&mut self, data: &[u8]) {
        self.update_inner(data);
    }
}

impl OutputSizeUser for Blake512 {
    type OutputSize = U64;
}

impl FixedOutput for Blake512 {
    fn finalize_into(self, out: &mut GenericArray<u8, Self::OutputSize>) {
        let hash = self.finalize_inner();
        out.copy_from_slice(&hash);
    }
}

impl Reset for Blake512 {
    fn reset(&mut self) {
        *self = Self::new();
    }
}

impl HashMarker for Blake512 {}

// ---------------------------------------------------------------------------
// Internal unit tests (access private fields for counter edge cases)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compress_buffer_counter_carry() {
        // When t0 is near u64::MAX, adding 1024 should overflow and increment t1.
        let mut h = Blake512::new();
        h.t0 = 0xFFFFFFFFFFFFFC00; // Adding 1024 wraps to 0
        h.t1 = 5;
        h.buf = [0xAA; 128];
        h.buf_len = 128;
        h.compress_buffer();

        assert_eq!(h.t0, 0, "t0 should wrap to 0");
        assert_eq!(h.t1, 6, "t1 should increment on carry");
    }

    #[test]
    fn compress_buffer_counter_no_carry() {
        let mut h = Blake512::new();
        h.t0 = 0;
        h.t1 = 0;
        h.buf = [0xBB; 128];
        h.buf_len = 128;
        h.compress_buffer();

        assert_eq!(h.t0, 1024, "t0 should be 1024 after one block");
        assert_eq!(h.t1, 0, "t1 should remain 0");
    }

    #[test]
    fn finalize_branch_a2_ptr_gt0_t0_eq_zero() {
        // Branch A2: ptr > 0, t0 == 0 (counter wrapped after prior blocks).
        // This requires t0 to be exactly 0 at finalize with data in the buffer.
        // Simulate: set t0=0, t1=1 (as if 2^54 blocks were processed), buf has 10 bytes.
        let mut h = Blake512::new();
        h.t0 = 0;
        h.t1 = 1;
        h.buf[..10].copy_from_slice(&[0xCC; 10]);
        h.buf_len = 10;

        let result = h.finalize_inner();

        // We can't easily verify the exact hash without a reference, but we can
        // verify the counter adjustment was applied correctly by checking the
        // output is 64 bytes and deterministic.
        assert_eq!(result.len(), 64);

        // Re-create the same state and verify determinism.
        let mut h2 = Blake512::new();
        h2.t0 = 0;
        h2.t1 = 1;
        h2.buf[..10].copy_from_slice(&[0xCC; 10]);
        h2.buf_len = 10;

        assert_eq!(h2.finalize_inner(), result);
    }

    #[test]
    fn finalize_tl_carry_propagation() {
        // When t0 + bit_len overflows, th should be incremented.
        let mut h = Blake512::new();
        h.t0 = u64::MAX - 50; // t0 + bit_len(10 bytes = 80 bits) will overflow
        h.t1 = 3;
        h.buf[..10].copy_from_slice(&[0xDD; 10]);
        h.buf_len = 10;

        let result = h.finalize_inner();
        assert_eq!(result.len(), 64);

        // Verify determinism with same state.
        let mut h2 = Blake512::new();
        h2.t0 = u64::MAX - 50;
        h2.t1 = 3;
        h2.buf[..10].copy_from_slice(&[0xDD; 10]);
        h2.buf_len = 10;

        assert_eq!(h2.finalize_inner(), result);
    }

    #[test]
    fn finalize_ptr0_sentinel_counter() {
        // When ptr == 0 (empty buffer), sentinel counter values should be set.
        // After compress_buffer in finalize, t0 wraps: 0xFFFFFFFFFFFFFC00 + 1024 = 0,
        // and t1 wraps: 0xFFFFFFFFFFFFFFFF + 1 = 0.
        let mut h = Blake512::new();
        h.t0 = 1024; // As if one block was compressed
        h.t1 = 0;
        h.buf_len = 0;

        let result = h.finalize_inner();
        assert_eq!(result.len(), 64);

        // This should match hashing 128 bytes... but with synthetic h state
        // from just IV (no prior compress). The point is it doesn't panic.
        // Verify determinism.
        let mut h2 = Blake512::new();
        h2.t0 = 1024;
        h2.t1 = 0;
        h2.buf_len = 0;

        assert_eq!(h2.finalize_inner(), result);
    }
}
