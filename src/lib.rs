// sha256.rs - Bare-metal SHA-256 implementation in Rust (no std, no external crates)

#![no_std]

// Rotate right operation
#[inline]
fn rotr(x: u32, n: u32) -> u32 {
    (x >> n) | (x << (32 - n))
}

// SHA-256 logical functions
#[inline]
fn ch(x: u32, y: u32, z: u32) -> u32 {
    (x & y) ^ (!x & z)
}

#[inline]
fn maj(x: u32, y: u32, z: u32) -> u32 {
    (x & y) ^ (x & z) ^ (y & z)
}

#[inline]
fn bsig0(x: u32) -> u32 {
    rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22)
}

#[inline]
fn bsig1(x: u32) -> u32 {
    rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25)
}

#[inline]
fn ssig0(x: u32) -> u32 {
    rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3)
}

#[inline]
fn ssig1(x: u32) -> u32 {
    rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10)
}

// Round constants
const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

#[repr(C)]
pub struct Sha256Ctx {
    h: [u32; 8],
    buffer: [u8; 64],
    buflen: u32,
    bitlen: u64,
}

impl Sha256Ctx {
    fn transform(&mut self, block: &[u8]) {
        let mut w = [0u32; 64];
        
        // Prepare message schedule
        for i in 0..16 {
            let j = i * 4;
            w[i] = ((block[j] as u32) << 24)
                | ((block[j + 1] as u32) << 16)
                | ((block[j + 2] as u32) << 8)
                | (block[j + 3] as u32);
        }
        
        for i in 16..64 {
            w[i] = ssig1(w[i - 2])
                .wrapping_add(w[i - 7])
                .wrapping_add(ssig0(w[i - 15]))
                .wrapping_add(w[i - 16]);
        }
        
        // Initialize working variables
        let mut a = self.h[0];
        let mut b = self.h[1];
        let mut c = self.h[2];
        let mut d = self.h[3];
        let mut e = self.h[4];
        let mut f = self.h[5];
        let mut g = self.h[6];
        let mut h = self.h[7];
        
        // Main compression loop
        for i in 0..64 {
            let t1 = h
                .wrapping_add(bsig1(e))
                .wrapping_add(ch(e, f, g))
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let t2 = bsig0(a).wrapping_add(maj(a, b, c));
            
            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }
        
        // Add to state
        self.h[0] = self.h[0].wrapping_add(a);
        self.h[1] = self.h[1].wrapping_add(b);
        self.h[2] = self.h[2].wrapping_add(c);
        self.h[3] = self.h[3].wrapping_add(d);
        self.h[4] = self.h[4].wrapping_add(e);
        self.h[5] = self.h[5].wrapping_add(f);
        self.h[6] = self.h[6].wrapping_add(g);
        self.h[7] = self.h[7].wrapping_add(h);
    }
}

#[no_mangle]
pub extern "C" fn rust_sha256_init(ctx: *mut Sha256Ctx) {
    unsafe {
        (*ctx).h = [
            0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
            0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
        ];
        (*ctx).buflen = 0;
        (*ctx).bitlen = 0;
    }
}

#[no_mangle]
pub extern "C" fn rust_sha256_update(ctx: *mut Sha256Ctx, data: *const u8, len: u32) {
    unsafe {
        let ctx_ref = &mut *ctx;
        let data_slice = core::slice::from_raw_parts(data, len as usize);
        
        ctx_ref.bitlen += (len as u64) * 8;
        
        let mut i = 0;
        
        // Fill buffer if partially full
        if ctx_ref.buflen > 0 {
            let need = 64 - ctx_ref.buflen;
            if len < need {
                for j in 0..len {
                    ctx_ref.buffer[(ctx_ref.buflen + j) as usize] = data_slice[j as usize];
                }
                ctx_ref.buflen += len;
                return;
            } else {
                for j in 0..need {
                    ctx_ref.buffer[(ctx_ref.buflen + j) as usize] = data_slice[j as usize];
                }
                let mut temp_buffer = [0u8; 64];
                temp_buffer.copy_from_slice(&ctx_ref.buffer);
                ctx_ref.transform(&temp_buffer);
                ctx_ref.buflen = 0;
                i += need;
            }
        }
        
        // Process full blocks
        while i + 64 <= len {
            ctx_ref.transform(&data_slice[i as usize..(i + 64) as usize]);
            i += 64;
        }
        
        // Copy remainder to buffer
        if i < len {
            let rem = len - i;
            for j in 0..rem {
                ctx_ref.buffer[j as usize] = data_slice[(i + j) as usize];
            }
            ctx_ref.buflen = rem;
        }
    }
}

#[no_mangle]
pub extern "C" fn rust_sha256_final(ctx: *mut Sha256Ctx, out_hash32: *mut u8) {
    unsafe {
        let ctx_ref = &mut *ctx;
        let bits = ctx_ref.bitlen;
        
        // Append 0x80
        ctx_ref.buffer[ctx_ref.buflen as usize] = 0x80;
        ctx_ref.buflen += 1;
        
        // Handle case where padding doesn't fit
        if ctx_ref.buflen > 56 {
            while ctx_ref.buflen < 64 {
                ctx_ref.buffer[ctx_ref.buflen as usize] = 0;
                ctx_ref.buflen += 1;
            }
            let mut temp_buffer = [0u8; 64];
            temp_buffer.copy_from_slice(&ctx_ref.buffer);
            ctx_ref.transform(&temp_buffer);
            ctx_ref.buflen = 0;
        }
        
        // Pad with zeros
        while ctx_ref.buflen < 56 {
            ctx_ref.buffer[ctx_ref.buflen as usize] = 0;
            ctx_ref.buflen += 1;
        }
        
        // Append length
        ctx_ref.buffer[56] = (bits >> 56) as u8;
        ctx_ref.buffer[57] = (bits >> 48) as u8;
        ctx_ref.buffer[58] = (bits >> 40) as u8;
        ctx_ref.buffer[59] = (bits >> 32) as u8;
        ctx_ref.buffer[60] = (bits >> 24) as u8;
        ctx_ref.buffer[61] = (bits >> 16) as u8;
        ctx_ref.buffer[62] = (bits >> 8) as u8;
        ctx_ref.buffer[63] = bits as u8;
        
        // Final transform
        let mut temp_buffer = [0u8; 64];
        temp_buffer.copy_from_slice(&ctx_ref.buffer);
        ctx_ref.transform(&temp_buffer);
        
        // Output hash
        let out_slice = core::slice::from_raw_parts_mut(out_hash32, 32);
        for i in 0..8 {
            let val = ctx_ref.h[i];
            out_slice[i * 4] = (val >> 24) as u8;
            out_slice[i * 4 + 1] = (val >> 16) as u8;
            out_slice[i * 4 + 2] = (val >> 8) as u8;
            out_slice[i * 4 + 3] = val as u8;
        }
    }
}

#[no_mangle]
pub extern "C" fn rust_sha256_to_hex(hash32: *const u8, hex_out: *mut u8) {
    const HEX_CHARS: &[u8; 16] = b"0123456789abcdef";
    unsafe {
        let hash_slice = core::slice::from_raw_parts(hash32, 32);
        let hex_slice = core::slice::from_raw_parts_mut(hex_out, 65);
        
        for i in 0..32 {
            let b = hash_slice[i];
            hex_slice[i * 2] = HEX_CHARS[(b >> 4) as usize];
            hex_slice[i * 2 + 1] = HEX_CHARS[(b & 0x0F) as usize];
        }
        hex_slice[64] = 0; // null terminator
    }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}