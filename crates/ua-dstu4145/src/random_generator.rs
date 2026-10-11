use std::time::{SystemTime, UNIX_EPOCH};

use rand_core::{CryptoRng, OsRng, RngCore};
use ua_gost::{DEFAULT_DKE, Gost28147};

use crate::RandomGeneratorError;

const BLOCK_BYTES: usize = Gost28147::BLOCK_BYTES;
const KEY_BYTES: usize = Gost28147::KEY_BYTES;
const BYTE_BITS: usize = 8;
/// .NET ticks (100 ns since 0001-01-01) at the Unix epoch: D counts time as the reference implementation does.
const TICKS_AT_UNIX_EPOCH: u64 = 621_355_968_000_000_000;
const NANOSECONDS_PER_TICK: u128 = 100;

/// The random bit generator of DSTU 4145-2002, Appendix А, on GOST 28147-89 in simple substitution mode.
///
/// State: the secret key k (256 bits), the secret seed s (64 bits) and I = E_k(D), D the date and time. Each bit is
/// x = E_k(I ⊕ s), s = E_k(x ⊕ I), output the least significant bit of x. Bytes are filled most significant bit
/// first, so the first bit leads an integer read big-endian (6.3, 6.4). The generator is only as good as its key and
/// seed, and slow by design: two block encryptions per bit.
pub struct RandomGenerator {
    cipher: Gost28147,
    i: [u8; BLOCK_BYTES],
    s: [u8; BLOCK_BYTES],
}

impl RandomGenerator {
    /// The generator with the key k, the seed s, the date and time D (the current UTC time in .NET ticks when absent)
    /// and a 128-entry GOST 28147 substitution table (the expanded default DKE when absent).
    pub fn new(
        key: &[u8; KEY_BYTES],
        seed: &[u8; BLOCK_BYTES],
        date_time: Option<u64>,
        sbox: Option<&[u8]>,
    ) -> Result<Self, RandomGeneratorError> {
        let mut cipher = match sbox {
            Some(sbox) => Gost28147::new(sbox)?,
            None => Gost28147::new(&Gost28147::expand_dke(&DEFAULT_DKE)?)?,
        };
        cipher.set_key(key);
        let d = match date_time {
            Some(ticks) => ticks,
            None => read_utc_ticks(),
        };
        let d = d.to_le_bytes();
        let i = cipher.encrypt_block(&d); // I = E_k(D)
        Ok(Self { cipher, i, s: *seed })
    }

    /// The generator whose key and seed come from the operating system's generator, at the current time.
    pub fn from_os_entropy() -> Self {
        let mut key = [0u8; KEY_BYTES];
        let mut seed = [0u8; BLOCK_BYTES];
        OsRng.fill_bytes(&mut key);
        OsRng.fill_bytes(&mut seed);
        let generator = Self::new(&key, &seed, None, None);
        key.fill(0);
        seed.fill(0);
        match generator {
            Ok(generator) => generator,
            Err(error) => unreachable!("the default DKE is a valid table: {error}"),
        }
    }

    /// The next bit, 0 or 1.
    pub fn next_bit(&mut self) -> u8 {
        let x = self.cipher.encrypt_block(&xor_blocks(&self.i, &self.s)); // x = E_k(I ⊕ s)
        self.s = self.cipher.encrypt_block(&xor_blocks(&x, &self.i)); // s = E_k(x ⊕ I)
        x[0] & 1 // x_0, the rightmost bit of x
    }
}

impl RngCore for RandomGenerator {
    fn next_u32(&mut self) -> u32 {
        rand_core::impls::next_u32_via_fill(self)
    }

    fn next_u64(&mut self) -> u64 {
        rand_core::impls::next_u64_via_fill(self)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        for byte in dest.iter_mut() {
            *byte = (0..BYTE_BITS).fold(0u8, |acc, _| (acc << 1) | self.next_bit());
        }
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

impl CryptoRng for RandomGenerator {}

fn xor_blocks(a: &[u8; BLOCK_BYTES], b: &[u8; BLOCK_BYTES]) -> [u8; BLOCK_BYTES] {
    std::array::from_fn(|j| a[j] ^ b[j])
}

/// The current UTC time in .NET ticks.
fn read_utc_ticks() -> u64 {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(after) => TICKS_AT_UNIX_EPOCH.wrapping_add((after.as_nanos() / NANOSECONDS_PER_TICK) as u64),
        Err(before) => TICKS_AT_UNIX_EPOCH.wrapping_sub((before.duration().as_nanos() / NANOSECONDS_PER_TICK) as u64),
    }
}
