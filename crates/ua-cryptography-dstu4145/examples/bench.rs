//! A simple `Instant` benchmark of the field and curve arithmetic and of DSTU 4145 signatures; prints a Markdown table.
//!
//! ```bash
//! cargo run --release -p ua-cryptography-dstu4145 --example bench [-- --quick]
//! # without PMULL/PCLMULQDQ:
//! cargo run --release -p ua-cryptography-dstu4145 --example bench --features ua-cryptography-gf2m/portable
//! ```

use std::hint::black_box;
use std::time::Instant;

use rand_core::{OsRng, RngCore};
use ua_cryptography_dstu4145::{DomainParameters, NORMAL_DEGREES, POLYNOMIAL_DEGREES, Signer};
use ua_cryptography_gf2m::FieldElement;
use ua_cryptography_gost::Gost34311;

const HASH_BYTES: usize = 32;
const PAYLOAD_BYTES: usize = 1 << 20;
const NANOSECONDS_PER_MICROSECOND: f64 = 1_000.0;

/// Iteration counts: (full run, `--quick`).
const FIELD_ITERATIONS: (u32, u32) = (200_000, 20_000);
const INVERSION_ITERATIONS: (u32, u32) = (5_000, 500);
const CURVE_ITERATIONS: (u32, u32) = (200, 20);
const WARM_UP_SIGNATURES: (u32, u32) = (20, 3);
const HASH_ITERATIONS: (u32, u32) = (20, 3);

fn main() {
    let is_quick = std::env::args().any(|argument| argument == "--quick");
    let pick = |(full, quick): (u32, u32)| if is_quick { quick } else { full };

    println!(
        "# DSTU 4145 benchmark (Rust, {}, {})",
        std::env::consts::ARCH,
        std::env::consts::OS
    );
    println!();
    let path = if ua_cryptography_gf2m::has_hardware_carryless_multiplication() {
        "hardware (PMULL/PCLMULQDQ)"
    } else {
        "portable (4-bit window)"
    };
    println!("Carry-less multiplication: {path}");
    println!();
    println!("| Curve | mul, ns | sqr, ns | inv, µs | kP, µs | sign, µs | verify, µs |");
    println!("|---|---:|---:|---:|---:|---:|---:|");

    let curves = select_curves();
    for (_, parameters) in &curves {
        warm_up(parameters, pick(WARM_UP_SIGNATURES));
    }
    for (name, parameters) in &curves {
        print_curve_row(name, parameters, &pick);
    }

    println!();
    println!("| Hash | MB/s |");
    println!("|---|---:|");
    let mut payload = vec![0u8; PAYLOAD_BYTES];
    OsRng.fill_bytes(&mut payload);
    let mut gost = Gost34311::default();
    let nanoseconds = measure(pick(HASH_ITERATIONS), || {
        black_box(gost.hash(black_box(&payload)));
    });
    println!(
        "| GOST 34.311 | {:.0} |",
        PAYLOAD_BYTES as f64 / (nanoseconds / 1e9) / 1e6
    );
}

fn select_curves() -> Vec<(String, DomainParameters)> {
    let polynomial = POLYNOMIAL_DEGREES
        .iter()
        .map(|&m| (format!("PB {m}"), ua_cryptography_dstu4145::get_polynomial_curve(m)));
    let normal = NORMAL_DEGREES.iter().map(|&m| {
        (
            format!("ONB {m}"),
            ua_cryptography_dstu4145::get_optimal_normal_curve(m),
        )
    });
    polynomial
        .chain(normal)
        .filter_map(|(name, curve)| curve.ok().map(|parameters| (name, parameters)))
        .collect()
}

fn warm_up(parameters: &DomainParameters, rounds: u32) {
    let mut signer = Signer::new(parameters);
    let key = signer.generate_key_pair();
    let hash = random_hash();
    for _ in 0..rounds {
        if let Ok(signature) = signer.sign_hash(&key.private_key, &hash) {
            black_box(signer.verify_hash(&key.public_key, &hash, &signature));
        }
    }
}

fn print_curve_row(name: &str, parameters: &DomainParameters, pick: &impl Fn((u32, u32)) -> u32) {
    let field = parameters.field();
    let mut signer = Signer::new(parameters);
    let key = signer.generate_key_pair();
    let hash = random_hash();
    let Ok(signature) = signer.sign_hash(&key.private_key, &hash) else {
        println!("| {name} | signing failed |");
        return;
    };

    let a = FieldElement::random(field, &mut OsRng);
    let b = FieldElement::random(field, &mut OsRng);
    let multiply = measure(pick(FIELD_ITERATIONS), || {
        black_box(black_box(&a) * black_box(&b));
    });
    let square = measure(pick(FIELD_ITERATIONS), || {
        black_box(black_box(&a).square());
    });
    let invert = measure(pick(INVERSION_ITERATIONS), || {
        black_box(black_box(&a).invert());
    });
    let k = parameters.generate_integer(&mut OsRng);
    let scalar_multiply = measure(pick(CURVE_ITERATIONS), || {
        black_box(parameters.curve().multiply(parameters.base_point(), black_box(&k)));
    });
    let sign = measure(pick(CURVE_ITERATIONS), || {
        black_box(signer.sign_hash(&key.private_key, black_box(&hash)).is_ok());
    });
    let verifier = Signer::new(parameters);
    let verify = measure(pick(CURVE_ITERATIONS), || {
        black_box(verifier.verify_hash(&key.public_key, black_box(&hash), &signature));
    });
    println!(
        "| {name} | {multiply:.0} | {square:.0} | {:.1} | {:.0} | {:.0} | {:.0} |",
        invert / NANOSECONDS_PER_MICROSECOND,
        scalar_multiply / NANOSECONDS_PER_MICROSECOND,
        sign / NANOSECONDS_PER_MICROSECOND,
        verify / NANOSECONDS_PER_MICROSECOND,
    );
}

fn random_hash() -> [u8; HASH_BYTES] {
    let mut hash = [0u8; HASH_BYTES];
    OsRng.fill_bytes(&mut hash);
    hash
}

/// Nanoseconds per call, after a warm-up of a tenth of the iterations (at least three).
fn measure(iterations: u32, mut action: impl FnMut()) -> f64 {
    for _ in 0..(iterations / 10).max(3) {
        action();
    }
    let started = Instant::now();
    for _ in 0..iterations {
        action();
    }
    started.elapsed().as_nanos() as f64 / f64::from(iterations)
}
