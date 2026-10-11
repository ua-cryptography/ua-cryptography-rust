//! The Montgomery ladder in López–Dahab projective x-only coordinates (J. López, R. Dahab, "Fast multiplication on
//! elliptic curves over GF(2^m) without precomputation", CHES 1999), on the internal representation.

use num_bigint::BigUint;

use crate::binary_field::add_words;
use crate::gf2_poly::{self, Words};
use crate::{BinaryCurve, BinaryField, CurvePoint, FieldElement};

/// A projective x-only point (X : Z).
struct ProjectiveX {
    x: Words,
    z: Words,
}

/// kP from the top `bits` bits of k (the leading one included); P is finite with x ≠ 0.
pub(super) fn multiply(curve: &BinaryCurve, p: &CurvePoint, k: &BigUint, bits: u64) -> CurvePoint {
    let field = curve.field();
    let Some((affine_x, _)) = p.coordinates() else {
        return curve.infinity();
    };
    let x = affine_x.words();

    // R0 = P, R1 = 2P = (x⁴ + B : x²)
    let mut r0 = ProjectiveX {
        x: *x,
        z: *field.one_words(),
    };
    let x_squared = field.square(x);
    let mut r1 = ProjectiveX {
        x: add_words(&field.square(&x_squared), curve.b().words()),
        z: x_squared,
    };

    let mut swap = 0u64;
    for i in (0..bits.saturating_sub(1)).rev() {
        let bit = u64::from(k.bit(i));
        swap ^= bit;
        swap_conditionally(&mut r0, &mut r1, swap);
        swap = bit;

        // R1 ← R0 + R1 (their difference is P), R0 ← 2 R0
        add_differential(field, &mut r1, &r0, x);
        double(field, &mut r0, curve.sqrt_b_words());
    }
    swap_conditionally(&mut r0, &mut r1, swap);

    recover_affine(curve, p, &r0, &r1)
}

/// a ← a + b, given that their difference has the affine x-coordinate x.
fn add_differential(field: &BinaryField, a: &mut ProjectiveX, b: &ProjectiveX, x: &Words) {
    let t1 = field.multiply(&a.x, &b.z); // Xa Zb
    let t2 = field.multiply(&b.x, &a.z); // Xb Za
    a.z = field.square(&add_words(&t1, &t2)); // (Xa Zb + Xb Za)²
    let product = field.multiply(&t1, &t2);
    a.x = add_words(&field.multiply(x, &a.z), &product); // x Za + Xa Zb Xb Za
}

/// r ← 2r: X = X⁴ + B Z⁴ = (X² + √B Z²)², Z = X² Z².
fn double(field: &BinaryField, r: &mut ProjectiveX, sqrt_b: &Words) {
    let x_squared = field.square(&r.x);
    let z_squared = field.square(&r.z);
    r.z = field.multiply(&x_squared, &z_squared);
    r.x = field.square(&add_words(&x_squared, &field.multiply(&z_squared, sqrt_b)));
}

/// The affine kP from (X1 : Z1) = kP, (X2 : Z2) = (k+1)P and P = (x, y) (López–Dahab, Mxy).
fn recover_affine(curve: &BinaryCurve, p: &CurvePoint, r0: &ProjectiveX, r1: &ProjectiveX) -> CurvePoint {
    if gf2_poly::is_zero(&r0.z) {
        return curve.infinity();
    }
    if gf2_poly::is_zero(&r1.z) {
        return curve.negate(p); // (k+1)P = O, so kP = −P
    }
    let field = curve.field();
    let Some((affine_x, affine_y)) = p.coordinates() else {
        return curve.infinity();
    };
    let (x, y) = (affine_x.words(), affine_y.words());

    let z_product = field.multiply(&r0.z, &r1.z); // Z1 Z2
    let a = add_words(&field.multiply(&r0.z, x), &r0.x); // X1 + x Z1
    let x_z2 = field.multiply(&r1.z, x);
    let numerator_x = field.multiply(&x_z2, &r0.x); // X1 x Z2, x_k after the division
    let b = field.multiply(&a, &add_words(&x_z2, &r1.x)); // (X1 + x Z1)(X2 + x Z2)
    let mut numerator_y = add_words(&field.square(x), y); // x² + y
    numerator_y = add_words(&field.multiply(&numerator_y, &z_product), &b);
    let denominator = field.invert(&field.multiply(&z_product, x)); // 1 / (x Z1 Z2)
    let ratio = field.multiply(&numerator_y, &denominator);
    let x_k = field.multiply(&numerator_x, &denominator); // X1 / Z1
    let y_k = add_words(&field.multiply(&add_words(&x_k, x), &ratio), y);

    CurvePoint::from_trusted_coordinates(
        curve,
        FieldElement::from_words(field, x_k),
        FieldElement::from_words(field, y_k),
    )
}

/// Swaps a and b when `swap` is 1, with the same operations either way.
fn swap_conditionally(a: &mut ProjectiveX, b: &mut ProjectiveX, swap: u64) {
    let mask = 0u64.wrapping_sub(swap);
    for (left, right) in
        a.x.iter_mut()
            .zip(b.x.iter_mut())
            .chain(a.z.iter_mut().zip(b.z.iter_mut()))
    {
        let difference = (*left ^ *right) & mask;
        *left ^= difference;
        *right ^= difference;
    }
}
