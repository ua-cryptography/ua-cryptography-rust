use std::ops::BitOr;

/// keyUsage bits (RFC 5280, 4.2.1.3): bit i of the value is the named bit i.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct KeyUsageFlags(pub u32);

impl KeyUsageFlags {
    /// No bit.
    pub const NONE: Self = Self(0);
    /// digitalSignature (0).
    pub const DIGITAL_SIGNATURE: Self = Self(1 << 0);
    /// nonRepudiation / contentCommitment (1).
    pub const NON_REPUDIATION: Self = Self(1 << 1);
    /// keyEncipherment (2).
    pub const KEY_ENCIPHERMENT: Self = Self(1 << 2);
    /// dataEncipherment (3).
    pub const DATA_ENCIPHERMENT: Self = Self(1 << 3);
    /// keyAgreement (4).
    pub const KEY_AGREEMENT: Self = Self(1 << 4);
    /// keyCertSign (5).
    pub const KEY_CERT_SIGN: Self = Self(1 << 5);
    /// cRLSign (6).
    pub const CRL_SIGN: Self = Self(1 << 6);
}

impl BitOr for KeyUsageFlags {
    type Output = Self;

    fn bitor(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }
}
