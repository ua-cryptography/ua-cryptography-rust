use ua_cryptography_dstu7564::Kupyna;
use ua_cryptography_gost::Gost34311;

/// A hash fed with a message in parts: what the bindings hand out as a hash state.
// The bindings keep the state on the heap already: boxing a variant would add a second allocation.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone)]
pub enum StreamingHash {
    /// GOST 34.311-95.
    Gost34311(Gost34311),
    /// DSTU 7564.
    Dstu7564(Kupyna),
}

impl StreamingHash {
    /// Absorbs the next part of the message.
    pub fn update(&mut self, data: &[u8]) {
        match self {
            Self::Gost34311(hash) => hash.update(data),
            Self::Dstu7564(hash) => hash.update(data),
        }
    }

    /// The hash of everything absorbed; the state starts over.
    pub fn finalize(&mut self) -> Vec<u8> {
        match self {
            Self::Gost34311(hash) => hash.finalize().to_vec(),
            Self::Dstu7564(hash) => hash.finalize(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ua_cryptography_dstu7564::HashSize;

    #[test]
    fn a_message_in_parts_has_the_hash_of_the_whole() {
        let mut gost = StreamingHash::Gost34311(Gost34311::default());
        let mut kupyna = StreamingHash::Dstu7564(Kupyna::new(HashSize::Bits256));
        for hash in [&mut gost, &mut kupyna] {
            hash.update(b"mes");
            hash.update(b"sage");
        }
        assert_eq!(gost.finalize(), Gost34311::calculate_hash(b"message").to_vec());
        assert_eq!(kupyna.finalize(), Kupyna::calculate_hash(b"message", HashSize::Bits256));
    }
}
