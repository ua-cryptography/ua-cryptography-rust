//! Java's DataInput / DataOutput as JKS uses them: big-endian integers and modified UTF-8 strings.

use crate::errors::KeyStoreError;

/// The last code unit written as one byte (U+0000 is not).
const LAST_ONE_BYTE_UNIT: u16 = 0x7F;
/// The last code unit written as two bytes.
const LAST_TWO_BYTE_UNIT: u16 = 0x7FF;
/// The lead bits of a two-byte sequence.
const TWO_BYTE_LEAD: u8 = 0xC0;
/// The lead bits of a three-byte sequence.
const THREE_BYTE_LEAD: u8 = 0xE0;
/// The lead bits of a continuation byte.
const CONTINUATION: u8 = 0x80;
/// The payload bits of a continuation byte.
const CONTINUATION_BITS: u8 = 0x3F;
/// The lead-byte mask that tells a two-byte sequence.
const TWO_BYTE_MASK: u8 = 0xE0;
/// The lead-byte mask that tells a three-byte sequence.
const THREE_BYTE_MASK: u8 = 0xF0;
/// The payload bits of a two-byte lead.
const TWO_BYTE_PAYLOAD: u8 = 0x1F;
/// The payload bits of a three-byte lead.
const THREE_BYTE_PAYLOAD: u8 = 0x0F;
/// The bits of one continuation byte.
const CONTINUATION_SHIFT: u32 = 6;

/// Reads the big-endian fields of a key store body.
pub(crate) struct JavaReader<'a> {
    data: &'a [u8],
    offset: usize,
}

impl<'a> JavaReader<'a> {
    pub(crate) fn new(data: &'a [u8]) -> Self {
        Self { data, offset: 0 }
    }

    pub(crate) fn is_at_end(&self) -> bool {
        self.offset == self.data.len()
    }

    pub(crate) fn read_bytes(&mut self, count: usize) -> Result<&'a [u8], KeyStoreError> {
        let end = self.offset.checked_add(count).filter(|&end| end <= self.data.len());
        let end = end.ok_or(KeyStoreError::Truncated)?;
        let bytes = &self.data[self.offset..end];
        self.offset = end;
        Ok(bytes)
    }

    pub(crate) fn read_u32(&mut self) -> Result<u32, KeyStoreError> {
        let bytes = self.read_bytes(size_of::<u32>())?;
        Ok(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    pub(crate) fn read_u64(&mut self) -> Result<u64, KeyStoreError> {
        let high = u64::from(self.read_u32()?);
        let low = u64::from(self.read_u32()?);
        Ok((high << u32::BITS) | low)
    }

    /// A u32 length followed by that many bytes.
    pub(crate) fn read_counted_bytes(&mut self) -> Result<&'a [u8], KeyStoreError> {
        let count = self.read_u32()? as usize;
        self.read_bytes(count)
    }

    /// DataInput.readUTF: a u16 length and modified UTF-8; unpaired surrogates become U+FFFD.
    pub(crate) fn read_java_utf(&mut self) -> Result<String, KeyStoreError> {
        let length = self.read_bytes(size_of::<u16>())?;
        let bytes = self.read_bytes(usize::from(u16::from_be_bytes([length[0], length[1]])))?;
        let units = decode_modified_utf8(bytes)?;
        Ok(String::from_utf16_lossy(&units))
    }
}

pub(crate) fn write_u32(output: &mut Vec<u8>, value: u32) {
    output.extend_from_slice(&value.to_be_bytes());
}

/// DataOutput.writeUTF: U+0000 as C0 80, characters outside the BMP as two 3-byte surrogates.
pub(crate) fn write_java_utf(output: &mut Vec<u8>, text: &str) -> Result<(), KeyStoreError> {
    let mut bytes = Vec::new();
    for unit in text.encode_utf16() {
        if unit != 0 && unit <= LAST_ONE_BYTE_UNIT {
            bytes.push(unit as u8);
        } else if unit <= LAST_TWO_BYTE_UNIT {
            bytes.push(TWO_BYTE_LEAD | (unit >> CONTINUATION_SHIFT) as u8);
            bytes.push(continuation(unit));
        } else {
            bytes.push(THREE_BYTE_LEAD | (unit >> (2 * CONTINUATION_SHIFT)) as u8);
            bytes.push(continuation(unit >> CONTINUATION_SHIFT));
            bytes.push(continuation(unit));
        }
    }
    // The length prefix is an unsigned 16-bit value.
    let length = u16::try_from(bytes.len()).map_err(|_| KeyStoreError::AliasTooLong)?;
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(&bytes);
    Ok(())
}

fn continuation(bits: u16) -> u8 {
    CONTINUATION | (bits as u8 & CONTINUATION_BITS)
}

fn decode_modified_utf8(bytes: &[u8]) -> Result<Vec<u16>, KeyStoreError> {
    let mut units = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        let lead = bytes[index];
        let payload = |offset: usize| u16::from(bytes[index + offset] & CONTINUATION_BITS);
        if lead < CONTINUATION {
            units.push(u16::from(lead));
            index += 1;
        } else if lead & TWO_BYTE_MASK == TWO_BYTE_LEAD && index + 1 < bytes.len() {
            units.push((u16::from(lead & TWO_BYTE_PAYLOAD) << CONTINUATION_SHIFT) | payload(1));
            index += 2;
        } else if lead & THREE_BYTE_MASK == THREE_BYTE_LEAD && index + 2 < bytes.len() {
            let high = u16::from(lead & THREE_BYTE_PAYLOAD) << (2 * CONTINUATION_SHIFT);
            units.push(high | (payload(1) << CONTINUATION_SHIFT) | payload(2));
            index += 3;
        } else {
            return Err(KeyStoreError::InvalidModifiedUtf8);
        }
    }
    Ok(units)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn modified_utf8_round_trips_nul_cyrillic_and_surrogate_pairs() {
        let text = "nul\u{0}char підпис 🔑";
        let mut output = Vec::new();
        write_java_utf(&mut output, text).unwrap();
        assert!(output.windows(5).any(|window| window == [b'n', b'u', b'l', 0xC0, 0x80]));
        assert!(!output[2..].contains(&0));
        let mut reader = JavaReader::new(&output);
        assert_eq!(reader.read_java_utf().unwrap(), text);
        assert!(reader.is_at_end());
    }

    #[test]
    fn truncated_data_is_refused() {
        let mut reader = JavaReader::new(&[0, 0, 1]);
        assert_eq!(reader.read_u32(), Err(KeyStoreError::Truncated));
        assert_eq!(
            JavaReader::new(&[0, 1, 0xC0]).read_java_utf(),
            Err(KeyStoreError::InvalidModifiedUtf8)
        );
    }
}
