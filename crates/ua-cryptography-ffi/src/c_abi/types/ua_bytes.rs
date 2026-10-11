/// Bytes the caller lends for one call. A NULL `data` with `len` 0 is empty; an optional input is absent when
/// `data` is NULL.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct UaBytes {
    /// The first byte.
    pub data: *const u8,
    /// The number of bytes.
    pub len: usize,
}
