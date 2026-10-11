/// Bytes the library hands out: the caller owns them and releases them with `ua_free_buffer`. Empty bytes have a
/// NULL `data`. A function writes its output buffers only when it returns `UA_STATUS_OK`.
#[repr(C)]
#[derive(Debug)]
pub struct UaBuffer {
    /// The first byte, or NULL when empty.
    pub data: *mut u8,
    /// The number of bytes.
    pub len: usize,
}
