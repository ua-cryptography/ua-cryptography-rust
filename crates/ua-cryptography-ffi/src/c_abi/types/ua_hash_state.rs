use crate::operations::StreamingHash;

/// A hash fed with a message in parts; made by `ua_gost34311_begin_hash` or `ua_dstu7564_begin_hash`, released
/// by `ua_end_hash` or `ua_free_hash_state`.
#[derive(Debug)]
pub struct UaHashState {
    /// The hash.
    pub hash: StreamingHash,
}
