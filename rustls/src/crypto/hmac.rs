/// A concrete HMAC implementation, reified with a hash function.
pub(crate) trait Hmac: Send + Sync {
    /// Prepare to use `key` as a HMAC key.
    fn open_key(&self, key: &[u8]) -> Box<dyn Key>;

    /// Give the length of the underlying hash function.  In RFC2104 terminology this is `L`.
    fn hash_output_len(&self) -> usize;
}

/// Maximum supported HMAC tag size: supports up to SHA512.
pub(crate) const HMAC_MAX_TAG: usize = 64;

/// A HMAC tag, stored as a value.
#[derive(Clone)]
pub(crate) struct Tag {
    buf: [u8; HMAC_MAX_TAG],
    used: usize,
}

impl Tag {
    pub(crate) fn new(bytes: &[u8]) -> Self {
        let mut tag = Self {
            buf: [0u8; HMAC_MAX_TAG],
            used: bytes.len(),
        };
        tag.buf[..bytes.len()].copy_from_slice(bytes);
        tag
    }
}

impl AsRef<[u8]> for Tag {
    fn as_ref(&self) -> &[u8] {
        &self.buf[..self.used]
    }
}

pub(crate) trait Key: Send + Sync {
    /// Calculates a tag over `data`.
    fn one_shot(&self, data: &[u8]) -> Tag;

    /// Starts a new incremental HMAC computation.
    fn start(&self) -> Box<dyn Incremental>;

    /// Returns the length of the tag returned by a computation using
    /// this key.
    fn tag_len(&self) -> usize;
}

pub(crate) trait Incremental {
    /// Add `data` to computation.
    fn update(self: Box<Self>, data: &[u8]) -> Box<dyn Incremental>;

    /// Finish the computation, returning the resulting tag.
    fn finish(self: Box<Self>) -> Tag;
}
