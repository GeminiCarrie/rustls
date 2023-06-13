use crate::crypto;
use ring;

pub(crate) struct Hmac(&'static ring::hmac::Algorithm);

pub(crate) static HMAC_SHA256: Hmac = Hmac(&ring::hmac::HMAC_SHA256);
pub(crate) static HMAC_SHA384: Hmac = Hmac(&ring::hmac::HMAC_SHA384);
#[cfg(test)]
pub(crate) static HMAC_SHA512: Hmac = Hmac(&ring::hmac::HMAC_SHA512);

impl From<ring::hmac::Tag> for crypto::hmac::Tag {
    fn from(val: ring::hmac::Tag) -> Self {
        Self::new(val.as_ref())
    }
}

impl crypto::hmac::Hmac for Hmac {
    fn open_key(&self, key: &[u8]) -> Box<dyn crypto::hmac::Key> {
        Box::new(Key(ring::hmac::Key::new(*self.0, key)))
    }

    fn hash_output_len(&self) -> usize {
        self.0.digest_algorithm().output_len
    }
}

struct Key(ring::hmac::Key);

impl crypto::hmac::Key for Key {
    fn one_shot(&self, data: &[u8]) -> crypto::hmac::Tag {
        ring::hmac::sign(&self.0, data).into()
    }

    fn start(&self) -> Box<dyn crypto::hmac::Incremental> {
        Box::new(Incremental(ring::hmac::Context::with_key(&self.0)))
    }

    fn tag_len(&self) -> usize {
        self.0
            .algorithm()
            .digest_algorithm()
            .output_len
    }
}

struct Incremental(ring::hmac::Context);

impl crypto::hmac::Incremental for Incremental {
    fn update(mut self: Box<Self>, data: &[u8]) -> Box<dyn crypto::hmac::Incremental> {
        self.0.update(data);
        self
    }

    fn finish(self: Box<Self>) -> crypto::hmac::Tag {
        self.0.sign().into()
    }
}
