use ring::{aead, hkdf};
use crate::msgs::codec;
use crate::msgs::codec::Codec;
use crate::msgs::enums::{ContentType, ProtocolVersion};
use crate::msgs::message::{BorrowMessage, Message, MessagePayload};
use crate::msgs::fragmenter::MAX_FRAGMENT_LEN;
use crate::error::TLSError;
use crate::suites::SupportedCipherSuite;
use crate::key_schedule::{derive_traffic_key, derive_traffic_iv};

/// Objects with this trait can decrypt TLS messages.
pub trait MessageDecrypter : Send + Sync {
    fn decrypt(&self, m: Message, seq: u64) -> Result<Message, TLSError>;
}

/// Objects with this trait can encrypt TLS messages.
pub trait MessageEncrypter : Send + Sync {
    fn encrypt(&self, m: BorrowMessage, seq: u64) -> Result<Message, TLSError>;
}

impl dyn MessageEncrypter {
    pub fn invalid() -> Box<dyn MessageEncrypter> {
        Box::new(InvalidMessageEncrypter {})
    }
}

impl dyn MessageDecrypter {
    pub fn invalid() -> Box<dyn MessageDecrypter> {
        Box::new(InvalidMessageDecrypter {})
    }
}

pub fn new_tls13_read(scs: &'static SupportedCipherSuite,
                      secret: &hkdf::Prk) -> Box<dyn MessageDecrypter> {
    let key = derive_traffic_key(secret, scs.get_aead_alg());
    let iv = derive_traffic_iv(secret);

    Box::new(TLS13MessageDecrypter::new(key, iv))
}

pub fn new_tls13_write(scs: &'static SupportedCipherSuite,
                       secret: &hkdf::Prk) -> Box<dyn MessageEncrypter> {
    let key = derive_traffic_key(secret, scs.get_aead_alg());
    let iv = derive_traffic_iv(secret);

    Box::new(TLS13MessageEncrypter::new(key, iv))
}

/// A TLS 1.3 write or read IV.
pub(crate) struct Iv([u8; ring::aead::NONCE_LEN]);

impl Iv {

    #[cfg(test)]
    pub(crate) fn value(&self) -> &[u8; 12] { &self.0 }
}

pub(crate) struct IvLen;

impl hkdf::KeyType for IvLen {
    fn len(&self) -> usize { aead::NONCE_LEN }
}

impl From<hkdf::Okm<'_, IvLen>> for Iv {
    fn from(okm: hkdf::Okm<IvLen>) -> Self {
        let mut r = Iv(Default::default());
        okm.fill(&mut r.0[..]).unwrap();
        r
    }
}

struct TLS13MessageEncrypter {
    enc_key: aead::LessSafeKey,
    iv: Iv,
}

struct TLS13MessageDecrypter {
    dec_key: aead::LessSafeKey,
    iv: Iv,
}

fn unpad_tls13(v: &mut Vec<u8>) -> ContentType {
    loop {
        match v.pop() {
            Some(0) => {}

            Some(content_type) => return ContentType::read_bytes(&[content_type]).unwrap(),

            None => return ContentType::Unknown(0),
        }
    }
}

fn make_tls13_nonce(iv: &Iv, seq: u64) -> ring::aead::Nonce {
    let mut nonce = [0u8; ring::aead::NONCE_LEN];
    codec::put_u64(seq, &mut nonce[4..]);

    nonce.iter_mut().zip(iv.0.iter()).for_each(|(nonce, iv)| {
        *nonce ^= *iv;
    });

    aead::Nonce::assume_unique_for_key(nonce)
}

fn make_tls13_aad(len: usize) -> ring::aead::Aad<[u8; 1 + 2 + 2]>{
    ring::aead::Aad::from([
        0x17, // ContentType::ApplicationData
        0x3, // ProtocolVersion (major)
        0x3, // ProtocolVersion (minor)
        (len >> 8) as u8,
        len as u8,
    ])
}

impl MessageEncrypter for TLS13MessageEncrypter {
    fn encrypt(&self, msg: BorrowMessage, seq: u64) -> Result<Message, TLSError> {
        let total_len = msg.payload.len() + 1 + self.enc_key.algorithm().tag_len();
        let mut buf = Vec::with_capacity(total_len);
        buf.extend_from_slice(&msg.payload);
        msg.typ.encode(&mut buf);

        let nonce = make_tls13_nonce(&self.iv, seq);
        let aad = make_tls13_aad(total_len);

        self.enc_key.seal_in_place_append_tag(nonce, aad, &mut buf)
            .map_err(|_| TLSError::General("encrypt failed".to_string()))?;

        Ok(Message {
            typ: ContentType::ApplicationData,
            version: ProtocolVersion::TLSv1_2,
            payload: MessagePayload::new_opaque(buf),
        })
    }
}

impl MessageDecrypter for TLS13MessageDecrypter {
    fn decrypt(&self, mut msg: Message, seq: u64) -> Result<Message, TLSError> {
        let payload = msg.take_opaque_payload()
            .ok_or(TLSError::DecryptError)?;
        let mut buf = payload.0;

        if buf.len() < self.dec_key.algorithm().tag_len() {
            return Err(TLSError::DecryptError);
        }

        let nonce = make_tls13_nonce(&self.iv, seq);
        let aad = make_tls13_aad(buf.len());
        let plain_len = self.dec_key.open_in_place(nonce, aad, &mut buf)
            .map_err(|_| TLSError::DecryptError)?
            .len();

        buf.truncate(plain_len);

        if buf.len() > MAX_FRAGMENT_LEN + 1 {
            return Err(TLSError::PeerSentOversizedRecord);
        }

        let content_type = unpad_tls13(&mut buf);
        if content_type == ContentType::Unknown(0) {
            let msg = "peer sent bad TLSInnerPlaintext".to_string();
            return Err(TLSError::PeerMisbehavedError(msg));
        }

        if buf.len() > MAX_FRAGMENT_LEN {
            return Err(TLSError::PeerSentOversizedRecord);
        }

        Ok(Message {
            typ: content_type,
            version: ProtocolVersion::TLSv1_3,
            payload: MessagePayload::new_opaque(buf),
        })
    }
}

impl TLS13MessageEncrypter {
    fn new(key: aead::UnboundKey, enc_iv: Iv) -> TLS13MessageEncrypter {
        TLS13MessageEncrypter {
            enc_key: aead::LessSafeKey::new(key),
            iv: enc_iv,
        }
    }
}

impl TLS13MessageDecrypter {
    fn new(key: aead::UnboundKey, dec_iv: Iv) -> TLS13MessageDecrypter {
        TLS13MessageDecrypter {
            dec_key: aead::LessSafeKey::new(key),
            iv: dec_iv,
        }
    }
}

/// A `MessageEncrypter` which doesn't work.
pub struct InvalidMessageEncrypter {}

impl MessageEncrypter for InvalidMessageEncrypter {
    fn encrypt(&self, _m: BorrowMessage, _seq: u64) -> Result<Message, TLSError> {
        Err(TLSError::General("encrypt not yet available".to_string()))
    }
}

/// A `MessageDecrypter` which doesn't work.
pub struct InvalidMessageDecrypter {}

impl MessageDecrypter for InvalidMessageDecrypter {
    fn decrypt(&self, _m: Message, _seq: u64) -> Result<Message, TLSError> {
        Err(TLSError::DecryptError)
    }
}
