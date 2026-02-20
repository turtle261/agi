//! CMR key-exchange message parsing and arithmetic helpers.

use num_bigint::BigUint;
use num_traits::Num;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Parsed key exchange payload.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum KeyExchangeMessage {
    /// `RSA key exchange request=n,e.`
    RsaRequest { n: BigUint, e: BigUint },
    /// `RSA key exchange reply=c.`
    RsaReply { c: BigUint },
    /// `DH key exchange request=g,p,A.`
    DhRequest {
        /// Generator.
        g: BigUint,
        /// Prime modulus.
        p: BigUint,
        /// Public value from initiator.
        a_pub: BigUint,
    },
    /// `DH key exchange reply=B.`
    DhReply { b_pub: BigUint },
    /// `Clear key exchange=<hex>.`
    ClearKey { key: Vec<u8> },
}

/// Key exchange parse/encode error.
#[derive(Debug, Error)]
pub enum KeyExchangeError {
    /// Body is not UTF-8.
    #[error("key exchange body is not utf-8")]
    NonUtf8,
    /// Syntax is malformed.
    #[error("malformed key exchange body")]
    Malformed,
    /// Number is not lower-case hex.
    #[error("key exchange numbers must be lower-case hexadecimal")]
    NotLowerHex,
    /// Hex decoding failed.
    #[error("invalid hexadecimal payload")]
    HexDecode,
}

/// Parses a message body as key exchange payload.
///
/// Returns `Ok(None)` if this body is not a key exchange control payload.
pub fn parse_key_exchange(body: &[u8]) -> Result<Option<KeyExchangeMessage>, KeyExchangeError> {
    let Ok(text) = std::str::from_utf8(body) else {
        return Ok(None);
    };

    if let Some(rest) = text.strip_prefix("RSA key exchange request=") {
        let rest = rest.strip_suffix('.').ok_or(KeyExchangeError::Malformed)?;
        let (n_hex, e_hex) = rest.split_once(',').ok_or(KeyExchangeError::Malformed)?;
        let n = parse_biguint_hex(n_hex)?;
        let e = parse_biguint_hex(e_hex)?;
        return Ok(Some(KeyExchangeMessage::RsaRequest { n, e }));
    }
    if let Some(rest) = text.strip_prefix("RSA key exchange reply=") {
        let rest = rest.strip_suffix('.').ok_or(KeyExchangeError::Malformed)?;
        let c = parse_biguint_hex(rest)?;
        return Ok(Some(KeyExchangeMessage::RsaReply { c }));
    }
    if let Some(rest) = text.strip_prefix("DH key exchange request=") {
        let rest = rest.strip_suffix('.').ok_or(KeyExchangeError::Malformed)?;
        let mut parts = rest.split(',');
        let g = parse_biguint_hex(parts.next().ok_or(KeyExchangeError::Malformed)?)?;
        let p = parse_biguint_hex(parts.next().ok_or(KeyExchangeError::Malformed)?)?;
        let a_pub = parse_biguint_hex(parts.next().ok_or(KeyExchangeError::Malformed)?)?;
        if parts.next().is_some() {
            return Err(KeyExchangeError::Malformed);
        }
        return Ok(Some(KeyExchangeMessage::DhRequest { g, p, a_pub }));
    }
    if let Some(rest) = text.strip_prefix("DH key exchange reply=") {
        let rest = rest.strip_suffix('.').ok_or(KeyExchangeError::Malformed)?;
        let b_pub = parse_biguint_hex(rest)?;
        return Ok(Some(KeyExchangeMessage::DhReply { b_pub }));
    }
    if let Some(rest) = text.strip_prefix("Clear key exchange=") {
        let rest = rest.strip_suffix('.').ok_or(KeyExchangeError::Malformed)?;
        let key = parse_hex_bytes(rest)?;
        return Ok(Some(KeyExchangeMessage::ClearKey { key }));
    }

    Ok(None)
}

impl KeyExchangeMessage {
    /// Encodes key exchange payload text (no trailing CRLF).
    #[must_use]
    pub fn render(&self) -> String {
        match self {
            Self::RsaRequest { n, e } => {
                format!(
                    "RSA key exchange request={},{}.",
                    biguint_to_lower_hex(n),
                    biguint_to_lower_hex(e)
                )
            }
            Self::RsaReply { c } => format!("RSA key exchange reply={}.", biguint_to_lower_hex(c)),
            Self::DhRequest { g, p, a_pub } => format!(
                "DH key exchange request={},{},{}.",
                biguint_to_lower_hex(g),
                biguint_to_lower_hex(p),
                biguint_to_lower_hex(a_pub)
            ),
            Self::DhReply { b_pub } => {
                format!("DH key exchange reply={}.", biguint_to_lower_hex(b_pub))
            }
            Self::ClearKey { key } => format!("Clear key exchange={}.", hex::encode(key)),
        }
    }
}

/// Computes modular exponentiation.
#[must_use]
pub fn mod_pow(base: &BigUint, exp: &BigUint, modulus: &BigUint) -> BigUint {
    base.modpow(exp, modulus)
}

/// Converts lower-case hex to big integer.
pub fn parse_biguint_hex(s: &str) -> Result<BigUint, KeyExchangeError> {
    if s.is_empty() || !is_lower_hex(s) {
        return Err(KeyExchangeError::NotLowerHex);
    }
    BigUint::from_str_radix(s, 16).map_err(|_| KeyExchangeError::HexDecode)
}

/// Converts bytes encoded as lower-case hex.
pub fn parse_hex_bytes(s: &str) -> Result<Vec<u8>, KeyExchangeError> {
    if s.is_empty() || !s.len().is_multiple_of(2) || !is_lower_hex(s) {
        return Err(KeyExchangeError::NotLowerHex);
    }
    hex::decode(s).map_err(|_| KeyExchangeError::HexDecode)
}

/// Converts big integer to lower-case hex.
#[must_use]
pub fn biguint_to_lower_hex(value: &BigUint) -> String {
    let mut out = value.to_str_radix(16);
    if out.is_empty() {
        out.push('0');
    }
    out
}

fn is_lower_hex(s: &str) -> bool {
    s.bytes()
        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_and_render_clear() {
        let parsed = parse_key_exchange(b"Clear key exchange=666f6f.")
            .expect("parse")
            .expect("control");
        assert_eq!(
            parsed,
            KeyExchangeMessage::ClearKey {
                key: b"foo".to_vec()
            }
        );
        assert_eq!(parsed.render(), "Clear key exchange=666f6f.");
    }

    #[test]
    fn parse_rsa_request() {
        let msg = parse_key_exchange(b"RSA key exchange request=0f,11.")
            .expect("parse")
            .expect("control");
        match msg {
            KeyExchangeMessage::RsaRequest { n, e } => {
                assert_eq!(biguint_to_lower_hex(&n), "f");
                assert_eq!(biguint_to_lower_hex(&e), "11");
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn rejects_leading_or_trailing_whitespace() {
        assert!(
            parse_key_exchange(b" RSA key exchange reply=ff.")
                .expect("parse")
                .is_none()
        );
        assert!(parse_key_exchange(b"RSA key exchange reply=ff. ").is_err());
    }

    #[test]
    fn non_utf8_body_is_not_key_exchange_control() {
        assert_eq!(parse_key_exchange(&[0xff, 0xfe]).expect("parse"), None);
    }
}
