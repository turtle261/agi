//! CMR protocol syntax and validation.

use std::cmp::Ordering;
use std::fmt::{Display, Formatter};

use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use thiserror::Error;
use time::{Month, OffsetDateTime};
use url::Url;

/// CMR transport channel.
#[derive(Clone, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub enum TransportKind {
    /// HTTP transport.
    Http,
    /// HTTPS transport.
    Https,
    /// SMTP transport.
    Smtp,
    /// UDP transport.
    Udp,
    /// SSH transport.
    Ssh,
    /// Other custom transport name.
    Other(String),
}

impl TransportKind {
    /// Returns true if this transport is authenticated/encrypted by design.
    #[must_use]
    pub fn is_secure_channel(&self) -> bool {
        matches!(self, Self::Https | Self::Ssh)
    }
}

/// Signature line.
#[derive(Clone, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub enum Signature {
    /// `0\r\n`
    Unsigned,
    /// `1` + lower-case HMAC-SHA-256 hex digest.
    Sha256([u8; 32]),
}

impl Signature {
    /// Encodes this signature as a protocol line without trailing CRLF.
    #[must_use]
    pub fn line_without_crlf(&self) -> String {
        match self {
            Self::Unsigned => "0".to_owned(),
            Self::Sha256(digest) => {
                let mut out = String::with_capacity(65);
                out.push('1');
                out.push_str(&hex::encode(digest));
                out
            }
        }
    }

    /// Returns true when this signature cryptographically validates.
    #[must_use]
    pub fn verifies(&self, payload_without_signature_line: &[u8], key: Option<&[u8]>) -> bool {
        match self {
            Self::Unsigned => true,
            Self::Sha256(expected) => {
                let Some(key) = key else {
                    return false;
                };
                let Ok(mut mac) = Hmac::<Sha256>::new_from_slice(key) else {
                    return false;
                };
                mac.update(payload_without_signature_line);
                let digest = mac.finalize().into_bytes();
                let mut actual = [0_u8; 32];
                actual.copy_from_slice(&digest[..32]);
                bool::from(actual.ct_eq(expected))
            }
        }
    }

    /// Creates a signed signature from key and payload.
    #[must_use]
    pub fn sign(payload_without_signature_line: &[u8], key: &[u8]) -> Self {
        let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC supports all key lengths");
        mac.update(payload_without_signature_line);
        let digest = mac.finalize().into_bytes();
        let mut out = [0_u8; 32];
        out.copy_from_slice(&digest[..32]);
        Self::Sha256(out)
    }
}

/// Timestamp with unbounded fractional precision.
#[derive(Clone, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct CmrTimestamp {
    year: u16,
    month: u8,
    day: u8,
    hour: u8,
    minute: u8,
    second: u8,
    fraction: String,
}

impl CmrTimestamp {
    /// Creates a current UTC timestamp with nanosecond precision.
    #[must_use]
    pub fn now_utc() -> Self {
        let now = OffsetDateTime::now_utc();
        let fraction = format!("{:09}", now.nanosecond())
            .trim_end_matches('0')
            .to_owned();
        Self {
            year: u16::try_from(now.year()).unwrap_or(0),
            month: now.month() as u8,
            day: now.day(),
            hour: now.hour(),
            minute: now.minute(),
            second: now.second(),
            fraction,
        }
    }

    /// Parses CMR timestamp syntax.
    pub fn parse(input: &str) -> Result<Self, ParseError> {
        if input.len() < 19 {
            return Err(ParseError::InvalidTimestamp(input.to_owned()));
        }
        let year = parse_dec_u16(&input[0..4], "year", input)?;
        if input.as_bytes().get(4) != Some(&b'/') {
            return Err(ParseError::InvalidTimestamp(input.to_owned()));
        }
        let month = parse_dec_u8(&input[5..7], "month", input)?;
        if input.as_bytes().get(7) != Some(&b'/') {
            return Err(ParseError::InvalidTimestamp(input.to_owned()));
        }
        let day = parse_dec_u8(&input[8..10], "day", input)?;
        if input.as_bytes().get(10) != Some(&b' ') {
            return Err(ParseError::InvalidTimestamp(input.to_owned()));
        }
        let hour = parse_dec_u8(&input[11..13], "hour", input)?;
        if input.as_bytes().get(13) != Some(&b':') {
            return Err(ParseError::InvalidTimestamp(input.to_owned()));
        }
        let minute = parse_dec_u8(&input[14..16], "minute", input)?;
        if input.as_bytes().get(16) != Some(&b':') {
            return Err(ParseError::InvalidTimestamp(input.to_owned()));
        }
        let second = parse_dec_u8(&input[17..19], "second", input)?;
        let fraction = if input.len() == 19 {
            String::new()
        } else {
            if input.as_bytes().get(19) != Some(&b'.') {
                return Err(ParseError::InvalidTimestamp(input.to_owned()));
            }
            let frac = &input[20..];
            if frac.is_empty() || !frac.bytes().all(|b| b.is_ascii_digit()) {
                return Err(ParseError::InvalidTimestamp(input.to_owned()));
            }
            frac.to_owned()
        };
        validate_calendar_parts(year, month, day, hour, minute, second, input)?;
        Ok(Self {
            year,
            month,
            day,
            hour,
            minute,
            second,
            fraction,
        })
    }

    /// Returns a clone with fractional seconds replaced.
    #[must_use]
    pub fn with_fraction(mut self, fraction: String) -> Self {
        self.fraction = fraction;
        self
    }

    /// Returns true when this timestamp is newer than `other`.
    #[must_use]
    pub fn is_newer_than(&self, other: &Self) -> bool {
        self > other
    }
}

impl Display for CmrTimestamp {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{:04}/{:02}/{:02} {:02}:{:02}:{:02}",
            self.year, self.month, self.day, self.hour, self.minute, self.second
        )?;
        if !self.fraction.is_empty() {
            write!(f, ".{}", self.fraction)?;
        }
        Ok(())
    }
}

impl Ord for CmrTimestamp {
    fn cmp(&self, other: &Self) -> Ordering {
        let cmp_tuple = (
            self.year,
            self.month,
            self.day,
            self.hour,
            self.minute,
            self.second,
        )
            .cmp(&(
                other.year,
                other.month,
                other.day,
                other.hour,
                other.minute,
                other.second,
            ));
        if cmp_tuple != Ordering::Equal {
            return cmp_tuple;
        }
        compare_fractional_decimal(&self.fraction, &other.fraction)
    }
}

impl PartialOrd for CmrTimestamp {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// Message identifier line (timestamp + sender address).
#[derive(Clone, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct MessageId {
    /// Send timestamp.
    pub timestamp: CmrTimestamp,
    /// Sender address.
    pub address: String,
}

impl MessageId {
    /// Parses an ID line (without trailing CRLF).
    pub fn parse(input: &str) -> Result<Self, ParseError> {
        let split_at = input
            .char_indices()
            .skip(19)
            .find_map(|(idx, ch)| (ch == ' ').then_some(idx))
            .ok_or_else(|| ParseError::InvalidMessageId(input.to_owned()))?;
        let ts = &input[..split_at];
        let address = &input[(split_at + 1)..];
        if address.is_empty() || address.contains('\r') || address.contains('\n') {
            return Err(ParseError::InvalidMessageId(input.to_owned()));
        }
        if let Some(parsed) = address
            .contains("://")
            .then(|| Url::parse(address))
            .transpose()
            .map_err(|_| ParseError::InvalidAddress(address.to_owned()))?
            && parsed.scheme().is_empty()
        {
            return Err(ParseError::InvalidAddress(address.to_owned()));
        }
        Ok(Self {
            timestamp: CmrTimestamp::parse(ts)?,
            address: address.to_owned(),
        })
    }

    /// Formats the ID line without trailing CRLF.
    #[must_use]
    pub fn line_without_crlf(&self) -> String {
        format!("{} {}", self.timestamp, self.address)
    }
}

impl Display for MessageId {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} {}", self.timestamp, self.address)
    }
}

/// Parsed CMR message.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CmrMessage {
    /// Signature line.
    pub signature: Signature,
    /// Routing header IDs, newest to oldest.
    pub header: Vec<MessageId>,
    /// Message body.
    pub body: Vec<u8>,
}

impl CmrMessage {
    /// Returns the immediate sender address.
    #[must_use]
    pub fn immediate_sender(&self) -> &str {
        self.header.first().map_or("", |id| id.address.as_str())
    }

    /// Returns the origin ID (oldest header entry).
    #[must_use]
    pub fn origin_id(&self) -> Option<&MessageId> {
        self.header.last()
    }

    /// Returns serialized header + body (without signature line).
    #[must_use]
    pub fn payload_without_signature_line(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.encoded_len().saturating_sub(4));
        for id in &self.header {
            out.extend_from_slice(id.line_without_crlf().as_bytes());
            out.extend_from_slice(b"\r\n");
        }
        out.extend_from_slice(b"\r\n");
        out.extend_from_slice(self.body.len().to_string().as_bytes());
        out.extend_from_slice(b"\r\n");
        out.extend_from_slice(&self.body);
        out
    }

    /// Encodes the message into protocol wire bytes.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.encoded_len());
        out.extend_from_slice(self.signature.line_without_crlf().as_bytes());
        out.extend_from_slice(b"\r\n");
        out.extend_from_slice(&self.payload_without_signature_line());
        out
    }

    /// Returns encoded byte length.
    #[must_use]
    pub fn encoded_len(&self) -> usize {
        let header_len: usize = self
            .header
            .iter()
            .map(|id| id.line_without_crlf().len() + 2)
            .sum();
        self.signature.line_without_crlf().len()
            + 2
            + header_len
            + 2
            + self.body.len().to_string().len()
            + 2
            + self.body.len()
    }

    /// Removes signature line.
    pub fn make_unsigned(&mut self) {
        self.signature = Signature::Unsigned;
    }

    /// Signs message with pairwise key.
    pub fn sign_with_key(&mut self, key: &[u8]) {
        self.signature = Signature::sign(&self.payload_without_signature_line(), key);
    }

    /// Prepends a new route hop.
    pub fn prepend_hop(&mut self, hop: MessageId) {
        self.header.insert(0, hop);
    }
}

/// Parse-time validation context.
#[derive(Clone, Debug)]
pub struct ParseContext<'a> {
    /// "Current time" used for future timestamp checks.
    pub now: CmrTimestamp,
    /// Recipient address; if present, this address cannot appear in the header.
    pub recipient_address: Option<&'a str>,
    /// Maximum allowed message byte length.
    pub max_message_bytes: usize,
    /// Maximum allowed header entries.
    pub max_header_ids: usize,
    /// Allows legacy v2.2 example line format (64-hex digest without `1` prefix).
    pub allow_legacy_v1_without_prefix: bool,
}

impl<'a> ParseContext<'a> {
    /// Creates a context with secure defaults.
    #[must_use]
    pub fn secure(now: CmrTimestamp, recipient_address: Option<&'a str>) -> Self {
        Self {
            now,
            recipient_address,
            max_message_bytes: 4 * 1024 * 1024,
            max_header_ids: 1024,
            allow_legacy_v1_without_prefix: false,
        }
    }
}

/// Protocol parse error.
#[derive(Debug, Error)]
pub enum ParseError {
    /// Message exceeds parser limit.
    #[error("message exceeds configured size limit")]
    TooLarge,
    /// Non-UTF-8 line where text is required.
    #[error("line is not valid utf-8")]
    NonUtf8Line,
    /// Invalid signature line.
    #[error("invalid signature line")]
    InvalidSignature,
    /// Invalid timestamp syntax/value.
    #[error("invalid timestamp `{0}`")]
    InvalidTimestamp(String),
    /// Invalid message ID line.
    #[error("invalid message id `{0}`")]
    InvalidMessageId(String),
    /// Invalid address in message ID.
    #[error("invalid address `{0}`")]
    InvalidAddress(String),
    /// Recipient address appears in header.
    #[error("recipient address appears in routing header")]
    RecipientAddressInHeader,
    /// Header addresses must be unique.
    #[error("duplicate address in routing header")]
    DuplicateAddress,
    /// Header timestamps must strictly descend.
    #[error("routing header timestamps are not strictly descending")]
    NonDescendingTimestamps,
    /// Header timestamp is in the future.
    #[error("routing header contains future timestamp")]
    FutureTimestamp,
    /// Missing header.
    #[error("routing header is empty")]
    EmptyHeader,
    /// Missing CRLF where required.
    #[error("malformed CRLF sequence")]
    MissingCrlf,
    /// Invalid length line.
    #[error("invalid body length field")]
    InvalidBodyLength,
    /// Body length mismatch.
    #[error("body length mismatch")]
    BodyLengthMismatch,
    /// Too many header IDs.
    #[error("too many header entries")]
    TooManyHeaderIds,
}

/// Parses and validates a wire-format CMR message.
pub fn parse_message(input: &[u8], ctx: &ParseContext<'_>) -> Result<CmrMessage, ParseError> {
    if input.len() > ctx.max_message_bytes {
        return Err(ParseError::TooLarge);
    }
    let (sig_line, mut rest) = take_crlf_line(input)?;
    let sig_line = std::str::from_utf8(sig_line).map_err(|_| ParseError::NonUtf8Line)?;
    let signature = parse_signature_line(sig_line, ctx.allow_legacy_v1_without_prefix)?;

    let mut header = Vec::new();
    loop {
        let (line, r) = take_crlf_line(rest)?;
        rest = r;
        if line.is_empty() {
            break;
        }
        if header.len() >= ctx.max_header_ids {
            return Err(ParseError::TooManyHeaderIds);
        }
        let line = std::str::from_utf8(line).map_err(|_| ParseError::NonUtf8Line)?;
        header.push(MessageId::parse(line)?);
    }
    if header.is_empty() {
        return Err(ParseError::EmptyHeader);
    }
    validate_header(&header, ctx)?;

    let (len_line, body_bytes) = take_crlf_line(rest)?;
    let len_line = std::str::from_utf8(len_line).map_err(|_| ParseError::NonUtf8Line)?;
    if len_line.is_empty() || !len_line.bytes().all(|b| b.is_ascii_digit()) {
        return Err(ParseError::InvalidBodyLength);
    }
    let body_len = len_line
        .parse::<usize>()
        .map_err(|_| ParseError::InvalidBodyLength)?;
    if body_len > ctx.max_message_bytes {
        return Err(ParseError::TooLarge);
    }
    if body_bytes.len() != body_len {
        return Err(ParseError::BodyLengthMismatch);
    }

    Ok(CmrMessage {
        signature,
        header,
        body: body_bytes.to_vec(),
    })
}

fn parse_signature_line(
    line: &str,
    allow_legacy_v1_without_prefix: bool,
) -> Result<Signature, ParseError> {
    if line == "0" {
        return Ok(Signature::Unsigned);
    }
    if line.len() == 65 && line.starts_with('1') && is_lower_hex(&line[1..]) {
        let mut digest = [0_u8; 32];
        hex::decode_to_slice(&line[1..], &mut digest).map_err(|_| ParseError::InvalidSignature)?;
        return Ok(Signature::Sha256(digest));
    }
    if allow_legacy_v1_without_prefix && line.len() == 64 && is_lower_hex(line) {
        let mut digest = [0_u8; 32];
        hex::decode_to_slice(line, &mut digest).map_err(|_| ParseError::InvalidSignature)?;
        return Ok(Signature::Sha256(digest));
    }
    Err(ParseError::InvalidSignature)
}

fn validate_header(header: &[MessageId], ctx: &ParseContext<'_>) -> Result<(), ParseError> {
    let mut addresses = std::collections::HashSet::<&str>::with_capacity(header.len());
    for (idx, id) in header.iter().enumerate() {
        if Some(id.address.as_str()) == ctx.recipient_address {
            return Err(ParseError::RecipientAddressInHeader);
        }
        if !addresses.insert(id.address.as_str()) {
            return Err(ParseError::DuplicateAddress);
        }
        if id.timestamp > ctx.now {
            return Err(ParseError::FutureTimestamp);
        }
        if idx > 0 && id.timestamp >= header[idx - 1].timestamp {
            return Err(ParseError::NonDescendingTimestamps);
        }
    }
    Ok(())
}

fn take_crlf_line(mut input: &[u8]) -> Result<(&[u8], &[u8]), ParseError> {
    let mut i = 0;
    while i + 1 < input.len() {
        if input[i] == b'\r' {
            if input[i + 1] != b'\n' {
                return Err(ParseError::MissingCrlf);
            }
            let line = &input[..i];
            input = &input[(i + 2)..];
            return Ok((line, input));
        }
        i += 1;
    }
    Err(ParseError::MissingCrlf)
}

fn parse_dec_u16(input: &str, _field: &str, full: &str) -> Result<u16, ParseError> {
    if input.len() != 4 || !input.bytes().all(|b| b.is_ascii_digit()) {
        return Err(ParseError::InvalidTimestamp(full.to_owned()));
    }
    input
        .parse::<u16>()
        .map_err(|_| ParseError::InvalidTimestamp(full.to_owned()))
}

fn parse_dec_u8(input: &str, _field: &str, full: &str) -> Result<u8, ParseError> {
    if input.len() != 2 || !input.bytes().all(|b| b.is_ascii_digit()) {
        return Err(ParseError::InvalidTimestamp(full.to_owned()));
    }
    input
        .parse::<u8>()
        .map_err(|_| ParseError::InvalidTimestamp(full.to_owned()))
}

fn validate_calendar_parts(
    year: u16,
    month: u8,
    day: u8,
    hour: u8,
    minute: u8,
    second: u8,
    full: &str,
) -> Result<(), ParseError> {
    if hour > 23 || minute > 59 || second > 59 {
        return Err(ParseError::InvalidTimestamp(full.to_owned()));
    }
    let month =
        Month::try_from(month).map_err(|_| ParseError::InvalidTimestamp(full.to_owned()))?;
    let date = time::Date::from_calendar_date(i32::from(year), month, day)
        .map_err(|_| ParseError::InvalidTimestamp(full.to_owned()))?;
    let _ = date
        .with_hms(hour, minute, second)
        .map_err(|_| ParseError::InvalidTimestamp(full.to_owned()))?;
    Ok(())
}

fn compare_fractional_decimal(a: &str, b: &str) -> Ordering {
    let max_len = a.len().max(b.len());
    for i in 0..max_len {
        let ad = a.as_bytes().get(i).copied().unwrap_or(b'0');
        let bd = b.as_bytes().get(i).copied().unwrap_or(b'0');
        match ad.cmp(&bd) {
            Ordering::Equal => {}
            non_eq => return non_eq,
        }
    }
    Ordering::Equal
}

fn is_lower_hex(s: &str) -> bool {
    s.bytes()
        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx<'a>(recipient: Option<&'a str>) -> ParseContext<'a> {
        ParseContext::secure(
            CmrTimestamp::parse("2030/01/01 00:00:00").expect("valid time"),
            recipient,
        )
    }

    #[test]
    fn parse_round_trip_unsigned() {
        let raw = b"0\r\n2029/12/31 23:59:59 http://alice\r\n\r\n5\r\nhello";
        let parsed = parse_message(raw, &ctx(Some("http://bob"))).expect("parse");
        assert_eq!(parsed.signature, Signature::Unsigned);
        assert_eq!(parsed.header.len(), 1);
        assert_eq!(parsed.body, b"hello");
        assert_eq!(parsed.to_bytes(), raw);
    }

    #[test]
    fn signed_verification_matches() {
        let mut m = CmrMessage {
            signature: Signature::Unsigned,
            header: vec![MessageId::parse("2029/01/01 00:00:00 http://alice").expect("id")],
            body: b"abc".to_vec(),
        };
        m.sign_with_key(b"secret");
        let payload = m.payload_without_signature_line();
        assert!(m.signature.verifies(&payload, Some(b"secret")));
        assert!(!m.signature.verifies(&payload, Some(b"wrong")));
    }

    #[test]
    fn rejects_recipient_in_header() {
        let raw = b"0\r\n2029/12/31 23:59:59 http://bob\r\n\r\n0\r\n";
        let err = parse_message(raw, &ctx(Some("http://bob"))).expect_err("must fail");
        assert!(matches!(err, ParseError::RecipientAddressInHeader));
    }
}
