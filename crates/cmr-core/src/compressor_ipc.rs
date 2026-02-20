//! IPC protocol for compressor isolation.

use std::io::{Read, Write};

use serde::{Deserialize, Serialize, de::DeserializeOwned};
use thiserror::Error;

/// Maximum message frame size used by default helpers.
pub const DEFAULT_MAX_FRAME_BYTES: usize = 8 * 1024 * 1024;

/// Compressor RPC request.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum CompressorRequest {
    /// Liveness check.
    Health,
    /// Compute symmetric NCD-like distance.
    NcdSym {
        /// Left payload.
        left: Vec<u8>,
        /// Right payload.
        right: Vec<u8>,
    },
    /// Compute CMR Section 3.2 compression distance:
    /// C(XY)-C(X) + C(YX)-C(Y).
    CompressionDistance {
        /// Left payload (X).
        left: Vec<u8>,
        /// Right payload (Y).
        right: Vec<u8>,
    },
    /// Compute intrinsic dependence of a sequence.
    IntrinsicDependence {
        /// Payload.
        data: Vec<u8>,
        /// Estimator max order.
        max_order: i64,
    },
    /// Compute distances from one payload to many candidates.
    BatchNcdSym {
        /// Target payload.
        target: Vec<u8>,
        /// Candidate payloads.
        candidates: Vec<Vec<u8>>,
    },
    /// Compute CMR distances from one payload to many candidates.
    BatchCompressionDistance {
        /// Target payload.
        target: Vec<u8>,
        /// Candidate payloads.
        candidates: Vec<Vec<u8>>,
    },
}

/// Compressor RPC response.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum CompressorResponse {
    /// Liveness check response.
    Health { ok: bool },
    /// Scalar distance.
    NcdSym { value: f64 },
    /// Scalar CMR distance.
    CompressionDistance { value: f64 },
    /// Scalar intrinsic-dependence value.
    IntrinsicDependence { value: f64 },
    /// Batch distances.
    BatchNcdSym { values: Vec<f64> },
    /// Batch CMR distances.
    BatchCompressionDistance { values: Vec<f64> },
    /// Error response from worker.
    Error { message: String },
}

/// IPC transport errors.
#[derive(Debug, Error)]
pub enum IpcError {
    /// Underlying I/O failure.
    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),
    /// Serde codec failure.
    #[error("serde error: {0}")]
    Serde(#[from] serde_json::Error),
    /// Length-prefix exceeds bounds.
    #[error("frame exceeds max length")]
    FrameTooLarge,
}

/// Writes a length-prefixed JSON frame.
pub fn write_frame<T: Serialize>(writer: &mut impl Write, value: &T) -> Result<(), IpcError> {
    let payload = serde_json::to_vec(value)?;
    let len = u32::try_from(payload.len()).map_err(|_| IpcError::FrameTooLarge)?;
    writer.write_all(&len.to_be_bytes())?;
    writer.write_all(&payload)?;
    writer.flush()?;
    Ok(())
}

/// Reads a length-prefixed JSON frame.
pub fn read_frame<T: DeserializeOwned>(
    reader: &mut impl Read,
    max_bytes: usize,
) -> Result<T, IpcError> {
    let mut len_buf = [0_u8; 4];
    reader.read_exact(&mut len_buf)?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > max_bytes {
        return Err(IpcError::FrameTooLarge);
    }
    let mut payload = vec![0_u8; len];
    reader.read_exact(&mut payload)?;
    Ok(serde_json::from_slice(&payload)?)
}
