//! Isolated compressor worker process.

use std::io::{BufReader, BufWriter};

use cmr_core::compressor_ipc::{
    CompressorRequest, CompressorResponse, DEFAULT_MAX_FRAME_BYTES, IpcError, read_frame,
    write_frame,
};
use infotheory::{InfotheoryCtx, NcdVariant};

fn main() {
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    let mut reader = BufReader::new(stdin.lock());
    let mut writer = BufWriter::new(stdout.lock());
    let ctx = InfotheoryCtx::default();

    loop {
        let req = match read_frame::<CompressorRequest>(&mut reader, DEFAULT_MAX_FRAME_BYTES) {
            Ok(req) => req,
            Err(IpcError::Io(err)) if err.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Err(err) => {
                let _ = write_frame(
                    &mut writer,
                    &CompressorResponse::Error {
                        message: format!("invalid request: {err}"),
                    },
                );
                break;
            }
        };

        let resp = handle_request(&ctx, req);
        if write_frame(&mut writer, &resp).is_err() {
            break;
        }
    }
}

fn handle_request(ctx: &InfotheoryCtx, req: CompressorRequest) -> CompressorResponse {
    match req {
        CompressorRequest::Health => CompressorResponse::Health { ok: true },
        CompressorRequest::NcdSym { left, right } => CompressorResponse::NcdSym {
            value: ctx.ncd_bytes(&left, &right, NcdVariant::SymVitanyi),
        },
        CompressorRequest::CompressionDistance { left, right } => {
            CompressorResponse::CompressionDistance {
                value: compression_distance(ctx, &left, &right),
            }
        }
        CompressorRequest::IntrinsicDependence { data, max_order } => {
            CompressorResponse::IntrinsicDependence {
                value: ctx.intrinsic_dependence_bytes(&data, max_order),
            }
        }
        CompressorRequest::BatchNcdSym { target, candidates } => {
            let values = candidates
                .iter()
                .map(|candidate| ctx.ncd_bytes(&target, candidate, NcdVariant::SymVitanyi))
                .collect();
            CompressorResponse::BatchNcdSym { values }
        }
        CompressorRequest::BatchCompressionDistance { target, candidates } => {
            let values = candidates
                .iter()
                .map(|candidate| compression_distance(ctx, &target, candidate))
                .collect();
            CompressorResponse::BatchCompressionDistance { values }
        }
    }
}

fn compression_distance(ctx: &InfotheoryCtx, left: &[u8], right: &[u8]) -> f64 {
    let c_left = ctx.compress_size(left) as f64;
    let c_right = ctx.compress_size(right) as f64;
    let c_xy = ctx.compress_size_chain(&[left, right]) as f64;
    let c_yx = ctx.compress_size_chain(&[right, left]) as f64;
    (c_xy - c_left) + (c_yx - c_right)
}
