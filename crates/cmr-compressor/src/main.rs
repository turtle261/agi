//! Isolated compressor worker process.

use std::io::{BufReader, BufWriter};

use cmr_core::compressor_ipc::{
    CompressorRequest, CompressorResponse, DEFAULT_MAX_FRAME_BYTES, IpcError, read_frame,
    write_frame,
};
use infotheory::InfotheoryCtx;

fn main() {
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    let mut reader = BufReader::new(stdin.lock());
    let mut writer = BufWriter::new(stdout.lock());
    let zpaq_method = resolve_zpaq_method(std::env::args().skip(1));
    let ctx = InfotheoryCtx::with_zpaq(zpaq_method);

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

fn resolve_zpaq_method(args: impl Iterator<Item = String>) -> String {
    let mut method_from_args: Option<String> = None;
    let mut pending_method = false;
    for arg in args {
        if pending_method {
            if !arg.is_empty() {
                method_from_args = Some(arg);
            }
            pending_method = false;
            continue;
        }
        if let Some(value) = arg.strip_prefix("--zpaq-method=") {
            if !value.is_empty() {
                method_from_args = Some(value.to_owned());
            }
            continue;
        }
        if arg == "--zpaq-method" {
            pending_method = true;
        }
    }

    method_from_args
        .or_else(|| std::env::var("CMR_ZPAQ_METHOD").ok())
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| "5".to_owned())
}

fn handle_request(ctx: &InfotheoryCtx, req: CompressorRequest) -> CompressorResponse {
    match req {
        CompressorRequest::Health => CompressorResponse::Health { ok: true },
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
