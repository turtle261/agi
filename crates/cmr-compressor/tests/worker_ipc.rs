use std::io::{BufReader, BufWriter};
use std::process::{Command, Stdio};

use cmr_core::compressor_ipc::{CompressorRequest, CompressorResponse, read_frame, write_frame};

#[test]
fn compressor_worker_handles_health_and_metric_requests() {
    let bin = env!("CARGO_BIN_EXE_cmr-compressor");
    let mut child = Command::new(bin)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("spawn worker");
    let mut stdin = BufWriter::new(child.stdin.take().expect("stdin"));
    let mut stdout = BufReader::new(child.stdout.take().expect("stdout"));

    write_frame(&mut stdin, &CompressorRequest::Health).expect("send health");
    let health: CompressorResponse = read_frame(&mut stdout, 1024 * 1024).expect("read health");
    assert!(matches!(health, CompressorResponse::Health { ok: true }));

    write_frame(
        &mut stdin,
        &CompressorRequest::IntrinsicDependence {
            data: b"aaaaabbbbbcccccdddddeeeee".to_vec(),
            max_order: 8,
        },
    )
    .expect("send id");
    let id: CompressorResponse = read_frame(&mut stdout, 1024 * 1024).expect("read id");
    let id_value = match id {
        CompressorResponse::IntrinsicDependence { value } => value,
        other => panic!("unexpected response: {other:?}"),
    };
    assert!(id_value.is_finite());
    assert!((0.0..=1.0).contains(&id_value));

    write_frame(
        &mut stdin,
        &CompressorRequest::CompressionDistance {
            left: b"abcabcabc".to_vec(),
            right: b"abcxyzabc".to_vec(),
        },
    )
    .expect("send distance");
    let distance: CompressorResponse = read_frame(&mut stdout, 1024 * 1024).expect("read distance");
    let distance_value = match distance {
        CompressorResponse::CompressionDistance { value } => value,
        other => panic!("unexpected response: {other:?}"),
    };
    assert!(distance_value.is_finite());

    write_frame(
        &mut stdin,
        &CompressorRequest::BatchCompressionDistance {
            target: b"planet jupiter".to_vec(),
            candidates: vec![
                b"planet saturn".to_vec(),
                b"planet mars".to_vec(),
                b"random noise text".to_vec(),
            ],
        },
    )
    .expect("send batch distance");
    let batch: CompressorResponse = read_frame(&mut stdout, 1024 * 1024).expect("read batch");
    let values = match batch {
        CompressorResponse::BatchCompressionDistance { values } => values,
        other => panic!("unexpected response: {other:?}"),
    };
    assert_eq!(values.len(), 3);
    assert!(values.iter().all(|v| v.is_finite()));

    drop(stdin);
    let status = child.wait().expect("wait child");
    assert!(status.success());
}
