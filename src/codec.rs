use zstd_safe::{CCtx, CParameter, DCtx, DParameter};

/// Maximum windowLog supported (25 => 32 MiB window, covers 16 MiB base + 16 MiB body).
pub const MAX_WINDOW_LOG: u32 = 25;

#[derive(Debug)]
pub struct CodecError(pub String);

impl std::fmt::Display for CodecError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "codec error: {}", self.0)
    }
}

impl std::error::Error for CodecError {}

fn map_zstd_err(code: usize) -> CodecError {
    CodecError(zstd_safe::get_error_name(code).to_string())
}

/// Wire body ceiling for the receiver so a maximum-size raw payload plus zstd framing
/// overhead is never rejected with 413.
pub fn max_wire_body_bytes(max_raw_bytes: usize) -> usize {
    zstd_safe::compress_bound(max_raw_bytes).max(max_raw_bytes.saturating_add(131_072))
}

/// Compute minimum windowLog (clamped to 18..=MAX_WINDOW_LOG) that covers `total_bytes`.
fn required_window_log(total_bytes: usize) -> u32 {
    let needed = total_bytes.max(1 << 18);
    let mut log = 18u32;
    while (1usize << log) < needed && log < MAX_WINDOW_LOG {
        log += 1;
    }
    log
}

/// Compress `raw` standalone using zstd and shrink to an exact-sized boxed slice
/// (no wasted compress_bound spare capacity retained in cache!).
pub fn compress_standalone(raw: &[u8], level: i32) -> Result<Box<[u8]>, CodecError> {
    let mut cctx = CCtx::create();
    cctx.set_parameter(CParameter::CompressionLevel(level))
        .map_err(map_zstd_err)?;
    let bound = zstd_safe::compress_bound(raw.len());
    let mut out = Vec::with_capacity(bound);
    cctx.compress2(&mut out, raw).map_err(map_zstd_err)?;
    Ok(out.into_boxed_slice())
}

/// Decompress standalone zstd payload with an explicit maximum raw length guard.
pub fn decompress_standalone(
    compressed: &[u8],
    expected_raw_len: usize,
    max_raw_len: usize,
) -> Result<Vec<u8>, CodecError> {
    if expected_raw_len > max_raw_len {
        return Err(CodecError(format!(
            "raw length {expected_raw_len} exceeds limit {max_raw_len}"
        )));
    }
    let mut dctx = DCtx::create();
    dctx.set_parameter(DParameter::WindowLogMax(MAX_WINDOW_LOG))
        .map_err(map_zstd_err)?;
    let mut out = Vec::with_capacity(expected_raw_len);
    let written = dctx
        .decompress(&mut out, compressed)
        .map_err(map_zstd_err)?;
    if written != expected_raw_len {
        return Err(CodecError(format!(
            "decompressed length mismatch: got {written}, expected {expected_raw_len}"
        )));
    }
    Ok(out)
}

/// Decompress an internally cached snapshot whose exact raw length is stored in the zstd frame header.
pub fn decompress_cached_snapshot(
    compressed: &[u8],
    max_raw_len: usize,
) -> Result<Vec<u8>, CodecError> {
    let content_size = zstd_safe::get_frame_content_size(compressed)
        .map_err(|_| CodecError("invalid zstd frame content size".into()))?
        .ok_or_else(|| CodecError("zstd frame missing content size".into()))?;
    let expected = usize::try_from(content_size)
        .map_err(|_| CodecError("frame content size overflow".into()))?;
    decompress_standalone(compressed, expected, max_raw_len)
}

/// Compress `raw` as a byte-exact delta against `base_raw` using zstd raw prefix dictionary + LDM.
/// Allocates full `compress_bound(raw.len())` up front and shrinks to exact size on return.
pub fn compress_delta(raw: &[u8], base_raw: &[u8], level: i32) -> Result<Box<[u8]>, CodecError> {
    let mut cctx = CCtx::create();
    let wlog = required_window_log(base_raw.len().saturating_add(raw.len()));
    cctx.set_parameter(CParameter::CompressionLevel(level))
        .map_err(map_zstd_err)?;
    cctx.set_parameter(CParameter::WindowLog(wlog))
        .map_err(map_zstd_err)?;
    cctx.set_parameter(CParameter::EnableLongDistanceMatching(true))
        .map_err(map_zstd_err)?;
    cctx.ref_prefix(base_raw).map_err(map_zstd_err)?;

    let bound = zstd_safe::compress_bound(raw.len());
    let mut out = Vec::with_capacity(bound);
    cctx.compress2(&mut out, raw).map_err(map_zstd_err)?;
    Ok(out.into_boxed_slice())
}

/// Reconstruct exact `raw` bytes from `delta` and `base_raw` using zstd raw prefix dictionary.
pub fn decompress_delta(
    delta: &[u8],
    base_raw: &[u8],
    expected_raw_len: usize,
    max_raw_len: usize,
) -> Result<Vec<u8>, CodecError> {
    if expected_raw_len > max_raw_len {
        return Err(CodecError(format!(
            "raw length {expected_raw_len} exceeds limit {max_raw_len}"
        )));
    }
    let mut dctx = DCtx::create();
    dctx.set_parameter(DParameter::WindowLogMax(MAX_WINDOW_LOG))
        .map_err(map_zstd_err)?;
    dctx.ref_prefix(base_raw).map_err(map_zstd_err)?;

    let mut out = Vec::with_capacity(expected_raw_len);
    let written = dctx.decompress(&mut out, delta).map_err(map_zstd_err)?;
    if written != expected_raw_len {
        return Err(CodecError(format!(
            "delta decompressed length mismatch: got {written}, expected {expected_raw_len}"
        )));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_delta_large_json_context_and_exact_allocation() {
        let mut base = String::from(r#"{"model":"example-model","stream":true,"input":["#);
        for i in 0..400 {
            if i > 0 {
                base.push(',');
            }
            base.push_str(&format!(
                r#"{{"role":"user","content":"Turn {i}: fn process_chunk(buf: &[u8]) -> Result<usize, Error> {{ /* realistic code block repeated context {} */ }}"}}"#,
                "abcdefghij0123456789".repeat(60)
            ));
        }
        let mut curr = base.clone();
        base.push_str("]}");
        curr.push_str(
            r#",{"role":"assistant","content":"Applied patch and ran cargo test."},{"role":"user","content":"Now optimize the LRU eviction path and add metrics."}]}"#,
        );

        let base_bytes = base.as_bytes();
        let curr_bytes = curr.as_bytes();
        assert!(curr_bytes.len() > 500_000);

        let standalone = compress_standalone(curr_bytes, 3).unwrap();
        let delta = compress_delta(curr_bytes, base_bytes, 3).unwrap();
        let restored =
            decompress_delta(&delta, base_bytes, curr_bytes.len(), 16 * 1024 * 1024).unwrap();

        assert_eq!(restored, curr_bytes);
        assert!(
            delta.len() < 1024,
            "expected tiny delta < 1 KiB, got {} bytes (raw={}, standalone={})",
            delta.len(),
            curr_bytes.len(),
            standalone.len()
        );
    }

    #[test]
    fn incompressible_payload_does_not_fail_buffer_bound() {
        // Pseudo-random incompressible 256 KiB payload.
        let mut state: u64 = 0x1234_5678_9abc_def0;
        let mut data = vec![0u8; 256 * 1024];
        for b in &mut data {
            state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            *b = (state >> 33) as u8;
        }
        let base = vec![0xAAu8; 64 * 1024];
        let delta = compress_delta(&data, &base, 3).unwrap();
        let restored = decompress_delta(&delta, &base, data.len(), 1024 * 1024).unwrap();
        assert_eq!(restored, data);
    }
}
