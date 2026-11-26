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

/// Compute minimum windowLog (clamped to 18..=MAX_WINDOW_LOG) that covers `total_bytes`.
fn required_window_log(total_bytes: usize) -> u32 {
    let needed = total_bytes.max(1 << 18);
    let mut log = 18u32;
    while (1usize << log) < needed && log < MAX_WINDOW_LOG {
        log += 1;
    }
    log
}

/// Compress `raw` standalone using zstd at the requested level.
pub fn compress_standalone(raw: &[u8], level: i32) -> Result<Vec<u8>, CodecError> {
    let mut cctx = CCtx::create();
    cctx.set_parameter(CParameter::CompressionLevel(level))
        .map_err(map_zstd_err)?;
    let bound = zstd_safe::compress_bound(raw.len());
    let mut out = Vec::with_capacity(bound);
    cctx.compress2(&mut out, raw).map_err(map_zstd_err)?;
    Ok(out)
}

/// Decompress standalone zstd payload with an explicit maximum raw length guard.
pub fn decompress_standalone(compressed: &[u8], expected_raw_len: usize, max_raw_len: usize) -> Result<Vec<u8>, CodecError> {
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
pub fn decompress_cached_snapshot(compressed: &[u8], max_raw_len: usize) -> Result<Vec<u8>, CodecError> {
    let content_size = zstd_safe::get_frame_content_size(compressed)
        .map_err(|_| CodecError("invalid zstd frame content size".into()))?
        .ok_or_else(|| CodecError("zstd frame missing content size".into()))?;
    let expected = usize::try_from(content_size)
        .map_err(|_| CodecError("frame content size overflow".into()))?;
    decompress_standalone(compressed, expected, max_raw_len)
}

/// Compress `raw` as a byte-exact delta against `base_raw` using zstd raw prefix dictionary + LDM.
pub fn compress_delta(raw: &[u8], base_raw: &[u8], level: i32) -> Result<Vec<u8>, CodecError> {
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
    let mut out = Vec::with_capacity(bound.min(raw.len().saturating_add(65536)));
    // Ensure output vector capacity is at least compress_bound if needed.
    if out.capacity() < bound {
        out.reserve(bound - out.capacity());
    }
    cctx.compress2(&mut out, raw).map_err(map_zstd_err)?;
    Ok(out)
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
    fn roundtrip_delta_large_json_context() {
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
        let restored = decompress_delta(&delta, base_bytes, curr_bytes.len(), 16 * 1024 * 1024).unwrap();

        assert_eq!(restored, curr_bytes);
        assert!(
            delta.len() < 1024,
            "expected tiny delta < 1 KiB, got {} bytes (raw={}, standalone={})",
            delta.len(),
            curr_bytes.len(),
            standalone.len()
        );
    }
}
