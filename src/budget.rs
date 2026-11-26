use axum::body::{Body, Bytes};
use http_body_util::BodyExt;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

/// Memory accounting granularity: 64 KiB per semaphore permit.
pub const MEM_UNIT_BYTES: usize = 64 * 1024;

#[derive(Debug)]
pub enum BudgetError {
    /// Request's required memory exceeds the server's entire configured in-flight budget (R2-05).
    ExceedsTotalBudget { needed: usize, budget: usize },
    /// Timed out waiting for memory permits under sustained saturation.
    Saturated,
    /// Global active request cap reached (immediate load shedding, R2-06).
    TooManyRequests,
    /// Request body exceeded configured `max_body_bytes`.
    PayloadTooLarge,
    /// Client stalled while uploading request body (R2-06).
    BodyReadTimeout,
    /// Underlying HTTP body stream error.
    BodyReadError(String),
}

/// Unified resource governor enforcing:
/// - Immediate global concurrent request ceiling (`max_concurrent_requests`)
/// - Strict in-flight RAM budget (`max_inflight_bytes`, never clamped below actual need!)
/// - Bounded blocking zstd codec concurrency (`max_codec_concurrency`)
pub struct ResourceBudget {
    active_requests: Arc<Semaphore>,
    mem_units: Arc<Semaphore>,
    total_mem_units: u32,
    total_mem_bytes: usize,
    codec_slots: Arc<Semaphore>,
    acquire_timeout: Duration,
}

impl ResourceBudget {
    pub fn new(
        max_concurrent_requests: usize,
        max_inflight_bytes: usize,
        max_codec_concurrency: usize,
        acquire_timeout: Duration,
    ) -> Self {
        let total_mem_units = bytes_to_units(max_inflight_bytes).max(1);
        Self {
            active_requests: Arc::new(Semaphore::new(max_concurrent_requests.max(1))),
            mem_units: Arc::new(Semaphore::new(total_mem_units as usize)),
            total_mem_units,
            total_mem_bytes: (total_mem_units as usize) * MEM_UNIT_BYTES,
            codec_slots: Arc::new(Semaphore::new(max_codec_concurrency.max(1))),
            acquire_timeout,
        }
    }

    pub fn total_mem_bytes(&self) -> usize {
        self.total_mem_bytes
    }

    /// Non-blocking global request slot acquisition (fast load shedding when overloaded).
    pub fn try_acquire_request(&self) -> Result<OwnedSemaphorePermit, BudgetError> {
        Arc::clone(&self.active_requests)
            .try_acquire_owned()
            .map_err(|_| BudgetError::TooManyRequests)
    }

    /// Acquire a blocking codec worker slot with timeout.
    pub async fn acquire_codec(&self) -> Result<OwnedSemaphorePermit, BudgetError> {
        tokio::time::timeout(
            self.acquire_timeout,
            Arc::clone(&self.codec_slots).acquire_owned(),
        )
        .await
        .map_err(|_| BudgetError::Saturated)?
        .map_err(|_| BudgetError::Saturated)
    }

    /// Create an empty RAII memory lease attached to this budget.
    pub fn new_lease(&self) -> MemoryLease {
        MemoryLease {
            sem: Arc::clone(&self.mem_units),
            total_units: self.total_mem_units,
            total_bytes: self.total_mem_bytes,
            acquire_timeout: self.acquire_timeout,
            held: Vec::new(),
            units: 0,
        }
    }
}

/// RAII memory lease that grows incrementally BEFORE allocating memory, shrinks when buffers
/// are released, and can split permits into spawned/blocking tasks so client cancellation
/// never leaks memory out of the budget (R2-01, R2-02, R2-04, R2-05).
pub struct MemoryLease {
    sem: Arc<Semaphore>,
    total_units: u32,
    total_bytes: usize,
    acquire_timeout: Duration,
    held: Vec<OwnedSemaphorePermit>,
    units: u32,
}

impl MemoryLease {
    pub fn held_bytes(&self) -> usize {
        (self.units as usize) * MEM_UNIT_BYTES
    }

    /// Ensure at least `bytes` of budget are reserved. Never silently clamps above total budget!
    pub async fn reserve_at_least(&mut self, bytes: usize) -> Result<(), BudgetError> {
        let needed_units = bytes_to_units(bytes);
        if needed_units > self.total_units {
            return Err(BudgetError::ExceedsTotalBudget {
                needed: bytes,
                budget: self.total_bytes,
            });
        }
        if needed_units <= self.units {
            return Ok(());
        }
        let delta = needed_units - self.units;
        let permit = tokio::time::timeout(
            self.acquire_timeout,
            Arc::clone(&self.sem).acquire_many_owned(delta),
        )
        .await
        .map_err(|_| BudgetError::Saturated)?
        .map_err(|_| BudgetError::Saturated)?;
        self.held.push(permit);
        self.units += delta;
        Ok(())
    }

    /// Acquire an independent child lease (e.g. to move into a `spawn_blocking` or background
    /// cache-compression task) so permits remain held until that task actually frees its buffers.
    pub async fn acquire_child(&self, bytes: usize) -> Result<MemoryLease, BudgetError> {
        let mut child = MemoryLease {
            sem: Arc::clone(&self.sem),
            total_units: self.total_units,
            total_bytes: self.total_bytes,
            acquire_timeout: self.acquire_timeout,
            held: Vec::new(),
            units: 0,
        };
        child.reserve_at_least(bytes).await?;
        Ok(child)
    }

    /// Release all permits when request buffers are fully dropped.
    pub fn release_all(&mut self) {
        self.held.clear();
        self.units = 0;
    }
}

pub fn bytes_to_units(bytes: usize) -> u32 {
    if bytes == 0 {
        return 0;
    }
    bytes.div_ceil(MEM_UNIT_BYTES).min(u32::MAX as usize) as u32
}

/// Stream-read an HTTP body incrementally:
/// - Enforces `body_read_timeout` across the entire upload (R2-06)
/// - Enforces `max_body_bytes` strictly before appending each frame
/// - Reserves memory permits BEFORE appending each chunk (fixes R2-01 chunked OOM!)
pub async fn read_body_with_budget(
    mut body: Body,
    max_body_bytes: usize,
    body_read_timeout: Duration,
    lease: &mut MemoryLease,
) -> Result<Bytes, BudgetError> {
    let deadline = tokio::time::Instant::now() + body_read_timeout;
    let mut buf: Vec<u8> = Vec::new();

    loop {
        let frame_opt = tokio::time::timeout_at(deadline, body.frame())
            .await
            .map_err(|_| BudgetError::BodyReadTimeout)?;

        let Some(frame_res) = frame_opt else {
            break;
        };
        let frame = frame_res.map_err(|e| BudgetError::BodyReadError(e.to_string()))?;
        if let Ok(chunk) = frame.into_data() {
            if chunk.is_empty() {
                continue;
            }
            let new_len = buf
                .len()
                .checked_add(chunk.len())
                .ok_or(BudgetError::PayloadTooLarge)?;
            if new_len > max_body_bytes {
                return Err(BudgetError::PayloadTooLarge);
            }
            // Reserve memory BEFORE growing `buf` (account for Vec growth up to 2x or exact).
            let target_cap = new_len.min(max_body_bytes);
            lease.reserve_at_least(target_cap).await?;
            if buf.capacity() < new_len {
                // Exact reserve avoids Vec doubling a 9 MiB upload into 18 MiB unexpectedly.
                let grow = (new_len - buf.len()).max(chunk.len());
                buf.reserve_exact(grow);
            }
            buf.extend_from_slice(&chunk);
        }
    }

    Ok(Bytes::from(buf))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn rejects_request_exceeding_total_budget_instead_of_clamping() {
        let budget = ResourceBudget::new(8, 256 * 1024, 2, Duration::from_millis(50));
        let mut lease = budget.new_lease();
        let err = lease.reserve_at_least(512 * 1024).await.unwrap_err();
        assert!(matches!(err, BudgetError::ExceedsTotalBudget { .. }));
    }

    #[tokio::test]
    async fn chunked_read_acquires_budget_incrementally_and_enforces_cap() {
        let budget = ResourceBudget::new(8, 128 * 1024, 2, Duration::from_millis(50));
        let mut lease = budget.new_lease();
        let body = Body::from(vec![b'a'; 200 * 1024]);
        let err = read_body_with_budget(body, 512 * 1024, Duration::from_secs(5), &mut lease)
            .await
            .unwrap_err();
        assert!(matches!(err, BudgetError::ExceedsTotalBudget { .. }));
    }
}
