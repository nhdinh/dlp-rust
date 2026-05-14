//! Syslog forwarder observability metrics.
//!
//! Provides counters and gauges for queue depth, send latency, retry count,
//! drop count, and TLS error rate. Uses tracing::info! with structured fields
//! for compatibility with existing logging infrastructure.

use std::sync::atomic::{AtomicU64, Ordering};

static QUEUE_DEPTH: AtomicU64 = AtomicU64::new(0);
static SEND_LATENCY_MS: AtomicU64 = AtomicU64::new(0);
static RETRY_COUNT: AtomicU64 = AtomicU64::new(0);
static DROP_COUNT: AtomicU64 = AtomicU64::new(0);
static TLS_ERROR_COUNT: AtomicU64 = AtomicU64::new(0);

/// Record the current syslog queue depth.
///
/// # Arguments
///
/// * `depth` - Number of events currently in the queue.
pub fn record_syslog_queue_depth(depth: u64) {
    QUEUE_DEPTH.store(depth, Ordering::Relaxed);
    tracing::info!(metric = "syslog_queue_depth", depth, "syslog queue depth");
}

/// Record the send latency of a successful syslog forward batch.
///
/// # Arguments
///
/// * `latency_ms` - Elapsed time in milliseconds for the forward operation.
pub fn record_syslog_send_latency(latency_ms: u64) {
    SEND_LATENCY_MS.store(latency_ms, Ordering::Relaxed);
    tracing::info!(
        metric = "syslog_send_latency_ms",
        latency_ms,
        "syslog send latency"
    );
}

/// Record retry attempts for failed syslog forwards.
///
/// # Arguments
///
/// * `retry_count` - Number of retry events to add to the counter.
pub fn record_syslog_retry(retry_count: u64) {
    RETRY_COUNT.fetch_add(retry_count, Ordering::Relaxed);
    tracing::info!(metric = "syslog_retry_count", retry_count, "syslog retry");
}

/// Record dropped events (queue at capacity).
///
/// # Arguments
///
/// * `drop_count` - Number of dropped events to add to the counter.
pub fn record_syslog_drop(drop_count: u64) {
    DROP_COUNT.fetch_add(drop_count, Ordering::Relaxed);
    tracing::info!(metric = "syslog_drop_count", drop_count, "syslog drop");
}

/// Record a TLS error during syslog forwarding.
pub fn record_syslog_tls_error() {
    TLS_ERROR_COUNT.fetch_add(1, Ordering::Relaxed);
    tracing::warn!(metric = "syslog_tls_error", "syslog TLS error");
}

/// Return a snapshot of all syslog metrics.
///
/// # Returns
///
/// A [`SyslogMetrics`] struct containing the current values of all counters.
pub fn get_syslog_metrics() -> SyslogMetrics {
    SyslogMetrics {
        queue_depth: QUEUE_DEPTH.load(Ordering::Relaxed),
        send_latency_ms: SEND_LATENCY_MS.load(Ordering::Relaxed),
        retry_count: RETRY_COUNT.load(Ordering::Relaxed),
        drop_count: DROP_COUNT.load(Ordering::Relaxed),
        tls_error_count: TLS_ERROR_COUNT.load(Ordering::Relaxed),
    }
}

/// Snapshot of syslog forwarder metrics.
#[derive(Debug, Clone, serde::Serialize)]
pub struct SyslogMetrics {
    /// Current number of events in the syslog queue.
    pub queue_depth: u64,
    /// Last recorded send latency in milliseconds.
    pub send_latency_ms: u64,
    /// Total number of retry attempts.
    pub retry_count: u64,
    /// Total number of dropped events.
    pub drop_count: u64,
    /// Total number of TLS errors.
    pub tls_error_count: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_record_and_get_queue_depth() {
        record_syslog_queue_depth(42);
        let m = get_syslog_metrics();
        assert_eq!(m.queue_depth, 42);
    }

    #[test]
    fn test_record_and_get_send_latency() {
        record_syslog_send_latency(150);
        let m = get_syslog_metrics();
        assert_eq!(m.send_latency_ms, 150);
    }

    #[test]
    fn test_record_retry_accumulates() {
        let before = get_syslog_metrics().retry_count;
        record_syslog_retry(3);
        record_syslog_retry(2);
        let after = get_syslog_metrics().retry_count;
        assert_eq!(after, before + 5);
    }

    #[test]
    fn test_record_drop_accumulates() {
        let before = get_syslog_metrics().drop_count;
        record_syslog_drop(1);
        let after = get_syslog_metrics().drop_count;
        assert_eq!(after, before + 1);
    }

    #[test]
    fn test_record_tls_error_accumulates() {
        let before = get_syslog_metrics().tls_error_count;
        record_syslog_tls_error();
        record_syslog_tls_error();
        let after = get_syslog_metrics().tls_error_count;
        assert_eq!(after, before + 2);
    }

    #[test]
    fn test_syslog_metrics_serde() {
        let m = SyslogMetrics {
            queue_depth: 10,
            send_latency_ms: 50,
            retry_count: 3,
            drop_count: 1,
            tls_error_count: 0,
        };
        let json = serde_json::to_string(&m).expect("serialize");
        assert!(json.contains("\"queue_depth\":10"));
        assert!(json.contains("\"send_latency_ms\":50"));
        assert!(json.contains("\"retry_count\":3"));
        assert!(json.contains("\"drop_count\":1"));
        assert!(json.contains("\"tls_error_count\":0"));
    }
}
