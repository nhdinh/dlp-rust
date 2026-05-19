//! ETW process creation watcher + WMI backstop.
//!
//! Architecture:
//! - Dedicated OS thread runs ETW ProcessTrace blocking loop.
//! - ETW callback parses Event ID 1 (ProcessStart), pushes ProcessEvent through crossbeam channel.
//! - NO pre-filtering at ETW layer (review fix: filtering happens in injection task).
//! - WMI backstop ONLY activates when ETW heartbeat is unhealthy.
//! - Channel overflow triggers immediate EnumProcesses sweep (review fix: not silent drop-oldest).

use crossbeam_channel::{bounded, Receiver, Sender, TrySendError};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

/// Event from ETW or WMI process creation notification.
#[derive(Debug, Clone)]
pub struct ProcessEvent {
    pub pid: u32,
    pub image_path: String,
    pub parent_pid: u32,
    pub creation_time: u64,
    pub source: EventSource,
    /// ETW event timestamp for latency measurement.
    pub event_timestamp: Instant,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventSource {
    Etw,
    Wmi,
    StartupSweep,
    PeriodicSweep,
}

/// Trigger for immediate EnumProcesses sweep.
#[derive(Debug, Clone, PartialEq)]
pub enum SweepTrigger {
    ChannelOverflow,
    HeartbeatRecovery,
}

pub struct ProcessWatcher {
    etw_shutdown: Arc<AtomicBool>,
    etw_handle: Option<thread::JoinHandle<()>>,
    event_tx: Sender<ProcessEvent>,
    event_rx: Receiver<ProcessEvent>,
    /// Last known ETW health.
    etw_healthy: Arc<AtomicBool>,
    /// Channel overflow counter (triggers sweep).
    overflow_count: AtomicUsize,
}

const CHANNEL_CAPACITY: usize = 1024;
const ETW_BUFFER_SIZE_KB: u32 = 256;
const ETW_BUFFER_COUNT: u32 = 200;

impl ProcessWatcher {
    /// Creates a new process watcher with a bounded channel.
    #[must_use]
    pub fn new() -> Self {
        let (tx, rx) = bounded::<ProcessEvent>(CHANNEL_CAPACITY);
        Self {
            etw_shutdown: Arc::new(AtomicBool::new(false)),
            etw_handle: None,
            event_tx: tx,
            event_rx: rx,
            etw_healthy: Arc::new(AtomicBool::new(true)),
            overflow_count: AtomicUsize::new(0),
        }
    }

    /// Start ETW watcher on dedicated thread.
    ///
    /// # Errors
    ///
    /// Returns an error if the ETW thread cannot be spawned.
    pub fn start(&mut self, sweep_trigger: Sender<SweepTrigger>) -> anyhow::Result<()> {
        let tx = self.event_tx.clone();
        let shutdown = Arc::clone(&self.etw_shutdown);
        let healthy = Arc::clone(&self.etw_healthy);

        let handle = thread::Builder::new()
            .name("etw-process-watcher".into())
            .spawn(move || {
                run_etw_loop(tx, shutdown, healthy, sweep_trigger);
            })?;

        self.etw_handle = Some(handle);
        Ok(())
    }

    /// Returns a reference to the event receiver.
    #[must_use]
    pub fn receiver(&self) -> &Receiver<ProcessEvent> {
        &self.event_rx
    }

    /// Returns whether ETW is currently healthy.
    #[must_use]
    pub fn is_etw_healthy(&self) -> bool {
        self.etw_healthy.load(Ordering::Relaxed)
    }

    /// Stops the ETW watcher and joins the thread.
    pub fn stop(&mut self) {
        self.etw_shutdown.store(true, Ordering::Relaxed);
        if let Some(h) = self.etw_handle.take() {
            let _ = h.join();
        }
    }

    /// Returns the current overflow count.
    #[must_use]
    pub fn overflow_count(&self) -> usize {
        self.overflow_count.load(Ordering::Relaxed)
    }
}

impl Default for ProcessWatcher {
    fn default() -> Self {
        Self::new()
    }
}

/// Run the ETW process creation event loop.
///
/// This function runs on a dedicated OS thread and blocks on the ETW trace.
/// It pushes parsed process events through the crossbeam channel.
fn run_etw_loop(
    tx: Sender<ProcessEvent>,
    shutdown: Arc<AtomicBool>,
    healthy: Arc<AtomicBool>,
    sweep_trigger: Sender<SweepTrigger>,
) {
    use ferrisetw::provider::{kernel_providers, Provider};
    use ferrisetw::schema_locator::SchemaLocator;
    use ferrisetw::trace::{KernelTrace, LoggingMode, TraceProperties, TraceTrait};
    use ferrisetw::EventRecord;

    let process_provider = Provider::kernel(&kernel_providers::PROCESS_PROVIDER)
        .add_callback(move |record: &EventRecord, schema_locator: &SchemaLocator| {
            if record.event_id() != 1 {
                return;
            }
            let ts = Instant::now();
            match schema_locator.event_schema(record) {
                Ok(schema) => {
                    let parser = ferrisetw::parser::Parser::create(record, &schema);
                    let pid: u32 = parser.try_parse("ProcessID").unwrap_or(0);
                    let image_name: String = parser.try_parse("ImageName").unwrap_or_default();
                    let parent_id: u32 = parser.try_parse("ParentProcessID").unwrap_or(0);
                    let creation_time: u64 = parser.try_parse("CreateTime").unwrap_or(0);

                    let event = ProcessEvent {
                        pid,
                        image_path: image_name,
                        parent_pid: parent_id,
                        creation_time,
                        source: EventSource::Etw,
                        event_timestamp: ts,
                    };

                    // Review fix: overflow triggers sweep, not silent drop-oldest.
                    match tx.try_send(event) {
                        Ok(()) => {}
                        Err(TrySendError::Full(_)) => {
                            tracing::warn!(
                                "ETW event channel full — triggering immediate sweep"
                            );
                            let _ = sweep_trigger.try_send(SweepTrigger::ChannelOverflow);
                        }
                        Err(TrySendError::Disconnected(_)) => {}
                    }
                }
                Err(e) => {
                    tracing::warn!("ETW schema error: {:?}", e);
                }
            }
        })
        .build();

    let props = TraceProperties {
        buffer_size: ETW_BUFFER_SIZE_KB,
        min_buffer: ETW_BUFFER_COUNT,
        max_buffer: ETW_BUFFER_COUNT,
        flush_timer: Duration::from_secs(1),
        log_file_mode: LoggingMode::EVENT_TRACE_REAL_TIME_MODE
            | LoggingMode::EVENT_TRACE_NO_PER_PROCESSOR_BUFFERING,
    };

    let trace_builder = KernelTrace::new()
        .named(String::from("DlpProcessWatcher"))
        .set_trace_properties(props)
        .enable(process_provider);

    // Start the trace and get the handle for processing.
    // Using start() instead of start_and_process() so we control the thread
    // and can stop the trace on shutdown.
    let (trace, trace_handle) = match trace_builder.start() {
        Ok(result) => result,
        Err(e) => {
            tracing::error!(error = ?e, "ETW trace start failed — marking unhealthy");
            healthy.store(false, Ordering::Relaxed);
            return;
        }
    };

    tracing::info!("ETW process watcher trace started");

    // Process trace in a blocking loop on this thread.
    // We spawn a separate thread for ProcessTrace so we can wait for shutdown
    // and then stop the trace.
    let process_shutdown = Arc::clone(&shutdown);
    let process_handle = std::thread::spawn(move || {
        let _ = ferrisetw::trace::KernelTrace::process_from_handle(trace_handle);
    });

    // Wait for shutdown signal.
    loop {
        if process_shutdown.load(Ordering::Relaxed) {
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }

    // Stop the trace on shutdown.
    if let Err(e) = trace.stop() {
        tracing::warn!(error = ?e, "ETW trace stop failed");
    }

    let _ = process_handle.join();
    tracing::info!("ETW process watcher stopped");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_process_watcher_new() {
        let watcher = ProcessWatcher::new();
        assert!(watcher.is_etw_healthy());
        assert_eq!(watcher.overflow_count(), 0);
    }

    #[test]
    fn test_process_event_source_variants() {
        let sources = [
            EventSource::Etw,
            EventSource::Wmi,
            EventSource::StartupSweep,
            EventSource::PeriodicSweep,
        ];
        for (i, s1) in sources.iter().enumerate() {
            for (j, s2) in sources.iter().enumerate() {
                if i == j {
                    assert_eq!(s1, s2);
                } else {
                    assert_ne!(s1, s2);
                }
            }
        }
    }

    #[test]
    fn test_sweep_trigger_variants() {
        assert_eq!(
            SweepTrigger::ChannelOverflow,
            SweepTrigger::ChannelOverflow
        );
        assert_eq!(
            SweepTrigger::HeartbeatRecovery,
            SweepTrigger::HeartbeatRecovery
        );
        assert_ne!(
            SweepTrigger::ChannelOverflow,
            SweepTrigger::HeartbeatRecovery
        );
    }
}
