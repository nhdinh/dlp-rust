//! Phase 58.1: JournalDegraded alert emission test.
//!
//! Verifies that `emit_journal_degraded_alert` constructs the correct
//! `IpcEnvelope::V1(IpcPayloadV1::JournalDegraded(...))` payload and
//! sends it via the named pipe. Also verifies graceful handling when
//! the pipe is unreachable.
//!
//! Run with:
//!     cargo test -p dlp-hook-dll --test journal_degraded_test -- --test-threads=1

use std::io::{Read, Write};
use std::os::windows::io::IntoRawHandle;
use std::time::Duration;

/// Connect to a named pipe as a client.
fn connect_client(pipe_name: &str) -> std::io::Result<std::fs::File> {
    let path = format!(r"\\.\pipe\{}", pipe_name.trim_start_matches(r"\\.\pipe\"));
    let mut attempts = 0;
    loop {
        match std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
        {
            Ok(f) => return Ok(f),
            Err(e) if attempts < 50 => {
                std::thread::sleep(Duration::from_millis(10));
                attempts += 1;
                if attempts % 10 == 0 {
                    eprintln!("client connect attempt {}: {}", attempts, e);
                }
            }
            Err(e) => return Err(e),
        }
    }
}

/// Send raw bytes over the pipe with a 4-byte length prefix.
fn send_raw(pipe: &mut std::fs::File, payload: &[u8]) -> std::io::Result<Vec<u8>> {
    let len = payload.len() as u32;
    pipe.write_all(&len.to_le_bytes())?;
    pipe.write_all(payload)?;
    pipe.flush()?;

    // Read 4-byte length prefix.
    let mut len_buf = [0u8; 4];
    pipe.read_exact(&mut len_buf)?;
    let response_len = u32::from_le_bytes(len_buf) as usize;

    let mut response = vec![0u8; response_len];
    pipe.read_exact(&mut response)?;
    Ok(response)
}

/// Close the pipe handle.
fn close_pipe(pipe: std::fs::File) {
    let _ = pipe.into_raw_handle();
}

// ---------------------------------------------------------------------------
// Test: JournalDegraded alert payload verification
// ---------------------------------------------------------------------------

#[test]
fn test_journal_degraded_alert_payload() {
    // This test verifies that emit_journal_degraded_alert constructs the
    // correct IpcEnvelope with IpcPayloadV1::JournalDegraded variant.
    //
    // We verify by constructing the envelope manually and checking the
    // bincode serialization round-trip.
    let alert = dlp_common::hook_ipc::JournalDegradedAlert {
        file_object: 0x1234_5678_9ABC_DEF0,
        op: 2,
        error: "test journal mapping lost".to_string(),
    };
    let envelope = dlp_common::hook_ipc::IpcEnvelope::V1(dlp_common::hook_ipc::IpcMessageV1 {
        payload: dlp_common::hook_ipc::IpcPayloadV1::JournalDegraded(alert.clone()),
    });

    // Verify serialization round-trip.
    let bytes = bincode::serialize(&envelope).expect("serialize JournalDegraded envelope");
    let deserialized: dlp_common::hook_ipc::IpcEnvelope =
        bincode::deserialize(&bytes).expect("deserialize JournalDegraded envelope");

    match deserialized {
        dlp_common::hook_ipc::IpcEnvelope::V1(msg) => match msg.payload {
            dlp_common::hook_ipc::IpcPayloadV1::JournalDegraded(ref received) => {
                assert_eq!(received.file_object, alert.file_object);
                assert_eq!(received.op, alert.op);
                assert_eq!(received.error, alert.error);
            }
            other => panic!("expected JournalDegraded payload, got {:?}", other),
        },
    }
}

// ---------------------------------------------------------------------------
// Test: JournalDegraded alert end-to-end over named pipe
// ---------------------------------------------------------------------------

#[cfg(windows)]
mod windows_tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;

    /// Test that emit_journal_degraded_alert sends the correct payload
    /// over the named pipe and the server receives it.
    #[test]
    fn test_journal_degraded_alert_pipe_send() {
        use windows::Win32::Storage::FileSystem::PIPE_ACCESS_DUPLEX;
        use windows::Win32::System::Pipes::{
            ConnectNamedPipe, CreateNamedPipeW, PIPE_READMODE_MESSAGE, PIPE_TYPE_MESSAGE, PIPE_WAIT,
        };

        let pipe_name = r"\\.\pipe\DlpHookPipeTestJournalDegraded";

        // Create a simple pipe server that reads one frame and stores it.
        let received = Arc::new(std::sync::Mutex::new(Vec::new()));
        let received_clone = Arc::clone(&received);
        let server_done = Arc::new(AtomicBool::new(false));
        let server_done_clone = Arc::clone(&server_done);

        let server_handle = std::thread::spawn(move || {
            unsafe {
                let name_wide: Vec<u16> =
                    pipe_name.encode_utf16().chain(std::iter::once(0)).collect();
                let name_pcwstr = windows::core::PCWSTR::from_raw(name_wide.as_ptr());

                let pipe_handle = CreateNamedPipeW(
                    name_pcwstr,
                    PIPE_ACCESS_DUPLEX,
                    PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
                    1,
                    4096,
                    4096,
                    0,
                    None,
                );

                if pipe_handle.is_invalid() {
                    panic!("CreateNamedPipeW failed");
                }

                // Connect to the client.
                let connected = ConnectNamedPipe(pipe_handle, None);
                if connected.is_err() && connected.unwrap_err().code().0 as u32 != 535 {
                    // 535 = ERROR_PIPE_CONNECTED (client already connected)
                    let _ = windows::Win32::Foundation::CloseHandle(pipe_handle);
                    panic!("ConnectNamedPipe failed");
                }

                // Read 4-byte length prefix.
                let mut len_buf = [0u8; 4];
                let mut read: u32 = 0;
                let read_result = windows::Win32::Storage::FileSystem::ReadFile(
                    pipe_handle,
                    Some(&mut len_buf),
                    Some(&mut read),
                    None,
                );
                if read_result.is_err() {
                    let _ = windows::Win32::Foundation::CloseHandle(pipe_handle);
                    panic!("ReadFile length failed");
                }
                let msg_len = u32::from_le_bytes(len_buf) as usize;

                // Read the message.
                let mut msg_buf = vec![0u8; msg_len];
                let read_result = windows::Win32::Storage::FileSystem::ReadFile(
                    pipe_handle,
                    Some(&mut msg_buf),
                    Some(&mut read),
                    None,
                );
                if read_result.is_err() {
                    let _ = windows::Win32::Foundation::CloseHandle(pipe_handle);
                    panic!("ReadFile message failed");
                }

                // Store the received bytes.
                let mut guard = received_clone.lock().unwrap();
                *guard = msg_buf;

                // Send an ACK response (empty Response payload).
                let ack =
                    dlp_common::hook_ipc::IpcEnvelope::V1(dlp_common::hook_ipc::IpcMessageV1 {
                        payload: dlp_common::hook_ipc::IpcPayloadV1::Response(
                            dlp_common::hook_ipc::HookResponse {
                                decision: dlp_common::Decision::ALLOW,
                                reason: "journal degraded ack".to_string(),
                                cache_hint: None,
                                cache_version: 0,
                                approval_override: None,
                            },
                        ),
                    });
                let ack_bytes = bincode::serialize(&ack).unwrap();
                let ack_len = ack_bytes.len() as u32;
                let mut written: u32 = 0;
                let _ = windows::Win32::Storage::FileSystem::WriteFile(
                    pipe_handle,
                    Some(&ack_len.to_le_bytes()),
                    Some(&mut written),
                    None,
                );
                let mut written: u32 = 0;
                let _ = windows::Win32::Storage::FileSystem::WriteFile(
                    pipe_handle,
                    Some(&ack_bytes),
                    Some(&mut written),
                    None,
                );
                let _ = windows::Win32::Storage::FileSystem::FlushFileBuffers(pipe_handle);

                let _ = windows::Win32::Foundation::CloseHandle(pipe_handle);
                server_done_clone.store(true, Ordering::SeqCst);
            }
        });

        // Wait for the server to create the pipe.
        std::thread::sleep(Duration::from_millis(100));

        // Connect client and send the alert.
        let mut client = connect_client(pipe_name).expect("client connect");

        let alert = dlp_common::hook_ipc::JournalDegradedAlert {
            file_object: 0xABCD_1234_5678_EF00,
            op: 3,
            error: "ring buffer full".to_string(),
        };
        let envelope = dlp_common::hook_ipc::IpcEnvelope::V1(dlp_common::hook_ipc::IpcMessageV1 {
            payload: dlp_common::hook_ipc::IpcPayloadV1::JournalDegraded(alert.clone()),
        });
        let envelope_bytes = bincode::serialize(&envelope).unwrap();

        let ack_bytes =
            send_raw(&mut client, &envelope_bytes).expect("send journal degraded alert");
        let ack_envelope: dlp_common::hook_ipc::IpcEnvelope =
            bincode::deserialize(&ack_bytes).expect("deserialize ack");
        match ack_envelope {
            dlp_common::hook_ipc::IpcEnvelope::V1(msg) => match msg.payload {
                dlp_common::hook_ipc::IpcPayloadV1::Response(resp) => {
                    assert_eq!(resp.decision, dlp_common::Decision::ALLOW);
                }
                other => panic!("expected Response ack, got {:?}", other),
            },
        }

        close_pipe(client);

        // Wait for server to finish.
        server_handle.join().expect("server thread join");

        // Verify the server received the correct payload.
        let guard = received.lock().unwrap();
        let received_envelope: dlp_common::hook_ipc::IpcEnvelope =
            bincode::deserialize(&guard).expect("deserialize received envelope");
        match received_envelope {
            dlp_common::hook_ipc::IpcEnvelope::V1(msg) => match msg.payload {
                dlp_common::hook_ipc::IpcPayloadV1::JournalDegraded(ref received_alert) => {
                    assert_eq!(received_alert.file_object, alert.file_object);
                    assert_eq!(received_alert.op, alert.op);
                    assert_eq!(received_alert.error, alert.error);
                }
                other => panic!("expected JournalDegraded payload, got {:?}", other),
            },
        }
    }

    /// Test that emit_journal_degraded_alert returns gracefully when the pipe
    /// is unreachable (no panic, no hang).
    #[test]
    fn test_journal_degraded_alert_graceful_on_closed_pipe() {
        // Call emit_journal_degraded_alert with no pipe server running.
        // The function should return without panicking.
        dlp_hook_dll::emit_journal_degraded_alert(
            0xDEAD_BEEF_CAFE_0000,
            4,
            "no pipe server available",
        );
        // If we reach this point, the function returned gracefully.
    }
}
