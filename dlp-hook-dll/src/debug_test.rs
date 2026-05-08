#[test]
fn debug_pipe_exists() {
    let pipe_name = r"\\.\pipe\DlpHookPipeDebugTest";
    let name_wide: Vec<u16> = pipe_name.encode_utf16().chain(std::iter::once(0)).collect();
    
    let pipe = unsafe {
        windows::Win32::System::Pipes::CreateNamedPipeW(
            windows::core::PCWSTR::from_raw(name_wide.as_ptr()),
            windows::Win32::Storage::FileSystem::PIPE_ACCESS_DUPLEX,
            windows::Win32::System::Pipes::PIPE_TYPE_MESSAGE
                | windows::Win32::System::Pipes::PIPE_READMODE_MESSAGE
                | windows::Win32::System::Pipes::PIPE_WAIT,
            1,
            65536,
            65536,
            5000,
            None,
        )
    };
    
    eprintln!("pipe = {:?}, is_invalid = {}", pipe, pipe.is_invalid());
    assert!(!pipe.is_invalid(), "CreateNamedPipeW failed");
    
    // Try to connect from same thread
    let client = unsafe {
        windows::Win32::Storage::FileSystem::CreateFileW(
            windows::core::PCWSTR::from_raw(name_wide.as_ptr()),
            (windows::Win32::Storage::FileSystem::FILE_GENERIC_READ.0
                | windows::Win32::Storage::FileSystem::FILE_GENERIC_WRITE.0) as u32,
            windows::Win32::Storage::FileSystem::FILE_SHARE_NONE,
            None,
            windows::Win32::Storage::FileSystem::OPEN_EXISTING,
            windows::Win32::Storage::FileSystem::FILE_FLAGS_AND_ATTRIBUTES(0),
            None,
        )
    };
    
    eprintln!("client = {:?}", client);
    
    let _ = unsafe { windows::Win32::System::Pipes::DisconnectNamedPipe(pipe) };
    let _ = unsafe { windows::Win32::Foundation::CloseHandle(pipe) };
}
