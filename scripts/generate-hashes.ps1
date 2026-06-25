$binaries = @('dlp-agent.exe','dlp-server.exe','dlp-admin-cli.exe','dlp-user-ui.exe','dlp_hook_dll.dll','dlp_hook_dll_x86.dll')
foreach ($b in $binaries) {
    if ($b -eq 'dlp_hook_dll_x86.dll') {
        $p = 'C:/Users/nhdinh/dev/dlp-rust/target/i686-pc-windows-msvc/release/' + $b
    } else {
        $p = 'C:/Users/nhdinh/dev/dlp-rust/target/release/' + $b
    }
    if (Test-Path $p) {
        $s256 = (Get-FileHash $p -Algorithm SHA256).Hash
        $s512 = (Get-FileHash $p -Algorithm SHA512).Hash
        Write-Output "$b | $s256 | $s512"
    } else {
        Write-Output "$b | NOT_FOUND | NOT_FOUND"
    }
}
