fn main() {
    // On Windows MSVC, explicitly export the hook symbols so they are
    // visible in the resulting DLL.
    let target = std::env::var("TARGET").unwrap_or_default();
    if target.contains("msvc") {
        for sym in &["HookCreateFileW", "HookNtCreateFile", "UnhookAll", "DllMain"] {
            println!("cargo:rustc-cdylib-link-arg=/EXPORT:{}", sym);
        }
    }
}
