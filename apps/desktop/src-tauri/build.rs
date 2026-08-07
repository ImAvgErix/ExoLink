fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("cargo:rerun-if-env-changed=EXOCORD_DEFAULT_API_URL");
    tauri_build::build();

    // Tauri's generated Windows resources include the Common Controls v6
    // activation manifest, but tauri-build only links them into binary targets.
    // The GNU test harness can also import TaskDialogIndirect once SQLCipher's
    // native objects are linked, so give test targets the same manifest.
    if cfg!(all(target_os = "windows", target_env = "gnu")) {
        let out_dir = std::env::var_os("OUT_DIR").ok_or("Cargo did not set OUT_DIR")?;
        let resource = std::path::PathBuf::from(out_dir).join("libresource.a");
        println!("cargo:rustc-link-arg={}", resource.display());
    }
    Ok(())
}
