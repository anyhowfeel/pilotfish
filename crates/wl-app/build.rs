//! Embeds the application icon in the Windows executable (a no-op on other hosts).

fn main() {
    println!("cargo:rerun-if-changed=../../assets/logo/pilotfish.ico");
    embed_windows_icon();
}

#[cfg(windows)]
fn embed_windows_icon() {
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows") {
        let mut res = winresource::WindowsResource::new();
        res.set_icon("../../assets/logo/pilotfish.ico");
        if let Err(err) = res.compile() {
            println!("cargo:warning=could not embed the Windows icon: {err}");
        }
    }
}

#[cfg(not(windows))]
fn embed_windows_icon() {}
