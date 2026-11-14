// Hands the Pingora version this was built against to the program, read from Cargo.toml's pin.
fn main() {
    let manifest = std::fs::read_to_string("Cargo.toml").expect("Cargo.toml");
    let version = manifest
        .lines()
        .find(|l| l.starts_with("pingora"))
        .and_then(|l| l.split("version = \"=").nth(1))
        .and_then(|r| r.split('"').next())
        .unwrap_or("?")
        .to_string();
    println!("cargo:rustc-env=PINGORA_VERSION={}", version);
    println!("cargo:rerun-if-changed=Cargo.toml");
}
