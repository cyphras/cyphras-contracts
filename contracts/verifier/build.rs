// Compiles the Groth16 verifying key in from keys/. The default build embeds the
// testnet-forgeable dev key; the `mainnet` feature embeds the ceremony key, which must match its
// pin in build/check.rs. Either key must pass the checks there or the build fails.

#[path = "build/check.rs"]
mod check;

use std::{env, fmt::Write as _, fs, path::PathBuf};

fn read(path: &PathBuf) -> Vec<u8> {
    println!("cargo:rerun-if-changed={}", path.display());
    fs::read(path).unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()))
}

fn bytes(b: &[u8]) -> String {
    let mut s = String::from("[");
    for (i, byte) in b.iter().enumerate() {
        if i > 0 {
            s.push(',');
        }
        write!(s, "0x{byte:02x}").unwrap();
    }
    s.push(']');
    s
}

fn main() {
    let keys = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap()).join("keys");
    let forgeable_path = keys.join("testnet-forgeable/verification_key.json");
    println!("cargo:rerun-if-changed=build/check.rs");

    let mainnet = env::var_os("CARGO_FEATURE_MAINNET").is_some();
    let (label, json, key) = if mainnet {
        let json = read(&keys.join("mainnet/verification_key.json"));
        let key = check::mainnet(&json, &read(&forgeable_path), check::MAINNET_SHA256);
        ("mainnet", json, key)
    } else {
        let json = read(&forgeable_path);
        let key = check::testnet_forgeable(&json);
        ("testnet-forgeable", json, key)
    };
    let key = key.unwrap_or_else(|e| panic!("refusing the {label} verifying key: {e}"));
    let sha256 = check::sha256_hex(&json);
    if !mainnet {
        println!(
            "cargo:warning=embedding the FORGEABLE testnet verifying key (sha256 {sha256}); \
             build with --features mainnet for a deployable mainnet vault"
        );
    }

    let ic: Vec<String> = key.ic.iter().map(|p| bytes(p)).collect();
    let out = format!(
        "pub(crate) const ALPHA: [u8; 64] = {};\n\
         pub(crate) const BETA: [u8; 128] = {};\n\
         pub(crate) const GAMMA: [u8; 128] = {};\n\
         pub(crate) const DELTA: [u8; 128] = {};\n\
         pub(crate) const IC: [[u8; 64]; {}] = [{}];\n\
         pub(crate) const FORGEABLE: bool = {};\n\
         soroban_sdk::contractmeta!(key = \"cyphras_vk\", val = \"{label} sha256:{sha256}\");\n",
        bytes(&key.alpha),
        bytes(&key.beta),
        bytes(&key.gamma),
        bytes(&key.delta),
        ic.len(),
        ic.join(","),
        !mainnet,
    );
    fs::write(
        PathBuf::from(env::var("OUT_DIR").unwrap()).join("vk.rs"),
        out,
    )
    .unwrap();
}
