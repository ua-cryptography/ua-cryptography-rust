//! Not a test: the local PKI server of the tests run standalone, for build_scripts/interop.sh (levels T and LT against the
//! C# ua-sign). Ignored unless asked for:
//!
//! ```text
//! UA_SIGN_TEST_PKI_DIRECTORY=DIR cargo test -p ua-cryptography-sign --test pki_server -- --ignored
//! ```
//!
//! writes DIR/signer.jks (the hierarchy's signer with its chain; password UA_SIGN_TEST_PKI_PASSWORD, default
//! "test password"), DIR/root.cer and DIR/ca.cer, then DIR/ready holding the server's base URL (/tsp, /ocsp,
//! /ca.p7b), and serves until DIR/stop appears.

mod common;

use std::path::Path;
use std::time::{Duration, Instant};

use common::Hierarchy;
use common::local_server::LocalPkiServer;

const DIRECTORY_VARIABLE: &str = "UA_SIGN_TEST_PKI_DIRECTORY";
const PASSWORD_VARIABLE: &str = "UA_SIGN_TEST_PKI_PASSWORD";
const DEFAULT_PASSWORD: &str = "test password";
const POLL_INTERVAL: Duration = Duration::from_millis(100);
const LONGEST_RUN: Duration = Duration::from_secs(3600);

#[test]
#[ignore = "a server for build_scripts/interop.sh, not a test"]
fn serve_the_test_pki_until_stopped() {
    let Ok(directory) = std::env::var(DIRECTORY_VARIABLE) else {
        eprintln!("{DIRECTORY_VARIABLE} is not set: nothing to serve.");
        return;
    };
    let directory = Path::new(&directory);
    let password = std::env::var(PASSWORD_VARIABLE).unwrap_or_else(|_| DEFAULT_PASSWORD.to_owned());
    let pki = Hierarchy::shared();
    let server = LocalPkiServer::start();
    pki.write_signer_key_store(directory.join("signer.jks").to_str().unwrap(), &password);
    pki.write_root(directory.join("root.cer").to_str().unwrap());
    std::fs::write(directory.join("ca.cer"), pki.issuing_ca.certificate.encoded()).unwrap();
    std::fs::write(directory.join("ready"), &server.base_url).unwrap();

    let started = Instant::now();
    while !directory.join("stop").exists() && started.elapsed() < LONGEST_RUN {
        std::thread::sleep(POLL_INTERVAL);
    }
    eprintln!(
        "served {} time-stamps, {} OCSP responses, {} caIssuers bundles",
        server.time_stamp_requests(),
        server.ocsp_requests(),
        server.ca_issuers_requests()
    );
}
