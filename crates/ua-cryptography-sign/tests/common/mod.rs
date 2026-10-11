//! What the ua-sign tests share: `ua-sign` run in process, a temporary directory, the synthetic PKI of the oracle
//! fixtures (`testdata/oracle/pki/hierarchy`) with its time-stamping service and OCSP responders, served over HTTP by
//! `local_server`, and the independent recipes the profile checks are made with.

#![allow(dead_code)] // each test binary uses its own part

pub mod local_server;
pub mod profiles;
pub mod recipes;
pub mod xml;

use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, Ordering};

use num_bigint::{BigInt, BigUint};
use time::OffsetDateTime;
use ua_cryptography_pki::{
    Certificate, CertificateBuilder, DistinguishedName, Dstu4145PrivateKey, JksKeyStore, SigningKey, algorithms,
    cms_builder, oids,
};

/// A path under `testdata/`.
pub fn testdata_path(relative: &str) -> PathBuf {
    PathBuf::from(concat!(env!("CARGO_MANIFEST_DIR"), "/../../testdata/")).join(relative)
}

/// A file under `testdata/oracle/pki/`.
pub fn read_oracle(relative: &str) -> Vec<u8> {
    let path = testdata_path("oracle/pki").join(relative);
    std::fs::read(&path).unwrap_or_else(|error| panic!("{}: {error}", path.display()))
}

/// A certificate under `testdata/oracle/pki/`.
pub fn oracle_certificate(relative: &str) -> Certificate {
    Certificate::load(&read_oracle(relative)).unwrap()
}

pub fn hex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}

pub fn to_hex_upper(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02X}")).collect()
}

/// Runs `ua-sign` in process; returns the exit code and the output followed by the error output.
pub fn run(args: &[&str]) -> (u8, String) {
    run_with_environment(args, &|_| None)
}

/// Runs `ua-sign` in process with `environment` as the environment variables.
pub fn run_with_environment(args: &[&str], environment: &dyn Fn(&str) -> Option<String>) -> (u8, String) {
    let args: Vec<String> = args.iter().map(|arg| (*arg).to_owned()).collect();
    let mut output = Vec::new();
    let mut error = Vec::new();
    let code = ua_cryptography_sign::run(&args, &mut output, &mut error, environment);
    output.extend(error);
    (code, String::from_utf8(output).unwrap())
}

/// A fresh directory under the system's temporary directory, removed when dropped.
pub struct TestDirectory {
    pub root: PathBuf,
}

impl TestDirectory {
    pub fn new(prefix: &str) -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let nanos = OffsetDateTime::now_utc().unix_timestamp_nanos();
        let name = format!(
            "{prefix}-{}-{nanos}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::SeqCst)
        );
        let root = std::env::temp_dir().join(name);
        std::fs::create_dir_all(&root).unwrap();
        Self { root }
    }

    /// The path of `name` in the directory, as text for a command line.
    pub fn path(&self, name: &str) -> String {
        self.root.join(name).to_str().unwrap().to_owned()
    }

    /// Writes `content` to `name` and returns its path.
    pub fn write(&self, name: &str, content: &[u8]) -> String {
        let path = self.path(name);
        std::fs::write(&path, content).unwrap();
        path
    }

    /// Every file directly in the directory.
    pub fn files(&self) -> Vec<String> {
        let mut files: Vec<String> = std::fs::read_dir(&self.root)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .filter(|path| path.is_file())
            .map(|path| path.to_str().unwrap().to_owned())
            .collect();
        files.sort();
        files
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

/// A certificate with its key.
pub struct Identity {
    pub certificate: Certificate,
    pub key: Dstu4145PrivateKey,
}

/// The hierarchy of `hierarchy/keys.json`: root → issuing CA → signer and OCSP; root → TSA and root OCSP.
pub struct Hierarchy {
    pub root: Identity,
    pub issuing_ca: Identity,
    pub signer: Identity,
    pub tsa: Identity,
    pub ocsp: Identity,
    pub root_ocsp: Identity,
}

impl Hierarchy {
    pub fn shared() -> &'static Hierarchy {
        static SHARED: OnceLock<Hierarchy> = OnceLock::new();
        SHARED.get_or_init(load_hierarchy)
    }

    /// Signer, issuing CA, root.
    pub fn signer_chain(&self) -> Vec<Certificate> {
        vec![
            self.signer.certificate.clone(),
            self.issuing_ca.certificate.clone(),
            self.root.certificate.clone(),
        ]
    }

    /// Every certificate, the signer's first.
    pub fn all_certificates(&self) -> Vec<Certificate> {
        [
            &self.signer,
            &self.issuing_ca,
            &self.root,
            &self.tsa,
            &self.ocsp,
            &self.root_ocsp,
        ]
        .iter()
        .map(|identity| identity.certificate.clone())
        .collect()
    }

    /// The responder of the certificates `issuer` issued.
    pub fn responder_for(&self, issuer: &Certificate) -> Option<&Identity> {
        if issuer == &self.issuing_ca.certificate {
            Some(&self.ocsp)
        } else if issuer == &self.root.certificate {
            Some(&self.root_ocsp)
        } else {
            None
        }
    }

    /// The hierarchy's signer in a JKS key store with its full chain, as a bank would issue it.
    pub fn write_signer_key_store(&self, path: &str, password: &str) {
        write_key_store(path, "signer", &self.signer.key, self.signer_chain(), password);
    }

    /// The root certificate written to `path`.
    pub fn write_root(&self, path: &str) -> String {
        std::fs::write(path, self.root.certificate.encoded()).unwrap();
        path.to_owned()
    }
}

/// A key store with one private key entry.
pub fn write_key_store(path: &str, alias: &str, key: &Dstu4145PrivateKey, chain: Vec<Certificate>, password: &str) {
    let mut store = JksKeyStore::new();
    store.add_private_key(alias, key, chain, password).unwrap();
    std::fs::write(path, store.save(password).unwrap()).unwrap();
}

/// A certificate for `key` issued by `issuer` (DSTU 4145 + DSTU 7564, not a CA), naming the OCSP responder and the
/// caIssuers address when given, as qualified providers issue to their customers.
pub fn issue(
    subject: &str,
    key: &Dstu4145PrivateKey,
    issuer: &Identity,
    ocsp_url: Option<&str>,
    ca_issuers_url: Option<&str>,
) -> Certificate {
    let mut builder = CertificateBuilder::new(DistinguishedName::parse(subject).unwrap(), key.public_key().clone())
        .unwrap()
        .add_basic_constraints(false);
    if ocsp_url.is_some() || ca_issuers_url.is_some() {
        builder = builder.add_authority_info_access(ocsp_url, ca_issuers_url);
    }
    builder.not_before = OffsetDateTime::now_utc() - time::Duration::days(1);
    builder.issue(&issuer.certificate, &issuer.key).unwrap()
}

fn load_hierarchy() -> Hierarchy {
    let keys: serde_json::Value = serde_json::from_slice(&read_oracle("hierarchy/keys.json")).unwrap();
    let identity = |name: &str| {
        let entry = &keys["identities"][name];
        let key = &entry["key"];
        Identity {
            certificate: oracle_certificate(entry["certificate"].as_str().unwrap()),
            key: private_key(
                key["m"].as_u64().unwrap() as u32,
                key["d"].as_str().unwrap(),
                key["dke"].as_str(),
            ),
        }
    };
    Hierarchy {
        root: identity("root"),
        issuing_ca: identity("issuing-ca"),
        signer: identity("signer"),
        tsa: identity("tsa"),
        ocsp: identity("ocsp"),
        root_ocsp: identity("root-ocsp"),
    }
}

/// A key on the curve of table Г.1 of degree `m` with d given in big-endian hex.
pub fn private_key(m: u32, d_hex: &str, dke_hex: Option<&str>) -> Dstu4145PrivateKey {
    let domain = ua_cryptography_dstu4145::get_polynomial_curve(m).unwrap();
    let d = BigUint::from_bytes_be(&hex(d_hex));
    Dstu4145PrivateKey::new(domain, d, dke_hex.map(hex), true).unwrap()
}

/// The policy a national time-stamping service uses with a hash.
pub fn policy_for(hash_oid: &str) -> &'static str {
    if hash_oid == oids::GOST34311 {
        oids::TSP_POLICY_GOST34311
    } else {
        oids::TSP_POLICY_DSTU7564
    }
}

/// A token of the hierarchy's TSA over `hash` (TSTInfo signed with DSTU 4145 and the requested hash).
pub fn stamp_hash(hash: &[u8], hash_oid: &str, include_certificate: bool, nonce: Option<&BigInt>) -> Vec<u8> {
    static SERIAL: AtomicU64 = AtomicU64::new(1);
    let serial = SERIAL.fetch_add(1, Ordering::Relaxed);
    let mut fields = vec![
        ua_cryptography_der::integer_from_i64(1),
        ua_cryptography_der::object_identifier(policy_for(hash_oid)),
        ua_cryptography_der::sequence([
            ua_cryptography_der::algorithm_identifier(hash_oid),
            ua_cryptography_der::octet_string(hash),
        ]),
        ua_cryptography_der::integer_from_i64(serial as i64),
        ua_cryptography_der::generalized_time(OffsetDateTime::now_utc()),
    ];
    if let Some(nonce) = nonce {
        fields.push(ua_cryptography_der::integer(nonce));
    }
    let tst_info = ua_cryptography_der::sequence(fields);
    let tsa = &Hierarchy::shared().tsa;
    let signer = SigningKey::new(tsa.key.clone(), vec![tsa.certificate.clone()]).unwrap();
    let attributes = cms_builder::signed_attributes(&tst_info, oids::TST_INFO, &signer, hash_oid, &[]).unwrap();
    let (signer_info, _) = cms_builder::signer_info(&attributes, &signer, hash_oid, &[]).unwrap();
    let certificates = if include_certificate {
        vec![tsa.certificate.clone()]
    } else {
        Vec::new()
    };
    cms_builder::signed_data(&signer_info, hash_oid, oids::TST_INFO, Some(&tst_info), &certificates)
}

/// A full OCSPResponse "good" about `certificate` from `responder` (DSTU 7564 CertID, DSTU 4145 + DSTU 7564).
pub fn respond(responder: &Identity, certificate: &Certificate, issuer: &Certificate) -> Vec<u8> {
    let key_hash = algorithms::hash(oids::DSTU7564_256, issuer.public_key_bits(), None).unwrap();
    let cert_id = ua_cryptography_der::sequence([
        ua_cryptography_der::algorithm_identifier(oids::DSTU7564_256),
        ua_cryptography_der::octet_string(
            &algorithms::hash(oids::DSTU7564_256, issuer.subject().encoded(), None).unwrap(),
        ),
        ua_cryptography_der::octet_string(&key_hash),
        ua_cryptography_der::integer(certificate.serial_number()),
    ]);
    let now = ua_cryptography_der::generalized_time(OffsetDateTime::now_utc());
    let good = ua_cryptography_der::encode(ua_cryptography_der::tag::context_primitive(0), &[]);
    let single = ua_cryptography_der::sequence([cert_id, good, now.clone()]);
    let responder_id = ua_cryptography_der::explicit(1, responder.certificate.subject().encoded());
    let data = ua_cryptography_der::sequence([responder_id, now, ua_cryptography_der::sequence([single])]);
    let signature = responder.key.sign(oids::DSTU4145_WITH_DSTU7564, &data).unwrap();
    let basic = ua_cryptography_der::sequence([
        data,
        ua_cryptography_der::algorithm_identifier(oids::DSTU4145_WITH_DSTU7564),
        ua_cryptography_der::bit_string(&ua_cryptography_der::octet_string(&signature)),
        ua_cryptography_der::explicit(0, &ua_cryptography_der::sequence([responder.certificate.encoded()])),
    ]);
    let bytes = ua_cryptography_der::sequence([
        ua_cryptography_der::object_identifier(oids::OCSP_BASIC),
        ua_cryptography_der::octet_string(&basic),
    ]);
    ua_cryptography_der::sequence([
        ua_cryptography_der::encode(ua_cryptography_der::tag::ENUMERATED, &[0]),
        ua_cryptography_der::explicit(0, &bytes),
    ])
}

/// One entry of a ZIP archive as stored.
pub struct ZipEntry {
    pub name: String,
    pub content: Vec<u8>,
    pub is_stored: bool,
}

/// The entries of a ZIP archive in archive order.
pub fn read_zip(container: &[u8]) -> Vec<ZipEntry> {
    use std::io::Read;
    let mut archive = zip::ZipArchive::new(std::io::Cursor::new(container)).unwrap();
    (0..archive.len())
        .map(|index| {
            let mut entry = archive.by_index(index).unwrap();
            let mut content = Vec::new();
            entry.read_to_end(&mut content).unwrap();
            ZipEntry {
                name: entry.name().unwrap().into_owned(),
                is_stored: entry.compression() == zip::CompressionMethod::Stored,
                content,
            }
        })
        .collect()
}

/// A ZIP archive of `entries`: the first stored, the rest deflated.
pub fn write_zip(entries: &[(&str, &[u8])]) -> Vec<u8> {
    use std::io::Write;
    let mut writer = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
    for (index, (name, content)) in entries.iter().enumerate() {
        let method = if index == 0 {
            zip::CompressionMethod::Stored
        } else {
            zip::CompressionMethod::Deflated
        };
        let options = zip::write::SimpleFileOptions::default().compression_method(method);
        writer.start_file(*name, options).unwrap();
        writer.write_all(content).unwrap();
    }
    writer.finish().unwrap().into_inner()
}

/// The position of `needle` in `haystack`.
pub fn position_of(haystack: &[u8], needle: &[u8]) -> usize {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
        .unwrap()
}

/// True when `path` exists.
pub fn exists(path: &str) -> bool {
    Path::new(path).exists()
}
