//! The synthetic PKI of the oracle fixtures (`testdata/oracle/pki`), an in-process time-stamping service and OCSP
//! responders signing with its keys, and helpers over reports.

#![allow(dead_code)] // each test binary uses its own part

pub mod local_server;
pub mod recipes;
pub mod xml;

use std::cell::Cell;
use std::path::PathBuf;
use std::sync::OnceLock;

use num_bigint::{BigInt, BigUint};
use time::OffsetDateTime;
use ua_cryptography_pki::{
    Certificate, CheckStatus, Dstu4145PrivateKey, OcspResponse, OcspService, ServiceError, SigningKey,
    TimeStampService, TimeStampToken, ValidationOptions, VerificationReport, VerificationResult, algorithms,
    cms_builder, oids,
};

/// The store password of most JKS fixtures.
pub const PASSWORD: &str = "correct horse battery staple";

/// A path under `testdata/`.
pub fn testdata_path(relative: &str) -> PathBuf {
    PathBuf::from(concat!(env!("CARGO_MANIFEST_DIR"), "/../../testdata/")).join(relative)
}

/// A file under `testdata/oracle/pki/`.
pub fn read_oracle(relative: &str) -> Vec<u8> {
    let path = testdata_path("oracle/pki").join(relative);
    std::fs::read(&path).unwrap_or_else(|error| panic!("{}: {error}", path.display()))
}

/// A JSON file under `testdata/oracle/pki/`.
pub fn read_json(relative: &str) -> serde_json::Value {
    serde_json::from_slice(&read_oracle(relative)).unwrap()
}

/// A certificate under `testdata/oracle/pki/`.
pub fn oracle_certificate(relative: &str) -> Certificate {
    Certificate::load(&read_oracle(relative)).unwrap()
}

/// A real certificate under `testdata/certificates/`.
pub fn real_certificate(relative: &str) -> Certificate {
    Certificate::load(&std::fs::read(testdata_path("certificates").join(relative)).unwrap()).unwrap()
}

/// Every `.cer` / `.crt` of a folder of `testdata/certificates/`, as paths relative to that folder, sorted.
pub fn real_certificate_files(folder: &str) -> Vec<String> {
    let mut files: Vec<String> = std::fs::read_dir(testdata_path("certificates").join(folder))
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|name| name.ends_with(".cer") || name.ends_with(".crt"))
        .map(|name| format!("{folder}/{name}"))
        .collect();
    files.sort();
    files
}

/// The ЦЗО roots.
pub fn czo_roots() -> Vec<Certificate> {
    real_certificate_files("czo-roots")
        .iter()
        .map(|file| real_certificate(file))
        .collect()
}

pub fn hex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}

pub fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
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
    pub signer_twin: Certificate,
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

    /// Every certificate except the signer's.
    pub fn validation_certificates(&self) -> Vec<Certificate> {
        [&self.issuing_ca, &self.root, &self.tsa, &self.ocsp, &self.root_ocsp]
            .iter()
            .map(|identity| identity.certificate.clone())
            .collect()
    }

    /// Every certificate, the signer's first.
    pub fn all_certificates(&self) -> Vec<Certificate> {
        let mut all = vec![self.signer.certificate.clone()];
        all.extend(self.validation_certificates());
        all
    }

    pub fn signing_key(&self) -> SigningKey {
        SigningKey::new(self.signer.key.clone(), self.signer_chain()).unwrap()
    }

    /// Trusting the root, with every certificate at hand, offline.
    pub fn trusting(&self) -> ValidationOptions<'static> {
        ValidationOptions {
            trust_anchors: vec![self.root.certificate.clone()],
            extra_certificates: self.all_certificates(),
            ..ValidationOptions::default()
        }
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
}

fn load_hierarchy() -> Hierarchy {
    let keys = read_json("hierarchy/keys.json");
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
        signer_twin: oracle_certificate("hierarchy/signer-twin.cer"),
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
    static SERIAL: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
    let serial = SERIAL.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
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

/// A token of the hierarchy's TSA over `covered`.
pub fn stamp(covered: &[u8], hash_oid: &str, include_certificate: bool) -> Vec<u8> {
    stamp_hash(
        &algorithms::hash(hash_oid, covered, None).unwrap(),
        hash_oid,
        include_certificate,
        None,
    )
}

/// The hierarchy's TSA called in process.
pub struct TestTimeStamps {
    pub include_certificate: bool,
    pub requests: Cell<usize>,
}

impl TestTimeStamps {
    pub fn new() -> Self {
        Self {
            include_certificate: true,
            requests: Cell::new(0),
        }
    }
}

impl TimeStampService for TestTimeStamps {
    fn get_token(&self, hash: &[u8], hash_oid: &str) -> Result<TimeStampToken, ServiceError> {
        self.requests.set(self.requests.get() + 1);
        Ok(TimeStampToken::load(&stamp_hash(hash, hash_oid, self.include_certificate, None)).unwrap())
    }
}

/// A full OCSPResponse "good" about `certificate` from `responder` (DSTU 7564 CertID, DSTU 4145 + DSTU 7564).
pub fn respond(responder: &Identity, certificate: &Certificate, issuer: &Certificate, zero_key_hash: bool) -> Vec<u8> {
    let mut key_hash = algorithms::hash(oids::DSTU7564_256, issuer.public_key_bits(), None).unwrap();
    if zero_key_hash {
        key_hash.fill(0);
    }
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

/// The hierarchy's OCSP responders called in process: the issuing CA's for its certificates, the root's for the
/// root's.
pub struct TestOcsp {
    pub requests: Cell<usize>,
}

impl TestOcsp {
    pub fn new() -> Self {
        Self { requests: Cell::new(0) }
    }
}

impl OcspService for TestOcsp {
    fn find_response(
        &self,
        certificate: &Certificate,
        issuer: &Certificate,
        _hash_oid: &str,
    ) -> Result<Option<OcspResponse>, ServiceError> {
        self.requests.set(self.requests.get() + 1);
        let Some(responder) = Hierarchy::shared().responder_for(issuer) else {
            return Ok(None);
        };
        Ok(Some(
            OcspResponse::load(&respond(responder, certificate, issuer, false)).unwrap(),
        ))
    }
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

/// True when the report has a check `name` with `status`.
pub fn has_check(report: &VerificationReport, name: &str, status: CheckStatus) -> bool {
    report
        .checks
        .iter()
        .any(|check| check.name == name && check.status == status)
}

/// Every check that did not pass, one per line.
pub fn describe(result: &VerificationResult) -> String {
    result
        .signatures
        .iter()
        .map(describe_report)
        .collect::<Vec<_>>()
        .join("\n")
}

/// Every check that did not pass, one per line.
pub fn describe_report(report: &VerificationReport) -> String {
    report
        .checks
        .iter()
        .filter(|check| check.status != CheckStatus::Passed)
        .map(|check| {
            format!(
                "{}: [{:?}] {}: {}",
                report.title, check.status, check.name, check.details
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// Every check as "Status: name", the form of the manifest.
pub fn check_lines(report: &VerificationReport) -> Vec<String> {
    report
        .checks
        .iter()
        .map(|check| format!("{:?}: {}", check.status, check.name))
        .collect()
}
