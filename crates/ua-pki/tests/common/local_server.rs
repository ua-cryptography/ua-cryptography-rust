//! The hierarchy's time-stamping service, OCSP responders and caIssuers bundle over HTTP on 127.0.0.1: a minimal
//! HTTP/1.1 server on `std::net::TcpListener`. Requests are read with `ua-der` directly, independently of the crate's
//! encoders.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::thread::JoinHandle;

use ua_der::Asn1Node;
use ua_pki::{Certificate, oids};

use super::{Hierarchy, respond, stamp_hash};

/// The size of the answer of /large: above the clients' 10 MiB cap.
pub const LARGE_ANSWER_BYTES: usize = (10 << 20) + 1;

/// What the server counts.
#[derive(Default)]
pub struct Counters {
    pub time_stamps: AtomicUsize,
    pub ocsp: AtomicUsize,
    pub ca_issuers: AtomicUsize,
}

pub struct LocalPkiServer {
    pub base_url: String,
    pub counters: Arc<Counters>,
    stop: Arc<AtomicBool>,
    address: std::net::SocketAddr,
    worker: Option<JoinHandle<()>>,
}

impl LocalPkiServer {
    /// Serves the hierarchy; `extra` are more certificates the OCSP responders answer for.
    pub fn start(extra: Vec<Certificate>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let counters = Arc::new(Counters::default());
        let stop = Arc::new(AtomicBool::new(false));
        let worker = {
            let counters = Arc::clone(&counters);
            let stop = Arc::clone(&stop);
            std::thread::spawn(move || {
                for stream in listener.incoming() {
                    if stop.load(Ordering::SeqCst) {
                        break;
                    }
                    if let Ok(stream) = stream {
                        serve(stream, &counters, &extra);
                    }
                }
            })
        };
        Self {
            base_url: format!("http://{address}"),
            counters,
            stop,
            address,
            worker: Some(worker),
        }
    }

    pub fn tsa_url(&self) -> String {
        format!("{}/tsp", self.base_url)
    }

    pub fn ocsp_url(&self) -> String {
        format!("{}/ocsp", self.base_url)
    }

    pub fn ca_issuers_url(&self) -> String {
        format!("{}/ca.p7b", self.base_url)
    }
}

impl Drop for LocalPkiServer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        let _ = TcpStream::connect(self.address);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

fn serve(stream: TcpStream, counters: &Counters, extra: &[Certificate]) {
    let mut reader = BufReader::new(stream);
    let mut request_line = String::new();
    if reader.read_line(&mut request_line).is_err() || request_line.is_empty() {
        return;
    }
    let path = request_line.split(' ').nth(1).unwrap_or("").to_owned();
    let mut length = 0;
    loop {
        let mut line = String::new();
        reader.read_line(&mut line).unwrap();
        if line == "\r\n" || line.is_empty() {
            break;
        }
        if let Some((name, value)) = line.split_once(':') {
            if name.eq_ignore_ascii_case("content-length") {
                length = value.trim().parse().unwrap();
            }
        }
    }
    let mut body = vec![0u8; length];
    reader.read_exact(&mut body).unwrap();
    let (status, content, media_type) = match path.as_str() {
        "/tsp" => {
            counters.time_stamps.fetch_add(1, Ordering::SeqCst);
            (200, time_stamp_response(&body), "application/timestamp-reply")
        }
        "/ocsp" => {
            counters.ocsp.fetch_add(1, Ordering::SeqCst);
            (200, ocsp_response(&body, extra), "application/ocsp-response")
        }
        "/ca.p7b" => {
            counters.ca_issuers.fetch_add(1, Ordering::SeqCst);
            (200, ca_issuers_bundle(), "application/pkcs7-mime")
        }
        "/large" => (200, vec![0u8; LARGE_ANSWER_BYTES], "application/octet-stream"),
        _ => (404, b"not found".to_vec(), "text/plain"),
    };
    let reason = if status == 200 { "OK" } else { "Not Found" };
    let head = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: {media_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        content.len()
    );
    let mut stream = reader.into_inner();
    let _ = stream.write_all(head.as_bytes());
    let _ = stream.write_all(&content);
}

// TimeStampReq { version, messageImprint { algorithm, hash }, reqPolicy?, nonce?, certReq? } → TimeStampResp.
fn time_stamp_response(request: &[u8]) -> Vec<u8> {
    let request = Asn1Node::parse(request).unwrap();
    let imprint = request.child(1).unwrap();
    let hash_oid = imprint.child(0).unwrap().child(0).unwrap().to_oid().unwrap();
    let hash = imprint.child(1).unwrap().to_octet_string().unwrap();
    let fields = request.children().unwrap();
    let nonce = fields
        .iter()
        .skip(2)
        .find(|f| f.has_tag(ua_der::tag::INTEGER))
        .map(|f| f.to_integer().unwrap());
    let certificate_requested = fields
        .iter()
        .any(|f| f.has_tag(ua_der::tag::BOOLEAN) && f.to_boolean().unwrap());
    let token = stamp_hash(&hash, &hash_oid, certificate_requested, nonce.as_ref());
    ua_der::sequence([ua_der::sequence([ua_der::integer_from_i64(0)]), token])
}

// OCSPRequest { TBSRequest { requestList { Request { CertID } } } } → the issuer's responder's answer.
fn ocsp_response(request: &[u8], extra: &[Certificate]) -> Vec<u8> {
    let request = Asn1Node::parse(request).unwrap();
    let cert_id = request
        .child(0)
        .unwrap()
        .child(0)
        .unwrap()
        .child(0)
        .unwrap()
        .child(0)
        .unwrap();
    let serial = cert_id.child(3).unwrap().to_integer().unwrap();
    let pki = Hierarchy::shared();
    let mut all = pki.all_certificates();
    all.extend(extra.iter().cloned());
    let subject = all
        .iter()
        .find(|c| c.serial_number() == &serial && !c.is_self_issued())
        .unwrap();
    let issuer = all.iter().find(|c| c.subject() == subject.issuer()).unwrap();
    respond(pki.responder_for(issuer).unwrap(), subject, issuer, false)
}

// A certs-only SignedData with the issuing CA, the TSA and the OCSP responder, as providers publish at caIssuers.
fn ca_issuers_bundle() -> Vec<u8> {
    let pki = Hierarchy::shared();
    let certificates = [&pki.issuing_ca, &pki.tsa, &pki.ocsp].map(|identity| identity.certificate.encoded().to_vec());
    let signed_data = ua_der::sequence([
        ua_der::integer_from_i64(1),
        ua_der::set_of(Vec::<Vec<u8>>::new()),
        ua_der::sequence([ua_der::object_identifier(oids::DATA)]),
        ua_der::implicit(0, &ua_der::set_of(certificates)),
        ua_der::set_of(Vec::<Vec<u8>>::new()),
    ]);
    ua_der::sequence([
        ua_der::object_identifier(oids::SIGNED_DATA),
        ua_der::explicit(0, &signed_data),
    ])
}
