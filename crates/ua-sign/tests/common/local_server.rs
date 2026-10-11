//! The hierarchy's time-stamping service, OCSP responders and caIssuers bundle over HTTP on 127.0.0.1: a minimal
//! HTTP/1.1 server on `std::net::TcpListener`, enough for ua-sign's HTTP clients. Requests are read with `ua-der`
//! directly, independently of `ua-pki`'s encoders.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::thread::JoinHandle;

use ua_der::Asn1Node;
use ua_pki::{Certificate, oids};

use super::{Hierarchy, respond, stamp_hash};

/// What the server counts, and the certificates it answers for besides the hierarchy's.
#[derive(Default)]
pub struct ServerState {
    pub time_stamps: AtomicUsize,
    pub ocsp: AtomicUsize,
    pub ca_issuers: AtomicUsize,
    pub extra_certificates: Mutex<Vec<Certificate>>,
}

pub struct LocalPkiServer {
    pub base_url: String,
    pub state: Arc<ServerState>,
    stop: Arc<AtomicBool>,
    address: SocketAddr,
    worker: Option<JoinHandle<()>>,
}

impl LocalPkiServer {
    /// Serves the hierarchy on a free port.
    pub fn start() -> Self {
        Self::start_on("127.0.0.1:0")
    }

    /// Serves the hierarchy on `address` (a fixed port where a recorded certificate names it).
    pub fn start_on(address: &str) -> Self {
        let listener = TcpListener::bind(address).unwrap_or_else(|error| panic!("{address}: {error}"));
        let address = listener.local_addr().unwrap();
        let state = Arc::new(ServerState::default());
        let stop = Arc::new(AtomicBool::new(false));
        let worker = {
            let state = Arc::clone(&state);
            let stop = Arc::clone(&stop);
            std::thread::spawn(move || {
                for stream in listener.incoming() {
                    if stop.load(Ordering::SeqCst) {
                        break;
                    }
                    if let Ok(stream) = stream {
                        serve(stream, &state);
                    }
                }
            })
        };
        Self {
            base_url: format!("http://{address}"),
            state,
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

    /// A certificate of the hierarchy's CAs the responders answer for, issued after the server started (it names
    /// the server's addresses).
    pub fn add_certificate(&self, certificate: Certificate) {
        self.state
            .extra_certificates
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(certificate);
    }

    pub fn time_stamp_requests(&self) -> usize {
        self.state.time_stamps.load(Ordering::SeqCst)
    }

    pub fn ocsp_requests(&self) -> usize {
        self.state.ocsp.load(Ordering::SeqCst)
    }

    pub fn ca_issuers_requests(&self) -> usize {
        self.state.ca_issuers.load(Ordering::SeqCst)
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

// Request line and headers, then exactly Content-Length bytes of body.
fn serve(stream: TcpStream, state: &ServerState) {
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
            state.time_stamps.fetch_add(1, Ordering::SeqCst);
            (200, time_stamp_response(&body), "application/timestamp-reply")
        }
        "/ocsp" => {
            state.ocsp.fetch_add(1, Ordering::SeqCst);
            let extra = state
                .extra_certificates
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .clone();
            (200, ocsp_response(&body, &extra), "application/ocsp-response")
        }
        "/ca.p7b" => {
            state.ca_issuers.fetch_add(1, Ordering::SeqCst);
            (200, ca_issuers_bundle(), "application/pkcs7-mime")
        }
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
    respond(pki.responder_for(issuer).unwrap(), subject, issuer)
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
