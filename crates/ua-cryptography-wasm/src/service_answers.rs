//! The answers of the PKI services fetched so far, standing behind the service traits of `ua-cryptography-pki`,
//! whose signers and verifier ask synchronously while `fetch` answers asynchronously.
//!
//! A question with no answer yet is written down and refused; [`ServiceAnswers::run_until_answered`] fetches what
//! was written down and runs the operation again, until a run asks nothing new. A run repeats only what does not
//! depend on chance: the signature value is fixed before the time-stamp over it is asked
//! (`signing::prepare_signature`, then `signing::complete_signature`).

use std::cell::RefCell;
use std::collections::HashMap;

use num_bigint::BigInt;
use rand_core::{OsRng, RngCore};
use ua_cryptography_operations::models::SigningPlan;
use ua_cryptography_pki::{
    Certificate, CertificateSource, OcspResponse, OcspService, ServiceError, SignatureServices, TimeStampService,
    TimeStampToken, certificate_files, time_stamp_protocol,
};

use crate::js_imports::{StartedRequest, start_get, start_post};

/// The most runs of one operation: one per CA certificate downloaded along a path, one for the OCSP answers, one for
/// the time-stamp.
const MAX_RUNS: usize = 12;
/// The bytes of an OCSP request nonce, as the native client sends.
const OCSP_NONCE_BYTES: usize = 16;
/// The media type of an OCSPRequest.
const OCSP_REQUEST_MEDIA_TYPE: &str = "application/ocsp-request";
/// Why a question is refused before its answer is fetched; read only when the runs ran out.
const NOT_ASKED: &str = "not asked: the operation asked too many questions";

/// A time-stamp request: the message imprint and its hash.
type TimeStampQuestion = (Vec<u8>, String);
/// An OCSP request: the certificate, its issuer (DER) and the hash of the CertID.
type OcspQuestion = (Vec<u8>, Vec<u8>, String);

/// A question to a service with no answer yet.
#[derive(PartialEq)]
enum ServiceQuestion {
    TimeStamp {
        url: String,
        hash: Vec<u8>,
        hash_oid: String,
    },
    Ocsp {
        url: String,
        certificate: Box<Certificate>,
        issuer: Box<Certificate>,
        hash_oid: String,
    },
    Download {
        url: String,
    },
}

/// A question whose request is on its way, with what checking the answer needs.
enum StartedQuestion {
    TimeStamp {
        key: TimeStampQuestion,
        nonce: BigInt,
        request: StartedRequest,
    },
    Ocsp {
        key: OcspQuestion,
        request: Result<StartedRequest, ServiceError>,
    },
    Download {
        url: String,
        request: StartedRequest,
    },
}

/// The time-stamping service at `tsa_url`, the OCSP responders (`ocsp_url` for all, else each certificate's) and
/// the caIssuers downloads, answered from what was fetched.
pub(crate) struct ServiceAnswers {
    tsa_url: Option<String>,
    ocsp_url: Option<String>,
    time_stamps: RefCell<HashMap<TimeStampQuestion, Result<TimeStampToken, ServiceError>>>,
    ocsp_responses: RefCell<HashMap<OcspQuestion, Result<OcspResponse, ServiceError>>>,
    downloads: RefCell<HashMap<String, Result<Vec<Certificate>, ServiceError>>>,
    questions: RefCell<Vec<ServiceQuestion>>,
}

impl ServiceAnswers {
    /// No answer yet; `tsa_url` is the time-stamping service, `ocsp_url` overrides every certificate's responder.
    pub(crate) fn new(tsa_url: Option<String>, ocsp_url: Option<String>) -> Self {
        Self {
            tsa_url,
            ocsp_url,
            time_stamps: RefCell::default(),
            ocsp_responses: RefCell::default(),
            downloads: RefCell::default(),
            questions: RefCell::default(),
        }
    }

    /// The services a signer of `plan` uses: these answers for what the plan needs, and its CA certificates.
    pub(crate) fn signature_services(&self, plan: &SigningPlan) -> SignatureServices<'_> {
        SignatureServices {
            time_stamps: plan.tsa_url.is_some().then_some(self as &dyn TimeStampService),
            ocsp: plan.is_long_term.then_some(self as &dyn OcspService),
            downloads: plan.is_long_term.then_some(self as &dyn CertificateSource),
            extra_certificates: plan.extra_certificates.clone(),
        }
    }

    /// The outcome of `operation` once it asks nothing unanswered: between runs, the questions of the last run are
    /// fetched all at once. A question that failed is answered with its failure.
    pub(crate) async fn run_until_answered<T>(&self, mut operation: impl FnMut() -> T) -> T {
        let mut outcome = operation();
        for _ in 1..MAX_RUNS {
            if self.questions.borrow().is_empty() {
                break;
            }
            self.fetch_answers().await;
            outcome = operation();
        }
        outcome
    }

    async fn fetch_answers(&self) {
        let questions = self.questions.take();
        let started: Vec<StartedQuestion> = questions.into_iter().map(start_question).collect();
        for question in started {
            self.keep_answer(question).await;
        }
    }

    async fn keep_answer(&self, question: StartedQuestion) {
        match question {
            StartedQuestion::TimeStamp { key, nonce, request } => {
                let token = request
                    .into_answer()
                    .await
                    .and_then(|answer| Ok(time_stamp_protocol::parse_response(&answer, &key.0, &key.1, &nonce)?));
                self.time_stamps.borrow_mut().insert(key, token);
            }
            StartedQuestion::Ocsp { key, request } => {
                let response = match request {
                    Ok(request) => request
                        .into_answer()
                        .await
                        .and_then(|answer| Ok(OcspResponse::load(&answer)?)),
                    Err(error) => Err(error),
                };
                self.ocsp_responses.borrow_mut().insert(key, response);
            }
            StartedQuestion::Download { url, request } => {
                let certificates = request
                    .into_answer()
                    .await
                    .and_then(|answer| Ok(certificate_files::parse(&answer)?));
                self.downloads.borrow_mut().insert(url, certificates);
            }
        }
    }

    // Written down once however often a run asks it.
    fn ask(&self, question: ServiceQuestion) {
        let mut questions = self.questions.borrow_mut();
        if !questions.contains(&question) {
            questions.push(question);
        }
    }
}

impl TimeStampService for ServiceAnswers {
    fn get_token(&self, hash: &[u8], hash_oid: &str) -> Result<TimeStampToken, ServiceError> {
        let Some(url) = &self.tsa_url else {
            unreachable!("a time-stamp is asked only of the services of a plan that names a time-stamping service");
        };
        let key = (hash.to_vec(), hash_oid.to_owned());
        if let Some(token) = self.time_stamps.borrow().get(&key) {
            return token.clone();
        }
        self.ask(ServiceQuestion::TimeStamp {
            url: url.clone(),
            hash: key.0,
            hash_oid: key.1,
        });
        Err(not_asked(url))
    }
}

impl OcspService for ServiceAnswers {
    fn find_response(
        &self,
        certificate: &Certificate,
        issuer: &Certificate,
        hash_oid: &str,
    ) -> Result<Option<OcspResponse>, ServiceError> {
        let url = match &self.ocsp_url {
            Some(url) => url.clone(),
            None => match certificate.ocsp_urls().into_iter().next() {
                Some(url) => url,
                None => return Ok(None),
            },
        };
        let key = (
            certificate.encoded().to_vec(),
            issuer.encoded().to_vec(),
            hash_oid.to_owned(),
        );
        if let Some(response) = self.ocsp_responses.borrow().get(&key) {
            return response.clone().map(Some);
        }
        self.ask(ServiceQuestion::Ocsp {
            url: url.clone(),
            certificate: Box::new(certificate.clone()),
            issuer: Box::new(issuer.clone()),
            hash_oid: key.2,
        });
        Err(not_asked(&url))
    }
}

impl CertificateSource for ServiceAnswers {
    fn download_certificates(&self, url: &str) -> Result<Vec<Certificate>, ServiceError> {
        if let Some(certificates) = self.downloads.borrow().get(url) {
            return certificates.clone();
        }
        self.ask(ServiceQuestion::Download { url: url.to_owned() });
        Err(not_asked(url))
    }
}

// The request of `question`, sent; the nonces are fresh, as the native clients make them.
fn start_question(question: ServiceQuestion) -> StartedQuestion {
    match question {
        ServiceQuestion::TimeStamp { url, hash, hash_oid } => {
            let nonce = time_stamp_protocol::create_nonce();
            let body = time_stamp_protocol::create_request(&hash, &hash_oid, &nonce, None);
            StartedQuestion::TimeStamp {
                request: start_post(&url, &body, time_stamp_protocol::REQUEST_MEDIA_TYPE),
                key: (hash, hash_oid),
                nonce,
            }
        }
        ServiceQuestion::Ocsp {
            url,
            certificate,
            issuer,
            hash_oid,
        } => {
            let mut nonce = [0u8; OCSP_NONCE_BYTES];
            OsRng.fill_bytes(&mut nonce);
            let request = match OcspResponse::create_request(&certificate, &issuer, &hash_oid, &nonce) {
                Ok(body) => Ok(start_post(&url, &body, OCSP_REQUEST_MEDIA_TYPE)),
                Err(error) => Err(ServiceError::from(error)),
            };
            StartedQuestion::Ocsp {
                key: (certificate.encoded().to_vec(), issuer.encoded().to_vec(), hash_oid),
                request,
            }
        }
        ServiceQuestion::Download { url } => StartedQuestion::Download {
            request: start_get(&url),
            url,
        },
    }
}

fn not_asked(url: &str) -> ServiceError {
    ServiceError::Transport {
        url: url.to_owned(),
        message: NOT_ASKED.to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::OffsetDateTime;
    use ua_cryptography_operations::models::KeyStoreRequest;
    use ua_cryptography_operations::models::simple_types::SignatureHash;
    use ua_cryptography_operations::operations::key_store;
    use ua_cryptography_pki::oids;

    const TSA_URL: &str = "http://tsa.test/tsp";

    // Self-signed: it names no OCSP responder and no caIssuers.
    fn self_signed_certificate() -> Certificate {
        let request = KeyStoreRequest {
            subject: "CN=Signer,C=UA".to_owned(),
            alias: "key".to_owned(),
            m: 257,
            validity_days: 1,
            signature_hash: SignatureHash::Dstu7564,
            password: "password".to_owned(),
        };
        let created = key_store::create_key_store(&request, OffsetDateTime::now_utc()).unwrap();
        Certificate::load(&created.certificate).unwrap()
    }

    #[test]
    fn a_time_stamp_is_written_down_once_and_refused_until_fetched() {
        let answers = ServiceAnswers::new(Some(TSA_URL.to_owned()), None);
        for _ in 0..2 {
            let refusal = answers.get_token(&[1, 2, 3], oids::DSTU7564_256).unwrap_err();
            assert!(
                matches!(refusal, ServiceError::Transport { ref url, .. } if url == TSA_URL),
                "{refusal}"
            );
        }
        assert_eq!(answers.questions.borrow().len(), 1);
    }

    #[test]
    fn a_certificate_naming_no_responder_asks_nothing() {
        let answers = ServiceAnswers::new(None, None);
        let certificate = self_signed_certificate();
        assert_eq!(
            answers.find_response(&certificate, &certificate, oids::DSTU7564_256),
            Ok(None)
        );
        assert!(answers.questions.borrow().is_empty());
    }

    #[test]
    fn the_overriding_responder_is_asked_about_any_certificate() {
        let answers = ServiceAnswers::new(None, Some("http://ocsp.test/".to_owned()));
        let certificate = self_signed_certificate();
        assert!(
            answers
                .find_response(&certificate, &certificate, oids::DSTU7564_256)
                .is_err()
        );
        assert_eq!(answers.questions.borrow().len(), 1);
    }

    #[test]
    fn a_download_is_written_down_once_per_address() {
        let answers = ServiceAnswers::new(None, None);
        for url in ["http://ca.test/a.p7b", "http://ca.test/a.p7b", "http://ca.test/b.p7b"] {
            assert!(answers.download_certificates(url).is_err());
        }
        assert_eq!(answers.questions.borrow().len(), 2);
    }
}
