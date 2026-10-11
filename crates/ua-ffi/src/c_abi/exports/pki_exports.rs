//! JKS key stores, certificates, and signing and verifying files in the formats of the national PKI. Reports are
//! UTF-8 JSON; the levels T and LT and online verification reach the services over HTTP.

use std::ffi::c_char;

use time::OffsetDateTime;

use crate::c_abi::call_guard::run_call;
use crate::c_abi::marshalling::{
    read_bytes, read_bytes_list, read_files, read_key_store_request, read_optional_text, read_signing_options,
    read_text, write_buffer,
};
use crate::c_abi::types::{UaBuffer, UaBytes, UaKeyStoreRequest, UaNamedBytes, UaSigningOptions, UaStatus};
use crate::models::{SigningRequest, VerificationRequest};
use crate::operations::{certificate_details, key_store, signing, verification};
use crate::utils::to_json;

/// A new JKS store protected by `password` (the key too), with a DSTU 4145 key and its self-signed certificate.
///
/// # Safety
/// Every pointer is NULL or valid as its type says; outputs are written only on `UA_STATUS_OK`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ua_create_key_store(
    request: *const UaKeyStoreRequest,
    password: *const c_char,
    key_store: *mut UaBuffer,
    certificate: *mut UaBuffer,
    error_message: *mut UaBuffer,
) -> UaStatus {
    unsafe {
        run_call(error_message, || {
            let request = read_key_store_request(request, read_text(password, "The password")?)?;
            let created = key_store::create_key_store(&request, OffsetDateTime::now_utc())?;
            write_buffer(key_store, created.key_store)?;
            write_buffer(certificate, created.certificate)
        })
    }
}

/// The certificate (DER) of the signing key `alias`; NULL `alias`: the one signing key of the store.
///
/// # Safety
/// As `ua_create_key_store`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ua_get_certificate(
    key_store: UaBytes,
    password: *const c_char,
    alias: *const c_char,
    certificate: *mut UaBuffer,
    error_message: *mut UaBuffer,
) -> UaStatus {
    unsafe {
        run_call(error_message, || {
            let result = key_store::get_certificate(
                read_bytes(key_store, "The key store")?,
                read_text(password, "The password")?,
                read_optional_text(alias, "The alias")?,
            )?;
            write_buffer(certificate, result)
        })
    }
}

/// The entries of a store as a JSON array: alias, kind, created, certificates.
///
/// # Safety
/// As `ua_create_key_store`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ua_get_key_store_entries(
    key_store: UaBytes,
    password: *const c_char,
    entries_json: *mut UaBuffer,
    error_message: *mut UaBuffer,
) -> UaStatus {
    unsafe {
        run_call(error_message, || {
            let entries = key_store::get_key_store_entries(
                read_bytes(key_store, "The key store")?,
                read_text(password, "The password")?,
            )?;
            write_buffer(entries_json, to_json(&entries))
        })
    }
}

/// What a certificate (DER, PEM or base64) says, as a JSON object.
///
/// # Safety
/// As `ua_create_key_store`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ua_get_certificate_details(
    certificate: UaBytes,
    details_json: *mut UaBuffer,
    error_message: *mut UaBuffer,
) -> UaStatus {
    unsafe {
        run_call(error_message, || {
            let details = certificate_details::get_certificate_details(read_bytes(certificate, "The certificate")?)?;
            write_buffer(details_json, to_json(&details))
        })
    }
}

/// Signs `files` with the key `alias` of the store (NULL: its one signing key).
///
/// * `files` — the files to sign under their names; CAdES and ASiC-S take one
/// * `certificates` — CA certificates completing the signer's chain (DER, PEM or a bundle each); may be NULL with 0
///
/// # Safety
/// As `ua_create_key_store`; `files` and `certificates` hold the counts given.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ua_sign(
    key_store: UaBytes,
    password: *const c_char,
    alias: *const c_char,
    files: *const UaNamedBytes,
    files_count: usize,
    certificates: *const UaBytes,
    certificates_count: usize,
    options: *const UaSigningOptions,
    signature: *mut UaBuffer,
    error_message: *mut UaBuffer,
) -> UaStatus {
    unsafe {
        run_call(error_message, || {
            let request = SigningRequest {
                key_store: read_bytes(key_store, "The key store")?.to_vec(),
                password: read_text(password, "The password")?.to_owned(),
                alias: read_optional_text(alias, "The alias")?.map(str::to_owned),
                files: read_files(files, files_count, "A file to sign")?,
                certificates: read_bytes_list(certificates, certificates_count, "A certificate")?,
                options: read_signing_options(options)?,
            };
            write_buffer(signature, signing::sign(&request)?)
        })
    }
}

/// Verifies a signature of any format and writes the report as JSON; an invalid signature is `UA_STATUS_OK` with
/// `"is_valid": false`.
///
/// * `data` — the data of a detached signature under the names its references use; one file stands for any name
/// * `trust_anchors` — trusted roots (DER, PEM or a bundle each)
/// * `certificates` — further certificates for the paths
/// * `is_online` — ask OCSP responders and caIssuers over the network
///
/// # Safety
/// As `ua_create_key_store`; the arrays hold the counts given.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ua_verify(
    signature: UaBytes,
    data: *const UaNamedBytes,
    data_count: usize,
    trust_anchors: *const UaBytes,
    trust_anchors_count: usize,
    certificates: *const UaBytes,
    certificates_count: usize,
    is_online: bool,
    report_json: *mut UaBuffer,
    error_message: *mut UaBuffer,
) -> UaStatus {
    unsafe {
        run_call(error_message, || {
            let request = VerificationRequest {
                signature: read_bytes(signature, "The signature")?.to_vec(),
                data: read_files(data, data_count, "A data file")?,
                trust_anchors: read_bytes_list(trust_anchors, trust_anchors_count, "A trust anchor")?,
                certificates: read_bytes_list(certificates, certificates_count, "A certificate")?,
                is_online,
            };
            let summary = verification::verify(&request, OffsetDateTime::now_utc())?;
            write_buffer(report_json, to_json(&summary))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::c_abi::marshalling::release_buffer;
    use crate::c_abi::types::{
        UA_SIGNATURE_FORMAT_ASIC_E, UA_SIGNATURE_FORMAT_CADES, UA_SIGNATURE_HASH_DSTU7564, UA_SIGNATURE_LEVEL_B,
    };
    use std::ptr;

    fn empty_buffer() -> UaBuffer {
        UaBuffer {
            data: ptr::null_mut(),
            len: 0,
        }
    }

    fn lend(bytes: &[u8]) -> UaBytes {
        UaBytes {
            data: bytes.as_ptr(),
            len: bytes.len(),
        }
    }

    fn take(buffer: UaBuffer) -> Vec<u8> {
        let bytes = unsafe { std::slice::from_raw_parts(buffer.data, buffer.len) }.to_vec();
        unsafe { release_buffer(buffer) };
        bytes
    }

    fn create_store() -> (Vec<u8>, Vec<u8>) {
        let request = UaKeyStoreRequest {
            subject: c"CN=Signer,O=Organization,C=UA".as_ptr(),
            alias: ptr::null(),
            m: 257,
            validity_days: 30,
            signature_hash: UA_SIGNATURE_HASH_DSTU7564,
        };
        let (mut store, mut certificate) = (empty_buffer(), empty_buffer());
        let status = unsafe {
            ua_create_key_store(
                &request,
                c"password".as_ptr(),
                &mut store,
                &mut certificate,
                ptr::null_mut(),
            )
        };
        assert_eq!(status, UaStatus::Ok);
        (take(store), take(certificate))
    }

    #[test]
    fn a_file_signed_through_the_abi_verifies_through_it() {
        let (store, certificate) = create_store();
        let files = [
            UaNamedBytes {
                name: c"a.txt".as_ptr(),
                content: lend(b"first"),
            },
            UaNamedBytes {
                name: c"b.txt".as_ptr(),
                content: lend(b"second"),
            },
        ];
        let options = UaSigningOptions {
            format: UA_SIGNATURE_FORMAT_ASIC_E,
            level: UA_SIGNATURE_LEVEL_B,
            hash: UA_SIGNATURE_HASH_DSTU7564,
            is_detached: false,
            has_content_time_stamp: false,
            tsa_url: ptr::null(),
            ocsp_url: ptr::null(),
        };
        let mut signature = empty_buffer();
        let status = unsafe {
            ua_sign(
                lend(&store),
                c"password".as_ptr(),
                ptr::null(),
                files.as_ptr(),
                files.len(),
                ptr::null(),
                0,
                &options,
                &mut signature,
                ptr::null_mut(),
            )
        };
        assert_eq!(status, UaStatus::Ok);
        let signature = take(signature);

        let trust = [lend(&certificate)];
        let mut report = empty_buffer();
        let status = unsafe {
            ua_verify(
                lend(&signature),
                ptr::null(),
                0,
                trust.as_ptr(),
                trust.len(),
                ptr::null(),
                0,
                false,
                &mut report,
                ptr::null_mut(),
            )
        };
        assert_eq!(status, UaStatus::Ok);
        let report: serde_json::Value = serde_json::from_slice(&take(report)).unwrap();
        assert_eq!(report["is_valid"], true, "{report:#}");
        assert_eq!(report["signed_files"], serde_json::json!(["a.txt", "b.txt"]));
    }

    #[test]
    fn a_wrong_password_and_two_files_for_cades_are_told_apart() {
        let (store, _) = create_store();
        let mut certificate = empty_buffer();
        let mut message = empty_buffer();
        let status = unsafe {
            ua_get_certificate(
                lend(&store),
                c"wrong".as_ptr(),
                ptr::null(),
                &mut certificate,
                &mut message,
            )
        };
        assert_eq!(status, UaStatus::WrongPassword);
        assert!(!take(message).is_empty());

        let file = UaNamedBytes {
            name: c"a.txt".as_ptr(),
            content: lend(b"a"),
        };
        let files = [file, file];
        let options = UaSigningOptions {
            format: UA_SIGNATURE_FORMAT_CADES,
            level: UA_SIGNATURE_LEVEL_B,
            hash: UA_SIGNATURE_HASH_DSTU7564,
            is_detached: false,
            has_content_time_stamp: false,
            tsa_url: ptr::null(),
            ocsp_url: ptr::null(),
        };
        let mut signature = empty_buffer();
        let status = unsafe {
            ua_sign(
                lend(&store),
                c"password".as_ptr(),
                ptr::null(),
                files.as_ptr(),
                files.len(),
                ptr::null(),
                0,
                &options,
                &mut signature,
                ptr::null_mut(),
            )
        };
        assert_eq!(status, UaStatus::InvalidArgument);
    }
}
