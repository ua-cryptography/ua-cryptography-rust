//! Signing files in CAdES, XAdES, ASiC-S or ASiC-E at levels B, T and LT, as `ua-sign sign` does.

use ua_pki::{
    CadesOptions, CadesSigner, Certificate, JksKeyStore, SignatureLevel, SignatureServices, SignedFile, SigningKey,
    XadesSigner, asic_container, certificate_files,
};

use crate::errors::OperationFailure;
use crate::models::SigningRequest;
use crate::models::simple_types::SignatureFormat;
use crate::operations::service_clients::ServiceClients;

/// The signature of the request's files; T and LT ask the services over the network.
pub fn sign(request: &SigningRequest) -> Result<Vec<u8>, OperationFailure> {
    check_files(request)?;
    let options = &request.options;
    let store = JksKeyStore::load(&request.key_store, &request.password)?;
    let signer = SigningKey::from_jks(&store, &request.password, request.alias.as_deref(), None)?;
    let extra_certificates = parse_certificates(&request.certificates)?;

    let needs_time_stamps = options.level >= SignatureLevel::T || options.has_content_time_stamp;
    let tsa_url = match &options.tsa_url {
        Some(url) => Some(url.clone()),
        None => signer.chain().iter().flat_map(Certificate::time_stamp_urls).next(),
    };
    if needs_time_stamps && tsa_url.is_none() {
        return Err(OperationFailure::invalid_argument(
            "No time-stamping service: the certificate names none, and none was given.",
        ));
    }
    let clients = ServiceClients::connect(
        tsa_url.as_deref().filter(|_| needs_time_stamps),
        options.level >= SignatureLevel::LT,
        options.ocsp_url.as_deref(),
    )?;
    let services = SignatureServices {
        time_stamps: clients.time_stamps(),
        ocsp: clients.ocsp(),
        downloads: clients.downloads(),
        extra_certificates,
    };
    create_signature(request, signer, services)
}

/// The certificates of every input: DER, PEM blocks or a CMS bundle.
pub fn parse_certificates(inputs: &[Vec<u8>]) -> Result<Vec<Certificate>, OperationFailure> {
    let mut certificates = Vec::new();
    for input in inputs {
        certificates.extend(certificate_files::parse(input)?);
    }
    Ok(certificates)
}

fn create_signature(
    request: &SigningRequest,
    signer: SigningKey,
    services: SignatureServices<'_>,
) -> Result<Vec<u8>, OperationFailure> {
    let options = &request.options;
    let files = &request.files;
    let hash_oid = options.hash.oid();
    let cades_options = CadesOptions {
        hash_oid: hash_oid.to_owned(),
        is_detached: options.is_detached || options.format == SignatureFormat::AsicS,
        level: options.level,
        has_content_time_stamp: options.has_content_time_stamp,
        ..CadesOptions::default()
    };
    let file = &files[0];
    match options.format {
        SignatureFormat::Cades => Ok(CadesSigner::new(signer, services).sign(&file.content, &cades_options)?),
        SignatureFormat::AsicS => {
            let cades = CadesSigner::new(signer, services).sign(&file.content, &cades_options)?;
            Ok(asic_container::create_asic_s(&file.name, &file.content, &cades)?)
        }
        SignatureFormat::Xades => {
            Ok(XadesSigner::new(signer, services).sign_to_bytes(files, hash_oid, options.level)?)
        }
        SignatureFormat::AsicE => {
            let xades = XadesSigner::new(signer, services).sign(files, hash_oid, options.level)?;
            Ok(asic_container::create_asic_e(files, &xades)?)
        }
    }
}

// One file at least, one for CAdES inside; distinct names; detached and content time-stamps are CAdES options.
fn check_files(request: &SigningRequest) -> Result<(), OperationFailure> {
    let options = &request.options;
    let files: &[SignedFile] = &request.files;
    if files.is_empty() {
        return Err(OperationFailure::invalid_argument("Nothing to sign: no file given."));
    }
    if files.len() > 1 && options.format.is_cades() {
        return Err(OperationFailure::invalid_argument(
            "CAdES and ASiC-S sign one file; XAdES and ASiC-E sign several.",
        ));
    }
    if options.is_detached && options.format != SignatureFormat::Cades {
        return Err(OperationFailure::invalid_argument(
            "Only a CAdES signature is detached.",
        ));
    }
    if options.has_content_time_stamp && !options.format.is_cades() {
        return Err(OperationFailure::invalid_argument(
            "A content time-stamp is a CAdES attribute: CAdES or ASiC-S only.",
        ));
    }
    let mut names: Vec<&str> = files.iter().map(|file| file.name.as_str()).collect();
    names.sort_unstable();
    names.dedup();
    if names.len() != files.len() {
        return Err(OperationFailure::invalid_argument("Two files to sign share one name."));
    }
    Ok(())
}
