//! Signing files in CAdES, XAdES, ASiC-S or ASiC-E at levels B, T and LT, as `ua-sign sign` does: a plan of the
//! request, then the signature with the services the binding connected for the plan.

use ua_cryptography_pki::{
    CadesOptions, CadesSigner, Certificate, JksKeyStore, SignatureLevel, SignatureServices, SignedFile, SigningKey,
    XadesSigner, asic_container, certificate_files,
};

use crate::errors::OperationFailure;
use crate::models::simple_types::SignatureFormat;
use crate::models::{PendingSignature, SigningPlan, SigningRequest};

/// The key, the chain and the services the request needs; refuses T and LT when no time-stamping service is known.
pub fn plan_signature(request: &SigningRequest) -> Result<SigningPlan, OperationFailure> {
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
    Ok(SigningPlan {
        signer,
        extra_certificates,
        tsa_url: tsa_url.filter(|_| needs_time_stamps),
        is_long_term: options.level >= SignatureLevel::LT,
    })
}

/// The signature of the request's files: [`prepare_signature`], then [`complete_signature`].
pub fn sign(
    request: &SigningRequest,
    plan: &SigningPlan,
    services: &SignatureServices<'_>,
) -> Result<Vec<u8>, OperationFailure> {
    let pending = prepare_signature(request, plan, services)?;
    complete_signature(request, plan, &pending, services)
}

/// The signed part of the signature and its value; only a content time-stamp asks a service here.
pub fn prepare_signature(
    request: &SigningRequest,
    plan: &SigningPlan,
    services: &SignatureServices<'_>,
) -> Result<PendingSignature, OperationFailure> {
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
    let cades = || CadesSigner::new(plan.signer.clone(), services.clone());
    let xades = || XadesSigner::new(plan.signer.clone(), services.clone());
    let file = &files[0];
    Ok(match options.format {
        SignatureFormat::Cades => PendingSignature::Cades(cades().prepare(&file.content, &cades_options)?),
        SignatureFormat::AsicS => PendingSignature::AsicS(cades().prepare(&file.content, &cades_options)?),
        SignatureFormat::Xades => PendingSignature::Xades(xades().prepare(files, hash_oid, options.level)?),
        SignatureFormat::AsicE => PendingSignature::AsicE(xades().prepare(files, hash_oid, options.level)?),
    })
}

/// The finished signature of `pending` over the request's files: T asks the time-stamping service, LT the OCSP responders and
/// caIssuers. Asking again with the same answers gives the same bytes.
pub fn complete_signature(
    request: &SigningRequest,
    plan: &SigningPlan,
    pending: &PendingSignature,
    services: &SignatureServices<'_>,
) -> Result<Vec<u8>, OperationFailure> {
    let files = &request.files;
    let cades = || CadesSigner::new(plan.signer.clone(), services.clone());
    let xades = || XadesSigner::new(plan.signer.clone(), services.clone());
    match pending {
        PendingSignature::Cades(pending) => Ok(cades().complete(pending)?),
        PendingSignature::AsicS(pending) => {
            let file = &files[0];
            let signature = cades().complete(pending)?;
            Ok(asic_container::create_asic_s(&file.name, &file.content, &signature)?)
        }
        PendingSignature::Xades(pending) => Ok(xades().complete(pending)?.to_bytes()),
        PendingSignature::AsicE(pending) => {
            let signature = xades().complete(pending)?;
            Ok(asic_container::create_asic_e(files, &signature)?)
        }
    }
}

/// The certificates of every input: DER, PEM blocks or a CMS bundle.
pub fn parse_certificates(inputs: &[Vec<u8>]) -> Result<Vec<Certificate>, OperationFailure> {
    let mut certificates = Vec::new();
    for input in inputs {
        certificates.extend(certificate_files::parse(input)?);
    }
    Ok(certificates)
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
