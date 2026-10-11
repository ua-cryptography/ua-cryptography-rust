//! Verifies a signed file of any supported format, recognised by its content: ASiC-S / ASiC-E (ZIP), XAdES (XML) or
//! CAdES (DER, PEM or base64).

use ua_xml_c14n::DocumentText;

use crate::asic_container::{self, ContainerContents};
use crate::cades::cades_verifier;
use crate::errors::VerificationError;
use crate::validation::{ValidationOptions, VerificationReport, VerificationResult};
use crate::xades::{SignedFile, xades_verifier};

/// The title of the report on an ASiC container's structure, which comes before the signatures' reports.
pub const CONTAINER_TITLE: &str = "container";
/// The format of a XAdES document.
const XADES_FORMAT: &str = "XAdES (XML)";
/// What an XAdES signature entry of ASiC is named like.
const SIGNATURE_ENTRY_WORD: &str = "signature";
/// The extension of XAdES entries.
const XML_EXTENSION: &str = ".xml";
/// The extension of CAdES entries.
const P7S_EXTENSION: &str = ".p7s";

/// Verifies `signature`. `detached` resolves the data of detached signatures: it is called with the file name a
/// XAdES reference uses, or with none for a detached CAdES; it returns none when the data is not available.
pub fn verify(
    signature: &[u8],
    detached: &dyn Fn(Option<&str>) -> Option<Vec<u8>>,
    options: &ValidationOptions<'_>,
) -> Result<VerificationResult, VerificationError> {
    if asic_container::looks_like_zip(signature) {
        return verify_asic(signature, options);
    }
    if ua_xml_c14n::looks_like_xml(signature) {
        let text = DocumentText::decode(signature)?;
        let document = text.parse()?;
        let resolve = |name: &str| detached(Some(name));
        let reports = xades_verifier::verify(&document, &resolve, options);
        let mut signed_files: Vec<SignedFile> = Vec::new();
        for name in xades_verifier::external_references(&document) {
            if signed_files.iter().any(|file| file.name == name) {
                continue;
            }
            if let Some(content) = detached(Some(&name)) {
                signed_files.push(SignedFile { name, content });
            }
        }
        return Ok(VerificationResult {
            format: XADES_FORMAT.to_owned(),
            signatures: reports,
            signed_files,
        });
    }
    cades_verifier::verify(signature, detached(None).as_deref(), options)
}

fn verify_asic(container: &[u8], options: &ValidationOptions<'_>) -> Result<VerificationResult, VerificationError> {
    let contents = asic_container::read_container(container)?;
    let mime_type = contents.mime_type.as_deref();
    let mut structure = VerificationReport::new(CONTAINER_TITLE);
    check_mime_type(&contents, &mut structure);
    let data = entries_where(&contents, asic_container::is_data_entry);
    let cades_entries = entries_where(&contents, is_cades_entry);

    let mut reports = Vec::new();
    let format = match mime_type {
        Some(asic_container::ASIC_S_MIME_TYPE) => {
            reports.extend(verify_asic_s_signatures(
                &data,
                &cades_entries,
                options,
                &mut structure,
            )?);
            "ASiC-S"
        }
        Some(asic_container::ASIC_E_MIME_TYPE) => {
            check_manifest(&contents, &data, &mut structure)?;
            if !cades_entries.is_empty() {
                structure.warn(
                    "signatures",
                    "CAdES signatures in ASiC-E (ASiCManifest) are not verified",
                );
            }
            "ASiC-E"
        }
        _ => {
            let details = format!("'{}' is not an ASiC media type", shown_mime_type(mime_type));
            structure.fail("mimetype", &details);
            "ZIP"
        }
    };

    let (xades_reports, mut covered) = verify_xades_entries(&contents, options)?;
    reports.extend(xades_reports);
    if mime_type == Some(asic_container::ASIC_S_MIME_TYPE) && !cades_entries.is_empty() && data.len() == 1 {
        covered.push(data[0].name.clone());
    }
    for file in data.iter().filter(|file| !covered.contains(&file.name)) {
        let name = format!("file '{}'", file.name);
        structure.fail(&name, "is in the container but not covered by any signature");
    }
    if reports.is_empty() {
        structure.fail("signatures", "the container holds no signature");
    }

    let mut signatures = vec![structure];
    signatures.extend(reports);
    Ok(VerificationResult {
        format: format.to_owned(),
        signatures,
        signed_files: data.into_iter().cloned().collect(),
    })
}

fn check_mime_type(contents: &ContainerContents, structure: &mut VerificationReport) {
    let is_first_and_stored = contents.is_mime_type_first_and_stored;
    let details = if is_first_and_stored {
        format!("'{}', first and stored", shown_mime_type(contents.mime_type.as_deref()))
    } else {
        "the mimetype entry must be first and uncompressed".to_owned()
    };
    structure.check("mimetype", is_first_and_stored, &details);
}

// ASiC-S: exactly one data file, which every CAdES entry signs detached.
fn verify_asic_s_signatures(
    data: &[&SignedFile],
    cades_entries: &[&SignedFile],
    options: &ValidationOptions<'_>,
    structure: &mut VerificationReport,
) -> Result<Vec<VerificationReport>, VerificationError> {
    let single = match data {
        [single] => Some(single),
        _ => None,
    };
    let details = match single {
        Some(single) => format!("one data file '{}'", single.name),
        None => format!("{} data files; ASiC-S holds exactly one", data.len()),
    };
    structure.check("data", single.is_some(), &details);
    let mut reports = Vec::new();
    for entry in cades_entries {
        let content = single.map(|single| single.content.as_slice());
        let result = cades_verifier::verify(&entry.content, content, options)?;
        reports.extend(titled(result.signatures, &entry.name));
    }
    Ok(reports)
}

// Every XAdES entry, its references resolved inside the container; returns the reports and the files covered.
fn verify_xades_entries(
    contents: &ContainerContents,
    options: &ValidationOptions<'_>,
) -> Result<(Vec<VerificationReport>, Vec<String>), VerificationError> {
    let resolve = |name: &str| {
        let is_data = !name.starts_with(asic_container::META_INF);
        contents.find(name).filter(|_| is_data).map(<[u8]>::to_vec)
    };
    let mut reports = Vec::new();
    let mut covered = Vec::new();
    for entry in entries_where(contents, is_xades_entry) {
        let text = DocumentText::decode(&entry.content)?;
        let document = text.parse()?;
        covered.extend(xades_verifier::external_references(&document));
        reports.extend(titled(
            xades_verifier::verify(&document, &resolve, options),
            &entry.name,
        ));
    }
    Ok((reports, covered))
}

fn entries_where(contents: &ContainerContents, is_wanted: fn(&str) -> bool) -> Vec<&SignedFile> {
    contents.entries.iter().filter(|entry| is_wanted(&entry.name)).collect()
}

fn check_manifest(
    contents: &ContainerContents,
    data: &[&SignedFile],
    structure: &mut VerificationReport,
) -> Result<(), VerificationError> {
    let Some(manifest) = contents.find(asic_container::MANIFEST_ENTRY) else {
        structure.warn("manifest", "META-INF/manifest.xml is missing");
        return Ok(());
    };
    let text = DocumentText::decode(manifest)?;
    let document = text.parse()?;
    let namespace = asic_container::MANIFEST_NAMESPACE;
    let listed: Vec<&str> = document
        .descendants()
        .filter(|node| {
            node.is_element()
                && node.tag_name().name() == "file-entry"
                && node.tag_name().namespace() == Some(namespace)
        })
        .filter_map(|node| node.attribute((namespace, "full-path")))
        .collect();
    let missing: Vec<&str> = data
        .iter()
        .map(|file| file.name.as_str())
        .filter(|name| !listed.contains(name))
        .collect();
    if missing.is_empty() {
        structure.pass("manifest", &format!("lists all {} data files", data.len()));
    } else {
        structure.warn("manifest", &format!("does not list {}", missing.join(", ")));
    }
    Ok(())
}

fn titled(reports: Vec<VerificationReport>, entry: &str) -> Vec<VerificationReport> {
    reports
        .into_iter()
        .map(|mut report| {
            report.title = format!("{} ({entry})", report.title);
            report
        })
        .collect()
}

// A missing mimetype entry is shown as empty quotes.
fn shown_mime_type(mime_type: Option<&str>) -> &str {
    mime_type.map_or("", |mime_type| mime_type)
}

fn is_xades_entry(name: &str) -> bool {
    let lower = name.to_lowercase();
    name.starts_with(asic_container::META_INF) && lower.contains(SIGNATURE_ENTRY_WORD) && lower.ends_with(XML_EXTENSION)
}

fn is_cades_entry(name: &str) -> bool {
    name.starts_with(asic_container::META_INF) && name.to_lowercase().ends_with(P7S_EXTENSION)
}
