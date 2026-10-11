//! Associated Signature Containers (ETSI EN 319 162): ZIP archives whose first entry, stored uncompressed, is the media
//! type. ASiC-S holds one data file and META-INF/signature.p7s (a detached CAdES); ASiC-E holds data files,
//! META-INF/manifest.xml and META-INF/signatures*.xml with XAdES signatures (docs/signature-formats.md, sections 8
//! and 10).

use std::io::{Cursor, Read, Write};

use ua_cryptography_xml_c14n::escape_attribute;
use zip::write::SimpleFileOptions;
use zip::{CompressionMethod, ZipArchive, ZipWriter};

use crate::errors::ContainerError;
use crate::xades::xml_element::XmlElement;
use crate::xades::{SignedFile, XML_DECLARATION, XadesSignature, mime_type_of};
use crate::xml_namespaces;

/// The media type of ASiC-S.
pub const ASIC_S_MIME_TYPE: &str = "application/vnd.etsi.asic-s+zip";
/// The media type of ASiC-E.
pub const ASIC_E_MIME_TYPE: &str = "application/vnd.etsi.asic-e+zip";
/// The detached CAdES of ASiC-S.
pub const ASIC_S_SIGNATURE_ENTRY: &str = "META-INF/signature.p7s";
/// The manifest of ASiC-E.
pub const MANIFEST_ENTRY: &str = "META-INF/manifest.xml";
/// The XAdES signatures of an ASiC-E container this crate makes.
pub const XADES_SIGNATURES_ENTRY: &str = "META-INF/signatures001.xml";
/// The namespace of asic:XAdESSignatures.
pub const XADES_SIGNATURES_NAMESPACE: &str = "http://uri.etsi.org/02918/v1.2.1#";
/// The namespace of the OpenDocument manifest.
pub const MANIFEST_NAMESPACE: &str = "urn:oasis:names:tc:opendocument:xmlns:manifest:1.0";
/// The entry holding the media type.
pub const MIME_TYPE_ENTRY: &str = "mimetype";
/// The folder of signatures and manifests.
pub const META_INF: &str = "META-INF/";

/// The largest total size of the entries when unpacked.
const MAX_UNPACKED_BYTES: u64 = 1 << 31;
/// The local file header signature that starts a ZIP archive.
const ZIP_MAGIC: [u8; 4] = [b'P', b'K', 3, 4];
/// The XML declaration of the manifest, as the C# implementation writes it.
const MANIFEST_DECLARATION: &str = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>";

/// The entries of a container as read.
pub(crate) struct ContainerContents {
    /// The media type, none when the mimetype entry is missing.
    pub(crate) mime_type: Option<String>,
    /// The file entries in archive order; a repeated name keeps its first place and its last content.
    pub(crate) entries: Vec<SignedFile>,
    /// True when the first entry is "mimetype", stored uncompressed.
    pub(crate) is_mime_type_first_and_stored: bool,
}

impl ContainerContents {
    pub(crate) fn find(&self, name: &str) -> Option<&[u8]> {
        self.entries
            .iter()
            .find(|entry| entry.name == name)
            .map(|entry| entry.content.as_slice())
    }
}

/// An ASiC-S container with one data file and its detached CAdES signature.
pub fn create_asic_s(data_name: &str, data: &[u8], detached_cades: &[u8]) -> Result<Vec<u8>, ContainerError> {
    write_zip(
        ASIC_S_MIME_TYPE,
        &[(data_name, data), (ASIC_S_SIGNATURE_ENTRY, detached_cades)],
    )
}

/// An ASiC-E container: the data files, the manifest and the XAdES signature wrapped into asic:XAdESSignatures
/// (exclusive canonicalization ignores the new root, so the signature stays valid).
pub fn create_asic_e(files: &[SignedFile], signature: &XadesSignature) -> Result<Vec<u8>, ContainerError> {
    let root = XmlElement::new("asic:XAdESSignatures")
        .with_attribute("xmlns:ds", xml_namespaces::DS)
        .with_attribute("xmlns:asic", XADES_SIGNATURES_NAMESPACE)
        .with_child(signature.element_inside_ds_scope());
    let mut signatures = String::from(XML_DECLARATION);
    root.write(&mut signatures);

    let manifest = manifest_of(files);
    let mut entries: Vec<(&str, &[u8])> = files
        .iter()
        .map(|file| (file.name.as_str(), file.content.as_slice()))
        .collect();
    entries.push((MANIFEST_ENTRY, manifest.as_bytes()));
    entries.push((XADES_SIGNATURES_ENTRY, signatures.as_bytes()));
    write_zip(ASIC_E_MIME_TYPE, &entries)
}

/// True when the data starts like a ZIP archive.
pub fn looks_like_zip(data: &[u8]) -> bool {
    data.len() > ZIP_MAGIC.len() && data.starts_with(&ZIP_MAGIC)
}

/// Data entries: everything except mimetype and META-INF/.
pub(crate) fn is_data_entry(name: &str) -> bool {
    name != MIME_TYPE_ENTRY && !name.starts_with(META_INF)
}

/// The entries of a container and its media type.
pub(crate) fn read_container(container: &[u8]) -> Result<ContainerContents, ContainerError> {
    let mut archive = ZipArchive::new(Cursor::new(container)).map_err(zip_error)?;
    let mut entries: Vec<SignedFile> = Vec::new();
    let mut total: u64 = 0;
    let mut is_mime_type_first_and_stored = false;
    for index in 0..archive.len() {
        let mut entry = archive.by_index(index).map_err(zip_error)?;
        let name = entry.name().map_err(zip_error)?.into_owned();
        if index == 0 {
            is_mime_type_first_and_stored = name == MIME_TYPE_ENTRY && entry.size() == entry.compressed_size();
        }
        if name.ends_with('/') {
            continue;
        }
        let mut content = Vec::new();
        let limit = MAX_UNPACKED_BYTES - total + 1;
        entry
            .by_ref()
            .take(limit)
            .read_to_end(&mut content)
            .map_err(|error| zip_error(error.into()))?;
        total += content.len() as u64;
        if total > MAX_UNPACKED_BYTES {
            return Err(ContainerError::TooLarge);
        }
        match entries.iter_mut().find(|existing| existing.name == name) {
            Some(existing) => existing.content = content,
            None => entries.push(SignedFile { name, content }),
        }
    }
    let mime_type = entries
        .iter()
        .find(|entry| entry.name == MIME_TYPE_ENTRY)
        .map(|entry| String::from_utf8_lossy(&entry.content).trim().to_owned());
    Ok(ContainerContents {
        mime_type,
        entries,
        is_mime_type_first_and_stored,
    })
}

// The manifest as the C# implementation writes it: built as text, empty elements without a space before "/>".
fn manifest_of(files: &[SignedFile]) -> String {
    let mut manifest = String::from(MANIFEST_DECLARATION);
    manifest.push_str(&format!("<manifest:manifest xmlns:manifest=\"{MANIFEST_NAMESPACE}\">"));
    manifest.push_str(&manifest_entry("/", ASIC_E_MIME_TYPE));
    for file in files {
        manifest.push_str(&manifest_entry(&file.name, mime_type_of(&file.name)));
    }
    manifest.push_str("</manifest:manifest>");
    manifest
}

fn manifest_entry(full_path: &str, media_type: &str) -> String {
    format!(
        "<manifest:file-entry manifest:full-path=\"{}\" manifest:media-type=\"{media_type}\"/>",
        escape_attribute(full_path)
    )
}

fn write_zip(mime_type: &str, entries: &[(&str, &[u8])]) -> Result<Vec<u8>, ContainerError> {
    let mut zip = ZipWriter::new(Cursor::new(Vec::new()));
    let stored = SimpleFileOptions::default().compression_method(CompressionMethod::Stored);
    zip.start_file(MIME_TYPE_ENTRY, stored).map_err(zip_error)?;
    zip.write_all(mime_type.as_bytes())
        .map_err(|error| zip_error(error.into()))?;
    let deflated = SimpleFileOptions::default().compression_method(CompressionMethod::Deflated);
    for (name, content) in entries {
        if *name == MIME_TYPE_ENTRY || name.contains("..") || name.starts_with('/') {
            return Err(ContainerError::InvalidEntryName {
                name: (*name).to_owned(),
            });
        }
        zip.start_file(*name, deflated).map_err(zip_error)?;
        zip.write_all(content).map_err(|error| zip_error(error.into()))?;
    }
    Ok(zip.finish().map_err(zip_error)?.into_inner())
}

fn zip_error(error: zip::result::ZipError) -> ContainerError {
    ContainerError::Zip {
        message: error.to_string(),
    }
}
