//! The algorithms of the Ukrainian PKI by their identifiers: hashes by OID and XML URI, and the signature algorithm
//! that goes with each hash (docs/signature-formats.md, section 2).

use sha1::Sha1;
use sha2::{Digest, Sha256};
use ua_cryptography_dstu7564::{HashSize, Kupyna};
use ua_cryptography_gost::{DEFAULT_DKE, Gost34311};

use crate::errors::AlgorithmError;
use crate::oids;

/// XML DigestMethod of DSTU 7564-256.
pub const XML_DSTU7564_256: &str = "http://www.w3.org/2001/04/xmlenc#dstu7564-256";
/// XML DigestMethod of GOST 34.311.
pub const XML_GOST34311: &str = "http://www.w3.org/2001/04/xmlenc#gost34311";
/// XML SignatureMethod of DSTU 4145 with DSTU 7564-256.
pub const XML_SIGNATURE_DSTU7564: &str = "http://www.w3.org/2001/04/xmldsig-more#dstu4145-dstu7564-256";
/// XML SignatureMethod of DSTU 4145 with GOST 34.311.
pub const XML_SIGNATURE_GOST34311: &str = "http://www.w3.org/2001/04/xmldsig-more#dstu4145-gost34311";
/// XML DigestMethod of SHA-1.
pub const XML_SHA1: &str = "http://www.w3.org/2000/09/xmldsig#sha1";
/// XML DigestMethod of SHA-256.
pub const XML_SHA256: &str = "http://www.w3.org/2001/04/xmlenc#sha256";

/// The hash of `data` by its OID, as the hash function outputs it (no byte reversal). GOST 34.311 uses the S-box
/// table `dke`, or DKE No. 1 when it is absent.
pub fn hash(oid: &str, data: &[u8], dke: Option<&[u8]>) -> Result<Vec<u8>, AlgorithmError> {
    match oid {
        oids::GOST34311 => hash_gost34311(data, dke),
        oids::DSTU7564_256 => Ok(Kupyna::calculate_hash(data, HashSize::Bits256)),
        oids::DSTU7564_384 => Ok(Kupyna::calculate_hash(data, HashSize::Bits384)),
        oids::DSTU7564_512 => Ok(Kupyna::calculate_hash(data, HashSize::Bits512)),
        oids::SHA1 => Ok(Sha1::digest(data).to_vec()),
        oids::SHA256 => Ok(Sha256::digest(data).to_vec()),
        _ => Err(AlgorithmError::UnsupportedHash { oid: oid.to_owned() }),
    }
}

/// The hashes a verifier accepts for document data and signed attributes: GOST 34.311 with the signer's DKE and, when
/// that DKE is not DKE No. 1, also with DKE No. 1 (which table a tool hashes with is not fixed by the formats; current
/// certificates carry no DKE at all). Other hashes have one value.
pub fn candidate_hashes(oid: &str, data: &[u8], dke: Option<&[u8]>) -> Result<Vec<Vec<u8>>, AlgorithmError> {
    let mut hashes = vec![hash(oid, data, dke)?];
    if oid == oids::GOST34311 && dke.is_some_and(|table| table != DEFAULT_DKE.as_slice()) {
        hashes.push(hash(oid, data, None)?);
    }
    Ok(hashes)
}

/// True when one of the [`candidate_hashes`] of `data` equals `expected`; a hash that cannot be computed (an
/// unsupported OID, a malformed DKE) matches nothing.
pub fn digest_matches(oid: &str, data: &[u8], expected: &[u8], dke: Option<&[u8]>) -> bool {
    match candidate_hashes(oid, data, dke) {
        Ok(hashes) => hashes.iter().any(|candidate| candidate.as_slice() == expected),
        Err(_) => false,
    }
}

/// True for the hashes [`hash`] computes.
pub fn is_supported_hash(oid: &str) -> bool {
    matches!(
        oid,
        oids::GOST34311 | oids::DSTU7564_256 | oids::DSTU7564_384 | oids::DSTU7564_512 | oids::SHA1 | oids::SHA256
    )
}

/// The hash a signature algorithm ("DSTU 4145 with …") stands for.
pub fn hash_of_signature_algorithm(signature_algorithm: &str) -> Result<&'static str, AlgorithmError> {
    match signature_algorithm {
        oids::DSTU4145_WITH_DSTU7564 => Ok(oids::DSTU7564_256),
        oids::DSTU4145_WITH_GOST34311 => Ok(oids::GOST34311),
        _ => Err(AlgorithmError::UnsupportedSignatureAlgorithm {
            oid: signature_algorithm.to_owned(),
        }),
    }
}

/// The signature algorithm used with a hash in the national PKI.
pub fn signature_algorithm_for(hash_oid: &str) -> Result<&'static str, AlgorithmError> {
    match hash_oid {
        oids::DSTU7564_256 => Ok(oids::DSTU4145_WITH_DSTU7564),
        oids::GOST34311 => Ok(oids::DSTU4145_WITH_GOST34311),
        _ => Err(AlgorithmError::NoSignatureAlgorithm {
            hash_oid: hash_oid.to_owned(),
        }),
    }
}

/// The XML-DSig DigestMethod URI of a hash.
pub fn xml_digest_method(hash_oid: &str) -> Result<&'static str, AlgorithmError> {
    match hash_oid {
        oids::DSTU7564_256 => Ok(XML_DSTU7564_256),
        oids::GOST34311 => Ok(XML_GOST34311),
        _ => Err(AlgorithmError::NoXmlDigestMethod {
            hash_oid: hash_oid.to_owned(),
        }),
    }
}

/// The XML-DSig SignatureMethod URI of DSTU 4145 with a hash.
pub fn xml_signature_method(hash_oid: &str) -> Result<&'static str, AlgorithmError> {
    match hash_oid {
        oids::DSTU7564_256 => Ok(XML_SIGNATURE_DSTU7564),
        oids::GOST34311 => Ok(XML_SIGNATURE_GOST34311),
        _ => Err(AlgorithmError::NoXmlSignatureMethod {
            hash_oid: hash_oid.to_owned(),
        }),
    }
}

/// The hash OID behind an XML DigestMethod or SignatureMethod URI.
pub fn hash_of_xml_algorithm(uri: &str) -> Result<&'static str, AlgorithmError> {
    match uri {
        XML_DSTU7564_256 | XML_SIGNATURE_DSTU7564 => Ok(oids::DSTU7564_256),
        XML_GOST34311 | XML_SIGNATURE_GOST34311 => Ok(oids::GOST34311),
        XML_SHA1 => Ok(oids::SHA1),
        XML_SHA256 => Ok(oids::SHA256),
        _ => Err(AlgorithmError::UnsupportedXmlAlgorithm { uri: uri.to_owned() }),
    }
}

/// A hash name as given on a command line or in configuration: "dstu7564" (256 bits), "gost34311", or an OID.
pub fn parse_hash_name(name: &str) -> Result<String, AlgorithmError> {
    match name.to_lowercase().as_str() {
        "dstu7564" | "dstu7564-256" | "kupyna" => Ok(oids::DSTU7564_256.to_owned()),
        "gost34311" | "gost" => Ok(oids::GOST34311.to_owned()),
        _ if is_supported_hash(name) => Ok(name.to_owned()),
        _ => Err(AlgorithmError::UnknownHashName { name: name.to_owned() }),
    }
}

/// The readable name of a hash; an unknown OID is returned as given.
pub fn hash_name(oid: &str) -> &str {
    match oid {
        oids::GOST34311 => "GOST 34.311-95",
        oids::DSTU7564_256 => "DSTU 7564-256",
        oids::DSTU7564_384 => "DSTU 7564-384",
        oids::DSTU7564_512 => "DSTU 7564-512",
        oids::SHA1 => "SHA-1",
        oids::SHA256 => "SHA-256",
        _ => oid,
    }
}

/// The name of a signature algorithm given by its OID or XML-DSig URI; an unknown one is returned as given.
pub fn signature_algorithm_name(identifier: &str) -> &str {
    match identifier {
        oids::DSTU4145_WITH_DSTU7564 | XML_SIGNATURE_DSTU7564 => "DSTU 4145 with DSTU 7564-256",
        oids::DSTU4145_WITH_GOST34311 | XML_SIGNATURE_GOST34311 => "DSTU 4145 with GOST 34.311-95",
        _ => identifier,
    }
}

fn hash_gost34311(data: &[u8], dke: Option<&[u8]>) -> Result<Vec<u8>, AlgorithmError> {
    match dke {
        None => Ok(Gost34311::calculate_hash(data).to_vec()),
        Some(table) => {
            let mut gost = Gost34311::from_dke(table).map_err(AlgorithmError::InvalidDke)?;
            Ok(gost.hash(data).to_vec())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gost_with_another_dke_also_accepts_dke_number_one() {
        let mut other_dke = DEFAULT_DKE;
        other_dke.swap(0, 1);
        let hashes = candidate_hashes(oids::GOST34311, b"data", Some(&other_dke)).unwrap();
        assert_eq!(hashes.len(), 2);
        assert_eq!(hashes[1], hash(oids::GOST34311, b"data", None).unwrap());
        assert_eq!(
            candidate_hashes(oids::GOST34311, b"data", Some(&DEFAULT_DKE))
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            candidate_hashes(oids::DSTU7564_256, b"data", Some(&other_dke))
                .unwrap()
                .len(),
            1
        );
    }

    #[test]
    fn names_and_uris_map_to_the_same_hashes() {
        assert_eq!(parse_hash_name("Kupyna").unwrap(), oids::DSTU7564_256);
        assert_eq!(parse_hash_name("GOST").unwrap(), oids::GOST34311);
        assert_eq!(parse_hash_name(oids::SHA256).unwrap(), oids::SHA256);
        assert!(parse_hash_name("md5").is_err());
        for hash_oid in [oids::DSTU7564_256, oids::GOST34311] {
            assert_eq!(
                hash_of_xml_algorithm(xml_digest_method(hash_oid).unwrap()).unwrap(),
                hash_oid
            );
            assert_eq!(
                hash_of_xml_algorithm(xml_signature_method(hash_oid).unwrap()).unwrap(),
                hash_oid
            );
            let signature_algorithm = signature_algorithm_for(hash_oid).unwrap();
            assert_eq!(hash_of_signature_algorithm(signature_algorithm).unwrap(), hash_oid);
        }
        assert_eq!(hash_name("1.2.3"), "1.2.3");
        assert!(hash(oids::DSTU7564_256, b"", None).is_ok_and(|h| h.len() == 32));
        assert!(!digest_matches("1.2.3", b"", &[], None));
    }
}
