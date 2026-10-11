//! The two provider profiles of docs/provider-formats.md, checked with the independent recipes: a PrivatBank `.sig`
//! (enveloped CAdES-T) and a "Дія" ASiC-E (XAdES-B-LT).

use ua_der::{Asn1Node, tag};
use ua_pki::{Certificate, asic_container, oids};
use ua_xml_c14n::DocumentText;

use super::xml::{self, ASIC, DS, MANIFEST, XADES};
use super::{read_zip, recipes};

/// The PrivatBank profile (docs/provider-formats.md, section 1): enveloped CAdES-T, DSTU 4145 with DSTU 7564-256,
/// signingTime as UTCTime, signingCertificateV2 with issuerSerial, only the signer's certificate inside.
pub fn assert_privatbank_profile(signature: &[u8], data: &[u8], signer: &Certificate) {
    let cms = recipes::read_cms(signature);
    assert_eq!(cms.content_type, oids::DATA);
    assert_eq!(cms.content.as_deref(), Some(data));
    assert_eq!(cms.certificates, [signer.encoded().to_vec()]);
    assert_eq!(cms.signers.len(), 1);
    let info = &cms.signers[0];
    assert_eq!(&info.serial_number, signer.serial_number());
    assert_eq!(info.digest_algorithm, oids::DSTU7564_256);
    assert_eq!(info.signature_algorithm, oids::DSTU4145_WITH_DSTU7564);
    assert!(recipes::verify_cms_signer(info, signer.encoded()));

    let mut signed: Vec<&str> = info.attributes.iter().map(|(oid, _)| oid.as_str()).collect();
    signed.sort();
    let mut expected = [
        oids::CONTENT_TYPE,
        oids::SIGNING_TIME,
        oids::MESSAGE_DIGEST,
        oids::SIGNING_CERTIFICATE_V2,
    ];
    expected.sort();
    assert_eq!(signed, expected);
    assert_eq!(
        Asn1Node::parse(info.signed(oids::SIGNING_TIME)).unwrap().tag(),
        tag::UTC_TIME
    );
    assert_eq!(info.message_digest(), recipes::hash(oids::DSTU7564_256, data, None));

    let attribute = Asn1Node::parse(info.signed(oids::SIGNING_CERTIFICATE_V2)).unwrap();
    let certificates = attribute.child(0).unwrap().children().unwrap();
    assert_eq!(certificates.len(), 1);
    let cert_id = &certificates[0];
    assert_eq!(
        cert_id.child(1).unwrap().to_octet_string().unwrap(),
        recipes::hash(oids::DSTU7564_256, signer.encoded(), None)
    );
    let issuer_serial = cert_id.child(2).unwrap();
    assert_eq!(
        &issuer_serial.child(1).unwrap().to_integer().unwrap(),
        signer.serial_number()
    );
    let names = issuer_serial.child(0).unwrap().children().unwrap();
    assert_eq!(names.len(), 1);
    assert_eq!(names[0].child(0).unwrap().encoded(), signer.issuer().encoded());

    let unsigned: Vec<&str> = info.unsigned.iter().map(|(oid, _)| oid.as_str()).collect();
    assert_eq!(unsigned, [oids::SIGNATURE_TIME_STAMP_TOKEN]);
    let token = info.unsigned(oids::SIGNATURE_TIME_STAMP_TOKEN);
    let (imprint_algorithm, _, policy) = recipes::read_time_stamp(token);
    assert_eq!(policy, oids::TSP_POLICY_DSTU7564);
    assert_eq!(imprint_algorithm, oids::DSTU7564_256);
    assert!(recipes::imprint_covers(token, &info.signature));
}

/// The "Дія" profile (docs/provider-formats.md, section 2): ASiC-E with one detached XAdES-B-LT, DSTU 4145 with
/// DSTU 7564-256; with a "good" OCSP response about the signer.
pub fn assert_diia_profile(container: &[u8], name: &str, data: &[u8], signer: &Certificate, issuer: &Certificate) {
    let entries = read_zip(container);
    let names: Vec<&str> = entries.iter().map(|entry| entry.name.as_str()).collect();
    assert_eq!(
        names,
        ["mimetype", name, "META-INF/manifest.xml", "META-INF/signatures001.xml"]
    );
    assert!(entries[0].is_stored);
    assert_eq!(entries[0].content, asic_container::ASIC_E_MIME_TYPE.as_bytes());
    assert_eq!(entries[1].content, data);

    let manifest_text = DocumentText::decode(&entries[2].content).unwrap();
    let manifest = manifest_text.parse().unwrap();
    let listed: Vec<&str> = xml::elements(&manifest, MANIFEST, "file-entry")
        .iter()
        .map(|e| e.attribute((MANIFEST, "full-path")).unwrap())
        .collect();
    assert_eq!(listed, ["/", name]);

    let text = DocumentText::decode(&entries[3].content).unwrap();
    let document = text.parse().unwrap();
    assert!(document.root_element().has_tag_name((ASIC, "XAdESSignatures")));
    let signatures = xml::elements(&document, DS, "Signature");
    assert_eq!(signatures.len(), 1);
    let signature = signatures[0];
    let exclusive = "http://www.w3.org/2001/10/xml-exc-c14n#";

    // SignedInfo: exclusive C14N, DSTU 4145 + DSTU 7564-256, the file and the signed properties.
    let signed_info = xml::child(&signature, DS, "SignedInfo");
    assert_eq!(
        xml::child(&signed_info, DS, "CanonicalizationMethod").attribute("Algorithm"),
        Some(exclusive)
    );
    let signature_method = xml::child(&signed_info, DS, "SignatureMethod").attribute("Algorithm");
    assert_eq!(
        signature_method,
        Some("http://www.w3.org/2001/04/xmldsig-more#dstu4145-dstu7564-256")
    );
    let references: Vec<_> = signed_info
        .children()
        .filter(|n| n.has_tag_name((DS, "Reference")))
        .collect();
    assert_eq!(references.len(), 2);
    assert_eq!(references[0].attribute("URI"), Some(name));
    assert_eq!(
        xml::base64(&xml::child(&references[0], DS, "DigestValue")),
        recipes::hash(oids::DSTU7564_256, data, None)
    );
    assert_eq!(
        references[1].attribute("Type"),
        Some("http://uri.etsi.org/01903#SignedProperties")
    );
    let transform = xml::child(&xml::child(&references[1], DS, "Transforms"), DS, "Transform");
    assert_eq!(transform.attribute("Algorithm"), Some(exclusive));

    let certificate = xml::base64(&xml::child(
        &xml::child(&xml::child(&signature, DS, "KeyInfo"), DS, "X509Data"),
        DS,
        "X509Certificate",
    ));
    assert_eq!(certificate, signer.encoded());
    let qualifying = xml::child(&xml::child(&signature, DS, "Object"), XADES, "QualifyingProperties");
    assert_eq!(
        qualifying.attribute("Target").map(str::to_owned),
        Some(format!("#{}", signature.attribute("Id").unwrap()))
    );

    // SignedProperties: the one the second reference covers; signing time, certificate, data format.
    let properties = xml::child(&qualifying, XADES, "SignedProperties");
    assert_eq!(
        references[1].attribute("URI").map(str::to_owned),
        Some(format!("#{}", properties.attribute("Id").unwrap()))
    );
    assert_eq!(
        xml::base64(&xml::child(&references[1], DS, "DigestValue")),
        recipes::hash(oids::DSTU7564_256, &xml::exclusive(properties), None)
    );
    let signature_properties = xml::child(&properties, XADES, "SignedSignatureProperties");
    let signing_time = xml::text(&xml::child(&signature_properties, XADES, "SigningTime"));
    assert!(time::OffsetDateTime::parse(&signing_time, &time::format_description::well_known::Rfc3339).is_ok());
    let cert_digest = xml::child(
        &xml::child(
            &xml::child(&signature_properties, XADES, "SigningCertificateV2"),
            XADES,
            "Cert",
        ),
        XADES,
        "CertDigest",
    );
    assert_eq!(
        xml::base64(&xml::child(&cert_digest, DS, "DigestValue")),
        recipes::hash(oids::DSTU7564_256, signer.encoded(), None)
    );
    let format = xml::child(
        &xml::child(&properties, XADES, "SignedDataObjectProperties"),
        XADES,
        "DataObjectFormat",
    );
    assert_eq!(
        format.attribute("ObjectReference").map(str::to_owned),
        Some(format!("#{}", references[0].attribute("Id").unwrap()))
    );
    assert!(!xml::text(&xml::child(&format, XADES, "MimeType")).is_empty());

    // The DSTU 4145 signature over the canonical SignedInfo.
    let key = recipes::read_public_key(signer.encoded());
    let value = xml::base64(&xml::child(&signature, DS, "SignatureValue"));
    assert!(recipes::verify_dstu4145(
        &key,
        &recipes::hash(oids::DSTU7564_256, &xml::exclusive(signed_info), None),
        &value
    ));

    // Level LT: the time-stamp over the canonical SignatureValue, the CA certificate, a good OCSP response.
    let unsigned = xml::child(
        &xml::child(&qualifying, XADES, "UnsignedProperties"),
        XADES,
        "UnsignedSignatureProperties",
    );
    let stamp = xml::child(&unsigned, XADES, "SignatureTimeStamp");
    assert_eq!(
        xml::child(&stamp, DS, "CanonicalizationMethod").attribute("Algorithm"),
        Some(exclusive)
    );
    let token = xml::base64(&xml::child(&stamp, XADES, "EncapsulatedTimeStamp"));
    assert_eq!(recipes::read_time_stamp(&token).2, oids::TSP_POLICY_DSTU7564);
    assert!(recipes::imprint_covers(
        &token,
        &xml::exclusive(xml::child(&signature, DS, "SignatureValue"))
    ));
    let values = xml::child(&unsigned, XADES, "CertificateValues");
    assert!(
        values
            .children()
            .filter(|n| n.is_element())
            .any(|value| xml::base64(&value) == issuer.encoded())
    );
    let ocsp = xml::elements(&document, XADES, "EncapsulatedOCSPValue");
    assert!(!ocsp.is_empty());
    let about_signer: Vec<u8> = ocsp
        .iter()
        .flat_map(|value| recipes::ocsp_statuses(&recipes::read_ocsp_response(&xml::base64(value))))
        .filter(|(serial, _)| serial == signer.serial_number())
        .map(|(_, status)| status)
        .collect();
    assert_eq!(about_signer, [0]);
}
