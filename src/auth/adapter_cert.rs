use crate::error::{AppError, AppResult, ErrorCode};
use std::time::Duration;

/// Verifies an adapter's X.509 client certificate against the configured root CA,
/// enforces Subject CommonName == `adapter_id`, and validates a proof-of-possession
/// signature over `locker-adapter-register:v1:{adapter_id}:{token_hash}:{ts}`.
pub fn verify_adapter_registration_cert(
    ca_cert_path: &std::path::Path,
    adapter_id: &str,
    token_hash: &str,
    cert_pem: &str,
    ts: i64,
    signature_b64: &str,
    now: i64,
) -> AppResult<()> {
    use base64::Engine as _;
    use rustls_pki_types::{CertificateDer, TrustAnchor, UnixTime};
    use webpki::{
        anchor_from_trusted_cert, ring as webpki_ring, EndEntityCert, KeyUsage,
        ALL_VERIFICATION_ALGS,
    };

    if now.abs_diff(ts) > 300 {
        return Err(AppError::new(
            ErrorCode::ReplayRejected,
            "adapter registration timestamp outside replay window",
        ));
    }
    if cert_pem.trim().is_empty() || cert_pem.len() > 64 * 1024 {
        return Err(AppError::invalid("certPem is required and must be <= 64 KiB"));
    }
    if signature_b64.trim().is_empty() || signature_b64.len() > 4096 {
        return Err(AppError::invalid("signature is required"));
    }

    let ca_bytes = std::fs::read(ca_cert_path).map_err(|err| {
        tracing::error!(path = %ca_cert_path.display(), error = %err, "failed to read MQTT CA cert");
        AppError::internal("failed to load adapter CA certificate")
    })?;
    let mut ca_reader = std::io::BufReader::new(ca_bytes.as_slice());
    let ca_ders: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut ca_reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|err| {
            tracing::error!(error = %err, "failed to parse MQTT CA PEM");
            AppError::internal("invalid adapter CA certificate")
        })?;
    if ca_ders.is_empty() {
        return Err(AppError::internal("no CA certificates found in MQTT_CA_CERT"));
    }
    let anchors: Vec<TrustAnchor<'_>> = ca_ders
        .iter()
        .map(anchor_from_trusted_cert)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|err| {
            tracing::error!(error = ?err, "failed to build trust anchor from MQTT CA");
            AppError::internal("invalid adapter CA certificate")
        })?;

    let mut cert_reader = std::io::BufReader::new(cert_pem.as_bytes());
    let chain: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut cert_reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| AppError::unauthorized("invalid adapter certPem"))?;
    let Some((leaf_der, intermediates)) = chain.split_first() else {
        return Err(AppError::unauthorized("adapter certPem contains no certificate"));
    };

    let end_entity = EndEntityCert::try_from(leaf_der)
        .map_err(|_| AppError::unauthorized("malformed adapter X.509 certificate"))?;
    let verify_time = UnixTime::since_unix_epoch(Duration::from_secs(now.max(0) as u64));
    end_entity
        .verify_for_usage(
            ALL_VERIFICATION_ALGS,
            &anchors,
            intermediates,
            verify_time,
            KeyUsage::client_auth(),
            None,
            None,
        )
        .map_err(|_| AppError::unauthorized("adapter certificate failed CA or clientAuth verification"))?;

    let cns = extract_cert_common_names(leaf_der.as_ref())
        .map_err(|_| AppError::unauthorized("failed to parse adapter certificate subject CN"))?;
    if cns.len() != 1 || cns[0] != adapter_id {
        return Err(AppError::unauthorized(
            "adapter certificate CN does not match adapterId",
        ));
    }

    let sig_bytes = base64::engine::general_purpose::STANDARD
        .decode(signature_b64.trim())
        .map_err(|_| AppError::invalid("signature must be valid base64"))?;
    let signed_msg = format!("locker-adapter-register:v1:{adapter_id}:{token_hash}:{ts}");

    let sig_algs = [
        webpki_ring::RSA_PKCS1_2048_8192_SHA256,
        webpki_ring::RSA_PSS_2048_8192_SHA256_LEGACY_KEY,
        webpki_ring::ECDSA_P256_SHA256,
        webpki_ring::ECDSA_P384_SHA384,
        webpki_ring::ED25519,
    ];
    let sig_ok = sig_algs.iter().any(|alg| {
        end_entity
            .verify_signature(*alg, signed_msg.as_bytes(), &sig_bytes)
            .is_ok()
    });
    if !sig_ok {
        return Err(AppError::unauthorized(
            "adapter certificate proof-of-possession signature invalid",
        ));
    }

    Ok(())
}

fn extract_cert_common_names(cert_der: &[u8]) -> Result<Vec<String>, der::Error> {
    use const_oid::ObjectIdentifier;
    use der::asn1::{AnyRef, Ia5StringRef, PrintableStringRef, Utf8StringRef};
    use der::{Decode, Header, Reader, SliceReader, Tag, TagNumber};

    const CN_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.4.3");

    let mut reader = SliceReader::new(cert_der)?;
    let cns = reader.sequence(|cert_r| {
        let cns = cert_r.sequence(|tbs_r| {
            if tbs_r.peek_tag().is_ok_and(|t| {
                matches!(
                    t,
                    Tag::ContextSpecific {
                        number: TagNumber::N0,
                        constructed: true
                    }
                )
            }) {
                AnyRef::decode(tbs_r)?;
            }
            AnyRef::decode(tbs_r)?; // serialNumber
            AnyRef::decode(tbs_r)?; // signature
            AnyRef::decode(tbs_r)?; // issuer
            AnyRef::decode(tbs_r)?; // validity

            let cns = tbs_r.sequence(|name_r| {
                let mut found = Vec::new();
                while !name_r.is_finished() {
                    let rdn_hdr = Header::decode(name_r)?;
                    rdn_hdr.tag.assert_eq(Tag::Set)?;
                    name_r.read_nested(rdn_hdr.length, |rdn_r| {
                        while !rdn_r.is_finished() {
                            rdn_r.sequence(|atv_r| {
                                let oid = ObjectIdentifier::decode(atv_r)?;
                                let val = AnyRef::decode(atv_r)?;
                                if oid == CN_OID {
                                    let s = if let Ok(u) = val.decode_as::<Utf8StringRef>() {
                                        u.as_str().to_string()
                                    } else if let Ok(p) = val.decode_as::<PrintableStringRef>() {
                                        p.as_str().to_string()
                                    } else if let Ok(i) = val.decode_as::<Ia5StringRef>() {
                                        i.as_str().to_string()
                                    } else {
                                        return Err(Tag::Utf8String.unexpected_error(None));
                                    };
                                    found.push(s);
                                }
                                Ok(())
                            })?;
                        }
                        Ok(())
                    })?;
                }
                Ok(found)
            })?;

            while !tbs_r.is_finished() {
                AnyRef::decode(tbs_r)?;
            }
            Ok(cns)
        })?;
        while !cert_r.is_finished() {
            AnyRef::decode(cert_r)?;
        }
        Ok(cns)
    })?;
    reader.finish(cns)
}
