//! Dirigera: Manger your IKEA devices.
//! Dirigera is a client to communicate with your IKEA Dirigera hub and control your Trådfri
//! devices. It is built with [`hyper`] and is bundled with an optional tool to generate the token
//! you need for the communication.
pub mod device;
pub mod hub;
pub mod scene;

pub use device::{Device, DeviceData, DeviceType};
pub use scene::Scene;

use serde::Deserialize;

pub(crate) fn deserialize_datetime<'de, D>(
    deserializer: D,
) -> Result<chrono::DateTime<chrono::Utc>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let date_str = String::deserialize(deserializer)?;
    match date_str.parse() {
        Ok(system_time) => Ok(system_time),
        Err(_) => Err(serde::de::Error::custom("Invalid date format")),
    }
}

pub(crate) fn deserialize_datetime_optional<'de, D>(
    deserializer: D,
) -> Result<Option<chrono::DateTime<chrono::Utc>>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    match deserialize_datetime(deserializer) {
        Ok(system_time) => Ok(Some(system_time)),
        Err(_) => Ok(None),
    }
}

/// A module that is used to disable TLS verification. This is used because the Dirigera HUB uses
/// HTTPS but with a self signed certificate.
pub mod danger {
    #[derive(Debug)]
    pub struct NoCertificateVerification;

    impl rustls::client::danger::ServerCertVerifier for NoCertificateVerification {
        fn verify_server_cert(
            &self,
            _end_entity: &rustls::pki_types::CertificateDer,
            _intermediates: &[rustls::pki_types::CertificateDer],
            _server_name: &rustls::pki_types::ServerName,
            _ocsp_response: &[u8],
            _now: rustls::pki_types::UnixTime,
        ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
            Ok(rustls::client::danger::ServerCertVerified::assertion())
        }

        fn verify_tls12_signature(
            &self,
            message: &[u8],
            cert: &rustls::pki_types::CertificateDer<'_>,
            dss: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            let supported_algos = rustls::crypto::CryptoProvider::get_default()
                .ok_or(rustls::Error::General("no crypto provider".into()))?
                .signature_verification_algorithms;
            rustls::crypto::verify_tls12_signature(message, cert, dss, &supported_algos)
        }

        fn verify_tls13_signature(
            &self,
            message: &[u8],
            cert: &rustls::pki_types::CertificateDer<'_>,
            dss: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            let supported_algos = rustls::crypto::CryptoProvider::get_default()
                .ok_or(rustls::Error::General("no crypto provider".into()))?
                .signature_verification_algorithms;
            rustls::crypto::verify_tls13_signature(message, cert, dss, &supported_algos)
        }

        fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
            rustls::crypto::CryptoProvider::get_default()
                .map(|p| p.signature_verification_algorithms.supported_schemes())
                .unwrap_or_default()
        }
    }

    pub fn tls_no_verify() -> rustls::ClientConfig {
        let mut tls = rustls::ClientConfig::builder()
            .with_root_certificates(rustls::RootCertStore::empty())
            .with_no_client_auth();

        tls.dangerous()
            .set_certificate_verifier(std::sync::Arc::new(NoCertificateVerification));

        tls
    }
}
