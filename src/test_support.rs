use anyhow::Result;
use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair};

pub struct TlsMaterial {
    pub ca: Vec<u8>,
    pub certs: Vec<Vec<u8>>,
    pub keys: Vec<Vec<u8>>,
}

pub fn generate_tls(n: u32) -> Result<TlsMaterial> {
    let ca_key = KeyPair::generate()?;
    let mut ca_params = CertificateParams::new(vec![])?;
    ca_params.distinguished_name = DistinguishedName::new();
    ca_params
        .distinguished_name
        .push(DnType::CommonName, "CRBB Test CA");
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let ca_cert = ca_params.self_signed(&ca_key)?;

    let ca_kp = KeyPair::from_pem(&ca_key.serialize_pem())?;
    let ca_for_signing = CertificateParams::from_ca_cert_pem(&ca_cert.pem())?
        .self_signed(&ca_kp)?;

    let mut certs = Vec::new();
    let mut keys = Vec::new();
    for i in 0..n {
        let kp = KeyPair::generate()?;
        let mut params = CertificateParams::new(vec![
            "localhost".to_string(),
            "127.0.0.1".to_string(),
        ])?;
        params.distinguished_name = DistinguishedName::new();
        params
            .distinguished_name
            .push(DnType::CommonName, format!("node-{}", i));
        let cert = params.signed_by(&kp, &ca_for_signing, &ca_kp)?;
        certs.push(cert.pem().into_bytes());
        keys.push(kp.serialize_pem().into_bytes());
    }
    Ok(TlsMaterial {
        ca: ca_cert.pem().into_bytes(),
        certs,
        keys,
    })
}