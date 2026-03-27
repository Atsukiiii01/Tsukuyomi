use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, KeyPair};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use std::fs;

pub fn load_ca() -> (String, String) {
    let ca_cert = fs::read_to_string("certs/ca.crt").expect("Failed to read certs/ca.crt");
    let ca_key = fs::read_to_string("certs/ca.key").expect("Failed to read certs/ca.key");
    (ca_cert, ca_key)
}

pub fn forge_cert(domain: &str, _ca_cert_pem: &str, ca_key_pem: &str) -> (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>) {
    // 1. Load the RSA CA Key. 
    // rcgen 0.13 automatically infers the RSA algorithm directly from the key.
    let ca_key_pair = KeyPair::from_pem(ca_key_pem).expect("Failed to parse CA key");

    // 2. Reconstruct the CA Signer
    let mut ca_params = CertificateParams::new(vec!["Tsukuyomi CA".to_string()]).unwrap();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let ca_cert_struct = ca_params.self_signed(&ca_key_pair).unwrap();

    // 3. Create the Target Certificate Params
    let mut params = CertificateParams::new(vec![domain.to_string()]).unwrap();
    params.distinguished_name.push(DnType::CommonName, domain);
    params.is_ca = IsCa::NoCa;

    // 4. Generate a fresh key pair for the target site (Defaults to fast ECDSA)
    let cert_key_pair = KeyPair::generate().unwrap();

    // 5. Sign the Target Certificate with our CA
    let cert = params.signed_by(&cert_key_pair, &ca_cert_struct, &ca_key_pair).unwrap();
    
    // 6. Serialize to PEM format
    let cert_pem = cert.pem();
    let key_pem = cert_key_pair.serialize_pem();

    // 7. Convert to Rustls 0.23 pki_types
    let certs = rustls_pemfile::certs(&mut cert_pem.as_bytes())
        .collect::<Result<Vec<_>, _>>().unwrap()
        .into_iter().map(CertificateDer::from).collect();
        
    let key = rustls_pemfile::private_key(&mut key_pem.as_bytes())
        .unwrap().unwrap();
    
    (certs, key)
}