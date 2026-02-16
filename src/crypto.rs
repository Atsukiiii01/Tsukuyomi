use rcgen::{BasicConstraints, Certificate, CertificateParams, DnType, IsCa, KeyPair};
use rustls::{Certificate as RustlsCert, PrivateKey};
use std::fs;

pub fn load_ca() -> (String, String) {
    // We still load both files, even though we only strictly need the key for signing.
    let ca_cert = fs::read_to_string("certs/ca.crt").expect("Failed to read certs/ca.crt");
    let ca_key = fs::read_to_string("certs/ca.key").expect("Failed to read certs/ca.key");
    (ca_cert, ca_key)
}

pub fn forge_cert(domain: &str, _ca_cert_pem: &str, ca_key_pem: &str) -> (Vec<RustlsCert>, PrivateKey) {
    // 1. Load the REAL CA Private Key
    let key_pair = KeyPair::from_pem(ca_key_pem).expect("Failed to parse CA key");

    // 2. Reconstruct the CA "Signer" object in memory.
    // We don't parse the ca.crt file (which causes the error). 
    // We just create a signer that uses the correct Private Key.
    let mut ca_params = CertificateParams::new(vec!["Tsukuyomi CA".to_string()]);
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.key_pair = Some(key_pair); // <--- The magic: Inject the real key

    let ca_cert_struct = Certificate::from_params(ca_params).unwrap();

    // 3. Create the Target Certificate (e.g., google.com)
    let mut params = CertificateParams::new(vec![domain.to_string()]);
    params.distinguished_name.push(DnType::CommonName, domain);
    params.is_ca = IsCa::NoCa;

    // 4. Sign the Target with our CA
    let cert = Certificate::from_params(params).unwrap();
    let cert_pem = cert.serialize_pem_with_signer(&ca_cert_struct).unwrap();
    let key_pem = cert.serialize_private_key_pem();

    // 5. Convert to Rustls format
    let certs = rustls_pemfile::certs(&mut cert_pem.as_bytes()).unwrap()
        .into_iter().map(RustlsCert).collect();
    let keys = rustls_pemfile::pkcs8_private_keys(&mut key_pem.as_bytes()).unwrap();
    
    (certs, PrivateKey(keys[0].clone()))
}