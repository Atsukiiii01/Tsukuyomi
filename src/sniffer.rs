use tls_parser::{parse_tls_plaintext, TlsMessage, TlsMessageHandshake, TlsExtension};

/// Attempts to parse a TLS ClientHello and extract the SNI (Server Name Indication).
/// Returns None if the packet is malformed or not a ClientHello.
pub fn extract_sni(data: &[u8]) -> Option<String> {
    // Attempt to parse the outer TLS record
    if let Ok((_, record)) = parse_tls_plaintext(data) {
        for msg in record.msg {
            // We only care about the Handshake -> ClientHello message
            if let TlsMessage::Handshake(TlsMessageHandshake::ClientHello(hello)) = msg {
                // Check if there are extensions (SNI is an extension)
                if let Some(extensions) = hello.ext {
                    // Parse the raw extension bytes
                    if let Ok((_, exts)) = tls_parser::parse_tls_extensions(extensions) {
                        for ext in exts {
                            // Match strictly on SNI extension type
                            if let TlsExtension::SNI(sni_vec) = ext {
                                // SNI can technically have multiple names, we take the first valid one
                                for (_, domain_bytes) in sni_vec {
                                    if let Ok(domain) = std::str::from_utf8(domain_bytes) {
                                        return Some(domain.to_string());
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    None
}