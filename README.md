# Tsukuyomi
**Post-Quantum Cryptography (PQC) MITM Proxy**

Tsukuyomi is a high-performance, transparent Man-in-the-Middle (MITM) proxy built in Rust. It is engineered to intercept, decrypt, and log TLS 1.3 traffic natively handling Post-Quantum Cryptography (specifically ML-KEM / Kyber-768) key encapsulations. 

Rather than relying on legacy interception tools that fail or panic against modern FIPS 203 quantum-resistant standards, Tsukuyomi dynamically bridges the connection, forging certificates on the fly to expose plaintext payloads.

## Core Architecture

The proxy operates via a highly modularized interception pipeline:

* **SNI Extraction (`sniffer.rs`):** Intercepts the inbound `CONNECT` tunnel and parses the TLS ClientHello to extract the Server Name Indication (SNI) before upstream DNS resolution.
* **Dynamic Forgery & PQC Engine (`crypto.rs`):** Acts as the localized Certificate Authority. It dynamically signs X.509 certificates for the intercepted SNI while simultaneously negotiating the ML-KEM/Kyber-768 key encapsulation for the upstream server connection.
* **The Bridge (`proxy.rs`):** Maintains the bidirectional TCP stream, handling the dual-encryption overhead (Client <-> Proxy, Proxy <-> Server) without dropping packets.
* **Traffic Analysis (`logger.rs`):** Rips the plaintext HTTP headers and body from the decrypted stream and outputs them to the console for operational analysis.

## Execution Requirements

This tool requires a localized Root CA to execute the MITM interception. 

1. **Generate the Root CA:**
```bash
mkdir certs
openssl genrsa -out certs/ca.key 2048
openssl req -x509 -new -nodes -key certs/ca.key -sha256 -days 3650 -out certs/ca.crt -subj "/CN=Tsukuyomi Root CA"

System Trust: The generated ca.crt must be explicitly trusted by the client environment (e.g., macOS Keychain, or explicitly passed via curl --cacert).

Deploy the Proxy:

Bash
cargo run
The proxy will bind to 127.0.0.1:8080 and await the tunnel request.

Operational Use Case
Built for offensive security engineers and Red Teams auditing infrastructure migrations to Post-Quantum standards. Tsukuyomi proves that a quantum-resistant tunnel is only as secure as the infrastructure's trust stores.
