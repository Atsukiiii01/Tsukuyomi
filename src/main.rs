mod sniffer;
mod proxy;
mod crypto;
mod logger;

use tokio::net::TcpListener;
use tokio::io::{AsyncReadExt, AsyncWriteExt}; // Added AsyncWriteExt so we can reply
use std::error::Error;

const LISTENER_ADDR: &str = "127.0.0.1:8080";

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // --- THE QUANTUM INJECTION ---
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    let listener = TcpListener::bind(LISTENER_ADDR).await?;
    
    println!("--- TSUKUYOMI V1.1 (FORWARD PROXY UPGRADE) ONLINE ---");
    println!("🛡️  PQC Engine: ML-KEM / Kyber-768 Armed");
    println!("Listening on: {}", LISTENER_ADDR);
    println!("Waiting for browser traffic...");

    loop {
        let (mut socket, _addr) = listener.accept().await?;

        tokio::spawn(async move {
            let mut buffer = [0u8; 4096]; 

            match socket.read(&mut buffer).await {
                Ok(n) if n > 0 => {
                    // Convert the raw bytes into a string to see if the browser is talking to us
                    let request_str = String::from_utf8_lossy(&buffer[..n]);
                    
                    // --- THE FORWARD PROXY HANDSHAKE ---
                    if request_str.starts_with("CONNECT ") {
                        // The browser is asking for a tunnel. E.g., "CONNECT google.com:443 HTTP/1.1"
                        let parts: Vec<&str> = request_str.split_whitespace().collect();
                        if parts.len() >= 2 {
                            let host_port = parts[1];
                            let target_host = host_port.split(':').next().unwrap_or(host_port);
                            
                            println!(" [TUNNEL REQUESTED] >> {}", target_host);
                            
                            // Tell the browser: "Tunnel open. Send the encrypted data."
                            let response = "HTTP/1.1 200 Connection Established\r\n\r\n";
                            if let Err(e) = socket.write_all(response.as_bytes()).await {
                                eprintln!(" [ERROR] Failed to send 200 OK: {}", e);
                                return;
                            }
                            
                            // Now we wait for the browser to send the actual TLS Handshake
                            let mut tls_buffer = [0u8; 4096];
                            match socket.read(&mut tls_buffer).await {
                                Ok(tls_n) if tls_n > 0 => {
                                    // Hand it off to the decryption engine
                                    if let Err(e) = proxy::bridge(socket, &tls_buffer[..tls_n], target_host).await {
                                        eprintln!(" [ERROR] Bridge failed: {}", e);
                                    }
                                },
                                _ => {}
                            }
                        }
                    } else {
                        // Fallback: If it's a direct transparent connection (like your curl test)
                        if let Some(target) = sniffer::extract_sni(&buffer[..n]) {
                            println!(" [TARGET ACQUIRED] >> {}", target);
                            if let Err(e) = proxy::bridge(socket, &buffer[..n], &target).await {
                                eprintln!(" [ERROR] Bridge failed: {}", e);
                            }
                        }
                    }
                },
                Ok(_) => { /* Client disconnected immediately */ }
                Err(e) => eprintln!(" [ERROR] Socket read failed: {}", e),
            }
        });
    }
}