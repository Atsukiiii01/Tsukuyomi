use tokio::net::TcpStream;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use std::error::Error;
use std::sync::Arc;
use std::pin::Pin;
use std::task::{Context, Poll}; 

use tokio_rustls::{TlsAcceptor, TlsConnector, rustls};
use rustls::ServerName; 
use crate::crypto;

pub async fn bridge(client_socket: TcpStream, initial_data: &[u8], target_host: &str) -> Result<(), Box<dyn Error>> {
    println!(" [PROXY] 🔓 Decrypting traffic for: {}", target_host);

    // --- PART 1: PREPARE THE HIJACK ---
    let (ca_cert, ca_key) = crypto::load_ca();
    let (certs, key) = crypto::forge_cert(target_host, &ca_cert, &ca_key);

    let server_config = rustls::ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth()
        .with_single_cert(certs, key)?;
    let acceptor = TlsAcceptor::from(Arc::new(server_config));

    // --- PART 2: CONNECT TO REAL SERVER ---
    let target_addr = format!("{}:443", target_host);
    let upstream_socket = TcpStream::connect(&target_addr).await?;
    
    // FIX IS HERE: Correct way to load WebPKI roots in newer versions
    let mut root_store = rustls::RootCertStore::empty();
    root_store.add_trust_anchors( // Changed from add_server_trust_anchors
        webpki_roots::TLS_SERVER_ROOTS.iter().map(|ta| { // Removed the .0
            rustls::OwnedTrustAnchor::from_subject_spki_name_constraints(
                ta.subject, ta.spki, ta.name_constraints,
            )
        })
    );
    
    let client_config = rustls::ClientConfig::builder()
        .with_safe_defaults()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    let connector = TlsConnector::from(Arc::new(client_config));
    
    let domain = ServerName::try_from(target_host)?;
    let mut upstream_tls = connector.connect(domain, upstream_socket).await?;

    // --- PART 3: REWIND THE STREAM ---
    let (read_half, write_half) = client_socket.into_split();
    let cursor = std::io::Cursor::new(initial_data.to_vec());
    let combined_reader = cursor.chain(read_half);
    
    let rewind_stream = RewindStream {
        reader: combined_reader,
        writer: write_half,
    };

    // --- PART 4: ACCEPT & TUNNEL ---
    let mut client_tls = acceptor.accept(rewind_stream).await?;

    let (mut c_read, mut c_write) = tokio::io::split(client_tls);
    let (mut s_read, mut s_write) = tokio::io::split(upstream_tls);

    let c_to_s = tokio::io::copy(&mut c_read, &mut s_write);
    let s_to_c = tokio::io::copy(&mut s_read, &mut c_write);

    match tokio::try_join!(c_to_s, s_to_c) {
        Ok(_) => println!(" [PROXY] Connection finished: {}", target_host),
        Err(e) => eprintln!(" [PROXY] Connection broken: {}", e),
    }

    Ok(())
}

struct RewindStream {
    reader: tokio::io::Chain<std::io::Cursor<Vec<u8>>, tokio::net::tcp::OwnedReadHalf>,
    writer: tokio::net::tcp::OwnedWriteHalf,
}

impl AsyncRead for RewindStream {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.reader).poll_read(cx, buf)
    }
}

impl AsyncWrite for RewindStream {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.writer).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.writer).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.writer).poll_shutdown(cx)
    }
}