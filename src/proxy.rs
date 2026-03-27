use tokio::net::TcpStream;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use std::error::Error;
use std::sync::Arc;
use std::pin::Pin;
use std::task::{Context, Poll}; 

use tokio_rustls::{TlsAcceptor, TlsConnector, rustls};
use rustls::pki_types::ServerName; 

use crate::crypto;
use crate::logger;

pub async fn bridge(client_socket: TcpStream, initial_data: &[u8], target_host: &str) -> Result<(), Box<dyn Error>> {
    println!(" [PROXY] 🔓 Decrypting traffic for: {}", target_host);

    let (ca_cert, ca_key) = crypto::load_ca();
    let (certs, key) = crypto::forge_cert(target_host, &ca_cert, &ca_key);

    let server_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)?;
    let acceptor = TlsAcceptor::from(Arc::new(server_config));

    let target_addr = format!("{}:443", target_host);
    let upstream_socket = TcpStream::connect(&target_addr).await?;
    
    let mut root_store = rustls::RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    
    let client_config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    let connector = TlsConnector::from(Arc::new(client_config));
    
    let domain = ServerName::try_from(target_host.to_string())?;
    let upstream_tls = connector.connect(domain, upstream_socket).await?; // Removed mut

    let (read_half, write_half) = client_socket.into_split();
    let cursor = std::io::Cursor::new(initial_data.to_vec());
    let combined_reader = cursor.chain(read_half);
    
    let rewind_stream = RewindStream {
        reader: combined_reader,
        writer: write_half,
    };

    let client_tls = acceptor.accept(rewind_stream).await?; // Removed mut

    let (mut c_read, mut c_write) = tokio::io::split(client_tls);
    let (mut s_read, mut s_write) = tokio::io::split(upstream_tls);

    let c_to_s = async {
        let mut buf = [0u8; 8192];
        loop {
            match c_read.read(&mut buf).await {
                Ok(0) => break Ok::<(), std::io::Error>(()),
                Ok(n) => {
                    logger::dump_traffic("CLIENT -> SERVER", &buf[..n]);
                    if let Err(e) = s_write.write_all(&buf[..n]).await { break Err(e); }
                }
                Err(e) => break Err(e),
            }
        }
    };

    let s_to_c = async {
        let mut buf = [0u8; 8192];
        loop {
            match s_read.read(&mut buf).await {
                Ok(0) => break Ok::<(), std::io::Error>(()),
                Ok(n) => {
                    logger::dump_traffic("SERVER -> CLIENT", &buf[..n]);
                    if let Err(e) = c_write.write_all(&buf[..n]).await { break Err(e); }
                }
                Err(e) => break Err(e),
            }
        }
    };

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