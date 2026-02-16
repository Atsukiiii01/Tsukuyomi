mod sniffer;
mod proxy;
mod crypto; // Placeholder for Phase 2

use tokio::net::TcpListener;
use tokio::io::AsyncReadExt;
use std::error::Error;

// You can change this port if needed
const LISTENER_ADDR: &str = "127.0.0.1:8080";

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // Bind the listener. If this fails, the program crashes (as it should).
    let listener = TcpListener::bind(LISTENER_ADDR).await?;
    
    println!("--- TSUKUYOMI V0.2 ONLINE ---");
    println!("Listening on: {}", LISTENER_ADDR);
    println!("Waiting for traffic...");

    loop {
        // Accept socket, ignore client address for now
        let (mut socket, _addr) = listener.accept().await?;

        // Spawn a lightweight thread for every connection so we don't block
        tokio::spawn(async move {
            let mut buffer = [0u8; 4096]; // 4kb buffer is usually enough for a Hello

            // We need to 'peek' at the data to decide what to do.
            match socket.read(&mut buffer).await {
                Ok(n) if n > 0 => {
                    // Pass the raw bytes to the sniffer module
                    if let Some(target) = sniffer::extract_sni(&buffer[..n]) {
                        println!(" [TARGET ACQUIRED] >> {}", target);

                        // HANDOFF: Call the bridge function in proxy.rs
                        // We pass the socket, the data we already read, and the target.
                        if let Err(e) = proxy::bridge(socket, &buffer[..n], &target).await {
                            eprintln!(" [ERROR] Bridge failed for {}: {}", target, e);
                        }

                    } else {
                        // Takes care of noise/bots or non-TLS traffic
                         println!(" [DEBUG] Ignored non-SNI packet"); 
                    }
                },
                Ok(_) => { /* Client disconnected immediately */ }
                Err(e) => eprintln!(" [ERROR] Socket read failed: {}", e),
            }
        });
    }
}