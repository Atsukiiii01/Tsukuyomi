/// A tactical logger to dump plaintext HTTP traffic to the terminal.
pub fn dump_traffic(direction: &str, data: &[u8]) {
    // We only care about printing readable text
    if let Ok(text) = std::str::from_utf8(data) {
        // Check if it looks like an HTTP request or response
        if text.starts_with("GET ") || text.starts_with("POST ") || text.starts_with("CONNECT ") || text.starts_with("HTTP/") {
            println!("\n[📡] ==== {} ====", direction);
            
            // Truncate so we don't flood the terminal with giant HTML bodies or images
            let display_len = std::cmp::min(text.len(), 1024);
            let display_text = &text[..display_len];
            
            // Print only the headers (we split by double-newline) to keep the terminal clean
            if let Some(header_end) = display_text.find("\r\n\r\n") {
                println!("{}", &display_text[..header_end]);
            } else {
                println!("{}", display_text);
            }
            
            println!("======================================\n");
        }
    }
}