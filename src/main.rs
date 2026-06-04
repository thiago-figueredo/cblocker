mod blocklist;

use std::{
    io,
    net::{IpAddr, SocketAddr},
    os::unix::io::AsRawFd,
    sync::{Arc, RwLock},
};

use blocklist::{block_sni, Blocklist};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};

const LISTEN_ADDR: &str = "0.0.0.0:8443";

// linux/netfilter_ipv6/ip6_tables.h
const IP6T_SO_ORIGINAL_DST: libc::c_int = 80;

#[tokio::main]
async fn main() -> io::Result<()> {
    let blocked = Arc::new(RwLock::new(Blocklist::load()));

    println!("Listening on {}", LISTEN_ADDR);

    let listener = TcpListener::bind(LISTEN_ADDR).await?;

    loop {
        let (stream, addr) = listener.accept().await?;

        let blocked = blocked.clone();

        tokio::spawn(async move {
            if let Err(e) = handle_client(stream, addr, blocked).await {
                eprintln!("[{}] error: {}", addr, e);
            }
        });
    }
}

async fn handle_client(
    mut client: TcpStream,
    peer: SocketAddr,
    blocked: Arc<RwLock<Blocklist>>,
) -> io::Result<()> {
    // Check the original destination IP before reading any data.
    // This catches ECH connections where the real SNI is encrypted and the
    // outer ClientHello only carries the Cloudflare public name instead.
    if let Some(dst_ip) = get_original_dst(&client) {
        if blocked.read().unwrap().is_ip_blocked(dst_ip) {
            println!("[BLOCKED] {} (destination IP {})", peer, dst_ip);
            client.shutdown().await?;
            return Ok(());
        }
    }

    // Read initial TLS packet
    let data = read_client_hello(&mut client).await?;

    if data.is_empty() {
        return Ok(());
    }

    // Extract SNI
    let sni = match extract_sni(&data) {
        Some(host) => host,
        None => {
            eprintln!("[{}] no SNI found", peer);
            return Ok(());
        }
    };

    println!("[{}] SNI => {}", peer, sni);

    // Check domain blocklist and direct IP SNI (e.g. client connected by IP)
    let is_blocked = {
        let bl = blocked.read().unwrap();
        bl.is_domain_blocked(&sni)
            || sni.parse::<IpAddr>().ok().map_or(false, |ip| bl.is_ip_blocked(ip))
    };

    if is_blocked {
        println!("[BLOCKED] {}", sni);
        client.shutdown().await?;
        return Ok(());
    }

    // IMPORTANT:
    // In a real transparent proxy you would recover the original
    // destination using SO_ORIGINAL_DST.
    //
    // For this MVP example, we simply connect to port 443
    // on the SNI hostname.
    relay(client, &sni, &data, blocked).await
}

async fn read_client_hello(client: &mut TcpStream) -> io::Result<Vec<u8>> {
    let mut buf = vec![0u8; 4096];
    let n = client.read(&mut buf).await?;
    buf.truncate(n);
    Ok(buf)
}

async fn relay(
    mut client: TcpStream,
    sni: &str,
    initial_data: &[u8],
    blocked: Arc<RwLock<Blocklist>>,
) -> io::Result<()> {
    let target = format!("{}:443", sni);

    let mut server = match TcpStream::connect(&target).await {
        Ok(s) => s,
        Err(e) => {
            eprintln!("connect failed: {}", e);
            return Ok(());
        }
    };

    // Forward initial bytes already read
    server.write_all(initial_data).await?;

    // Bidirectional relay
    let (mut cr, mut cw) = client.split();
    let (mut sr, mut sw) = server.split();

    let client_to_server = tokio::io::copy(&mut cr, &mut sw);
    let server_to_client = tokio::io::copy(&mut sr, &mut cw);

    if let Err(e) = tokio::try_join!(client_to_server, server_to_client) {
        if e.kind() == io::ErrorKind::BrokenPipe {
            block_sni(sni, &blocked);
        } else {
            return Err(e);
        }
    }

    Ok(())
}

fn get_original_dst(stream: &TcpStream) -> Option<IpAddr> {
    let fd = stream.as_raw_fd();

    // Try IPv4 SO_ORIGINAL_DST
    unsafe {
        let mut addr: libc::sockaddr_in = std::mem::zeroed();
        let mut len = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;

        if libc::getsockopt(
            fd,
            libc::SOL_IP,
            libc::SO_ORIGINAL_DST,
            &mut addr as *mut _ as *mut libc::c_void,
            &mut len,
        ) == 0 {
            return Some(IpAddr::V4(std::net::Ipv4Addr::from(
                u32::from_be(addr.sin_addr.s_addr),
            )));
        }
    }

    // Try IPv6 IP6T_SO_ORIGINAL_DST
    unsafe {
        let mut addr: libc::sockaddr_in6 = std::mem::zeroed();
        let mut len = std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t;

        if libc::getsockopt(
            fd,
            libc::SOL_IPV6,
            IP6T_SO_ORIGINAL_DST,
            &mut addr as *mut _ as *mut libc::c_void,
            &mut len,
        ) == 0 {
            return Some(IpAddr::V6(std::net::Ipv6Addr::from(
                addr.sin6_addr.s6_addr,
            )));
        }
    }

    None
}

// Very small TLS ClientHello SNI parser
//
// This is NOT production-grade.
// It is intentionally minimal for learning purposes.
fn extract_sni(data: &[u8]) -> Option<String> {
    // TLS record header minimum size
    if data.len() < 5 {
        return None;
    }

    // TLS handshake record
    if data[0] != 0x16 {
        return None;
    }

    let mut pos = 5;

    // Handshake type: ClientHello
    if data.get(pos)? != &0x01 {
        return None;
    }

    pos += 4; // handshake header

    pos += 2; // version
    pos += 32; // random

    // Session ID
    let session_len = *data.get(pos)? as usize;
    pos += 1 + session_len;

    // Cipher suites
    let cipher_len =
        u16::from_be_bytes([*data.get(pos)?, *data.get(pos + 1)?]) as usize;
    pos += 2 + cipher_len;

    // Compression methods
    let comp_len = *data.get(pos)? as usize;
    pos += 1 + comp_len;

    // Extensions
    let ext_len =
        u16::from_be_bytes([*data.get(pos)?, *data.get(pos + 1)?]) as usize;
    pos += 2;

    let ext_end = pos + ext_len;

    while pos + 4 <= ext_end && pos + 4 <= data.len() {
        let ext_type =
            u16::from_be_bytes([data[pos], data[pos + 1]]);

        let ext_size =
            u16::from_be_bytes([data[pos + 2], data[pos + 3]]) as usize;

        pos += 4;

        // SNI extension
        if ext_type == 0x0000 {
            // Server Name list length
            pos += 2;

            // Name type
            pos += 1;

            let name_len =
                u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;

            pos += 2;

            let hostname =
                std::str::from_utf8(&data[pos..pos + name_len]).ok()?;

            return Some(hostname.to_string());
        }

        pos += ext_size;
    }

    None
}
