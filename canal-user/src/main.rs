use std::net::UdpSocket;
use std::io;

use canal_common::RudpHdr;

fn to_be_bytes(hdr: &RudpHdr) -> Vec<u8> {
    let mut buffer = Vec::with_capacity(RudpHdr::LEN);
    
    // Single bytes don't need conversion
    buffer.push(hdr.control);
    buffer.push(hdr.hdr_len);
    
    // Convert multi-byte fields to big-endian
    buffer.extend_from_slice(&hdr.seq.to_be_bytes());
    buffer.extend_from_slice(&hdr.check.to_be_bytes());
    buffer.extend_from_slice(&hdr.custom.to_be_bytes());
    
    buffer
}

// Convert from big-endian bytes back to RudpHdr
fn from_be_bytes(bytes: &[u8]) -> Option<RudpHdr> {
    if bytes.len() < size_of::<RudpHdr>() {
        return None;
    }

    Some(RudpHdr {
        control: bytes[0],
        hdr_len: bytes[1],
        seq: u16::from_be_bytes([bytes[2], bytes[3]]),
        check: u16::from_be_bytes([bytes[4], bytes[5]]),
        custom: u16::from_be_bytes([bytes[6], bytes[7]]),
    })
}

fn main() -> io::Result<()> {
    let sock = UdpSocket::bind("0.0.0.0:30000")?;
    println!("Receiving...");

    let mut count = 0;
    while count < 1000 {
        // let mut buf = [0u8; RudpHdr::LEN + std::mem::size_of::<u128>()];
        let mut buf = [0u8; 4096 + 32];

        let (bytes_read, src_addr) = sock.recv_from(&mut buf)?;
        sock.send_to(&mut buf[..bytes_read], src_addr)?;

        print!(".");
        count += 1;
    }

    Ok(())
}
