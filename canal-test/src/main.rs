use std::net::UdpSocket;
// use tokio::net::UdpSocket;
use std::io;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use std::sync::Arc;

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

// #[tokio::main]
fn main() -> io::Result<()> {
    let sock = UdpSocket::bind("0.0.0.0:30001")?;
    sock.set_read_timeout(Some(Duration::from_secs(3)))?;
    sock.set_write_timeout(Some(Duration::from_secs(3)))?;
    sock.connect("ip address to remotehost:30000")?;

    let mut seq: u16 = 1000;
    let mut rtt_sum: u128 = 0;
    
    while seq < 2000 {
        let header = RudpHdr {
            control: 0,
            hdr_len: RudpHdr::LEN as u8,
            seq: seq.to_be(),
            check: 0xFFFF,
            custom: 0x0000
        };
        
        let mut send_buf = Vec::<u8>::with_capacity(RudpHdr::LEN + std::mem::size_of::<u128>());
        send_buf.extend_from_slice(&to_be_bytes(&header));
        send_buf.extend_from_slice(&SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_micros()
            .to_be_bytes());
        
        sock.send(&send_buf)?;
        
        let mut recv_buf = [0u8; RudpHdr::LEN + std::mem::size_of::<u128>()];
        sock.recv(&mut recv_buf)?;

        let header = from_be_bytes(&recv_buf).unwrap();
        let past = u128::from_be_bytes(recv_buf[RudpHdr::LEN..].try_into().unwrap());
        
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_micros();
        // println!("seq: {}", u16::from_be(header.seq));
        // println!("RTT: {}", now - past);
        rtt_sum += now - past;

        seq += 1;
    }
    
    println!("RTT avg: {}", u64::try_from(rtt_sum).unwrap() as f64 / 1000.0);

    // receiver.await?;

    Ok(())
}
