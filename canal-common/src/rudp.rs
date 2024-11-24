use core::mem;
use network_types::udp::UdpHdr;

pub const RUDP_VER: u8 = 0b0100_0000;

/// RUDP header, which is present after the UDP header.
#[repr(C)]
#[derive(Debug, Copy, Clone)]
// #[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct RudpHdr {
    pub control: u8,
    pub hdr_len: u8,
    pub seq: u16,
    pub check: u16,
    pub custom: u16,
}

impl RudpHdr {
    pub const LEN: usize = mem::size_of::<RudpHdr>();

    pub const SYN: u8 = 0b0000_0001;
    pub const ACK: u8 = 0b0000_0010;
    pub const EAK: u8 = 0b0000_0100;
    pub const RST: u8 = 0b0000_1000;
    pub const NUL: u8 = 0b0001_0000;
    // 0b0010_0000 is not used (reserved)
    pub const VER: u8 = RUDP_VER;

    #[inline(always)]
    pub fn calc_checksum(
        udphdr: &UdpHdr,
        rudphdr: &RudpHdr,
        data_start: usize,
        data_end: usize,
    ) -> u16 {
        let data_length = data_end - data_start;

        let mut sum: u32 = u32::from(u16::from_be(udphdr.source))
            + u32::from(u16::from_be(udphdr.dest))
            + u32::from(u16::from_be(udphdr.len))
            + u32::from(rudphdr.control)
            + u32::from(rudphdr.hdr_len)
            + u32::from(u16::from_be(rudphdr.seq))
            + u32::from(u16::from_be(rudphdr.custom));

        // Add data section to checksum as 16-bit words
        let mut i = 0;
        while i + 1 < data_length {
            let word = unsafe {
                let ptr = (data_start + i) as *const u8;
                u16::from_be_bytes([*ptr, *ptr.add(1)])
            };
            sum += u32::from(word);

            i += 2;
        }

        // Handle odd byte
        if data_length % 2 == 1 {
            let last_byte = unsafe { *((data_start + data_length - 1) as *const u8) };
            sum += u32::from(last_byte) << 8;
        }

        // Add carries
        // Note: Bounded loop to make BPF verifier happy
        // while (sum >> 16) != 0 {
        for _ in 0..2 {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }

        !sum as u16
    }
}
