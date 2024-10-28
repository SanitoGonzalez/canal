use core::mem;
use network_types::udp::UdpHdr;

/// RUDP header, which is present after the UDP header.
#[repr(C)]
#[derive(Debug, Copy, Clone)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct RudpHdr {
    pub control: u8,
    pub seq: u16,
    pub check: u16,
    pub length: u16,
}

impl RudpHdr {
    pub const LEN: usize = mem::size_of::<RudpHdr>();

    #[inline(always)]
    pub fn calc_checksum(udphdr: &UdpHdr, rudphdr: &RudpHdr, data_offset: usize) -> u16 {
        let data_length = usize::from(u16::from_be(rudphdr.length));

        // let mut sum: u32 = 0;
        let mut sum: u32 = u32::from(u16::from_be(udphdr.source))
            + u32::from(u16::from_be(udphdr.dest))
            + u32::from(u16::from_be(udphdr.len))
            + u32::from(rudphdr.control)
            + u32::from(u16::from_be(rudphdr.seq))
            + u32::from(u16::from_be(rudphdr.length));

        // Add data section to checksum as 16-bit words
        let mut i = 0;
        while i + 1 < data_length {
            let word = unsafe {
                let ptr = (data_offset + i) as *const u8;
                u16::from_be_bytes([*ptr, *ptr.add(1)])
            };
            sum += u32::from(word);

            i += 2;
        }

        // // Handle odd byte
        if data_length % 2 == 1 {
            let last_byte = unsafe { *((data_offset + data_length - 1) as *const u8) };
            sum += u32::from(last_byte) << 8;
        }

        // Add carries
        // Bounded loop to make BPF verifier happy
        // while (sum >> 16) != 0 {
        for _ in 0..2 {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }

        !sum as u16
    }
}
