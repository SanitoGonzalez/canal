#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::{bpf_timer, iphdr, xdp_action, TC_ACT_OK, TC_ACT_SHOT, TC_ACT_PIPE},
    macros::{classifier, map, xdp},
    maps::{Array, HashMap, PerCpuArray, RingBuf},
    programs::{TcContext, XdpContext}
};
use aya_log_ebpf::info;

use canal_common::RudpHdr;
use core::mem;
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr},
    udp::UdpHdr,
};

// const RETRANSMISSION_BUFFER_SIZE: usize = 4096;

#[repr(C)]
pub struct Buf {
   pub data: [u8; 4096],
}

#[map]
static mut BUF: PerCpuArray<Buf> = PerCpuArray::with_max_entries(128, 0);
static BUF_INDEX: u32 = 0;

#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct Retransmission {
    pub timer: bpf_timer,
    pub seq: u16,
    pub retries: u8,
    pub buf_index: u32,
}

impl Retransmission {
    pub const LEN: usize = mem::size_of::<Retransmission>();
}

#[map]
static DATA: RingBuf = RingBuf::with_byte_size(128 * Retransmission::LEN as u32, 0);

// #[map]
// static RETRANSMISSION_BUFFER: HashMap<u16, [u8; RETRANSMISSION_BUFFER_SIZE]>
//     = HashMap::<u16, [u8; RETRANSMISSION_BUFFER_SIZE]>::with_max_entries(512, 0);

#[map]
static RETRANSMISSIONS: HashMap<u16, Retransmission>
    = HashMap::<u16, Retransmission>::with_max_entries(128, 0);

#[xdp]
pub fn rudp_ingress(ctx: XdpContext) -> u32 {
    match try_ingress(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

fn try_ingress(ctx: XdpContext) -> Result<u32, ()> {
    let mut offset: usize = 0;
    
    let ethhdr: *mut EthHdr = ptr_at_mut(&ctx, offset)?;
    offset += EthHdr::LEN;
    match unsafe {*ethhdr}.ether_type {
        EtherType::Ipv4 => {}
        _ => return Ok(xdp_action::XDP_PASS),
    }
    
    let ipv4hdr: *mut Ipv4Hdr = ptr_at_mut(&ctx, offset)?;
    offset += Ipv4Hdr::LEN;
    match unsafe {*ipv4hdr}.proto {
        IpProto::Udp => {}
        _ => return Ok(xdp_action::XDP_PASS),
    }

    let udphdr: *mut UdpHdr = ptr_at_mut(&ctx, offset)?;
    offset += UdpHdr::LEN;

    let rudphdr: *mut RudpHdr = match ptr_at_mut(&ctx, offset) {
        Ok(hdr) => hdr,
        Err(_) => return Ok(xdp_action::XDP_PASS),
    };
    // offset += RudpHdr::LEN;

    // Checksum
    // if RudpHdr::calc_checksum(&unsafe{*udphdr}, &unsafe{*rudphdr}, offset, ctx.data_end())
    //         != u16::from_be(unsafe{*rudphdr}.check)
    // {
    //     // Checksum is inavlid
    // }

    // For experiment
    if u16::from_be(unsafe{*udphdr}.dest) == 30000 {
        info!(&ctx, " received a RDUP packet!");

        // Reflect with ACK
        reflect(ethhdr, ipv4hdr, udphdr);
        unsafe {
            (*rudphdr).control = RudpHdr::ACK;
            // let seq = u16::from_be((*rudphdr).seq).wrapping_add(1);
            // (*rudphdr).seq = seq.to_be();
        }

        //TODO: Recalculate checksum

        // Truncate packet

        return Ok(xdp_action::XDP_TX);
    }
    

    Ok(xdp_action::XDP_PASS)
}

fn reflect(ethhdr: *mut EthHdr, ipv4hdr: *mut Ipv4Hdr , udphdr: *mut UdpHdr) {
    unsafe {
        // Swap Ethernet addresses
        let tmp_mac = (*ethhdr).src_addr;
        (*ethhdr).src_addr = (*ethhdr).dst_addr;
        (*ethhdr).dst_addr = tmp_mac;

        // Swap IP addresses
        let tmp_addr = (*ipv4hdr).src_addr;
        (*ipv4hdr).src_addr = (*ipv4hdr).dst_addr;
        (*ipv4hdr).dst_addr = tmp_addr;

        // Swap UDP ports
        let tmp_port = (*udphdr).source;
        (*udphdr).source = (*udphdr).dest;
        (*udphdr).dest = tmp_port;

        // Recacluate checksums
        (*ipv4hdr).check = 0;
        (*udphdr).check = 0;

        let data = ipv4hdr as *const u8;
        let mut sum: u32 = 0;
        let words = core::slice::from_raw_parts(data as *const u16, Ipv4Hdr::LEN / 2);

        for word in words {
            sum += u32::from(u16::from_be(*word));
        }

        while (sum >> 16) != 0 {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }

        (*ipv4hdr).check = (!sum as u16).to_be();
    }
}

#[classifier]
fn rudp_egress(ctx: TcContext) -> i32 {
    match try_egress(ctx) {
        Ok(ret) => ret,
        Err(_) => TC_ACT_SHOT
    }
}

fn try_egress(ctx: TcContext) -> Result<i32, i32> {
    let mut offset: usize = 0;

    let ethhdr: *const EthHdr = ptr_at(&ctx, offset)?;
    offset += EthHdr::LEN;
    match unsafe {*ethhdr}.ether_type {
        EtherType::Ipv4 => {},
        _ => return Ok(TC_ACT_OK)
    }

    let ipv4hdr: *const Ipv4Hdr = ptr_at(&ctx, offset)?;
    offset += Ipv4Hdr::LEN;
    match unsafe {*ipv4hdr}.proto {
        IpProto::Udp => {}
        _ => return Ok(TC_ACT_OK),
    }

    let udphdr: *const UdpHdr = ptr_at(&ctx, offset)?;
    offset += UdpHdr::LEN;

    let rudphdr: *const RudpHdr = match ptr_at(&ctx, offset) {
        Ok(hdr) => hdr,
        Err(_) => return Ok(TC_ACT_OK),
    };
    // offset += RudpHdr::LEN;

    // For experiment
    if u16::from_be(unsafe{*udphdr}.source) == 30001 {
        info!(&ctx, " sending a RDUP packet!");

        // let data_len = ctx.data_end() - ctx.data();

        let seq = u16::from_be(unsafe{*rudphdr}.seq);

        let buf_index = BUF_INDEX.wrapping_add(1);
        let buf = unsafe {
            let ptr = BUF.get_ptr_mut(buf_index).ok_or(TC_ACT_OK)?;
            &mut *ptr
        };
        // ctx.load_bytes(0, &mut buf.data).map_err(|_| TC_ACT_OK)?;

        let mut rt = DATA.reserve::<Retransmission>(0).ok_or(TC_ACT_OK)?;
        unsafe{*rt.as_mut_ptr()}.buf_index = buf_index;
        if let Err(_) = RETRANSMISSIONS.insert(&seq, &unsafe{*rt.as_mut_ptr()}, 0) {
            info!(&ctx, "Failed to insert packet into retransmission buffer");
        }
        rt.submit(0);

        return Ok(TC_ACT_OK);
    }

    Ok(TC_ACT_OK)
}

#[inline(always)]
fn ptr_at<T>(ctx: &TcContext, offset: usize) -> Result<*const T, i32> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();

    if start + offset + len > end {
        return Err(0);
    }

    Ok((start + offset) as *const T)
}

#[inline(always)]
fn ptr_at_mut<T>(ctx: &XdpContext, offset: usize) -> Result<*mut T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();

    if start + offset + len > end {
        return Err(());
    }

    Ok((start + offset) as *mut T)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
