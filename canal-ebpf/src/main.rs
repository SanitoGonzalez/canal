#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::{bpf_timer, xdp_action, TC_ACT_OK, TC_ACT_SHOT},
    helpers::{bpf_timer_cancel, bpf_timer_init, bpf_timer_set_callback, bpf_timer_start},
    macros::{map, xdp}, maps::{HashMap, PerfEventArray},
    programs::{TcContext, XdpContext}
};
use aya_log_ebpf::{info, warn};

use canal_common::RudpHdr;
use core::mem;
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr},
    udp::UdpHdr,
};

struct Retransmission {
    pub timer: bpf_timer
}

#[map]
static mut LISTEN_PORTS: HashMap<u16, u8> = HashMap::<u16, u8>::with_max_entries(64, 0);

#[map]
static mut ACTIVE_PORTS: HashMap<u16, u8> = HashMap::<u16, u8>::with_max_entries(32768, 0);

#[map]
static mut RETRANSMISSONS: HashMap<u32, Retransmission> = HashMap::<u32, Retransmission>::with_max_entries(32768, 0);

// #[map]
// static mut CONNECTION_REQUESTS: PerfEventArray<ConnectionRequest> = PerfEventArray::new(0);

#[xdp]
pub fn rudp_ingress(ctx: XdpContext) -> u32 {
    match try_ingress(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

fn try_ingress(ctx: XdpContext) -> Result<u32, ()> {
    let mut offset: usize = 0;

    let ethhdr: *const EthHdr = ptr_at(&ctx, offset)?;
    offset += EthHdr::LEN;
    match unsafe {*ethhdr}.ether_type {
        EtherType::Ipv4 => {}
        _ => return Ok(xdp_action::XDP_PASS),
    }

    let ipv4hdr: *const Ipv4Hdr = ptr_at(&ctx, offset)?;
    offset += Ipv4Hdr::LEN;
    match unsafe {*ipv4hdr}.proto {
        IpProto::Udp => {}
        _ => return Ok(xdp_action::XDP_PASS),
    }

    let udphdr: *const UdpHdr = ptr_at(&ctx, offset)?;
    offset += UdpHdr::LEN;

    let rudphdr: *const RudpHdr = match ptr_at(&ctx, offset) {
        Ok(hdr) => hdr,
        Err(_) => return Ok(xdp_action::XDP_PASS),
    };
    offset += RudpHdr::LEN;

    // Check if listen port or socket
    let dest_port: u16 = u16::from_be(unsafe{*udphdr}.dest);
    if unsafe { LISTEN_PORTS.get(&dest_port).is_none() && ACTIVE_PORTS.get(&dest_port).is_none() } {
        // This is not RUDP packet
        return Ok(xdp_action::XDP_PASS);
    }

    // Checksum
    if RudpHdr::calc_checksum(&unsafe{*udphdr}, &unsafe{*rudphdr}, offset, ctx.data_end())
            != u16::from_be(unsafe{*rudphdr}.check)
    {
        // Checksum is inavlid
        //TODO: Request retransmission
    }

    //TODO: Strip off the headers and redirect to port via express path
    Ok(xdp_action::XDP_PASS)
}


fn retransmission_callback() -> i32 {



    0
}

// #[tc]
fn rudp_egress(ctx: TcContext) -> i32 {
    match try_egress(ctx) {
        Ok(ret) => ret,
        Err(_) => TC_ACT_SHOT
    }
}

fn try_egress(ctx: TcContext) -> Result<i32, ()> {
    let mut offset: usize = 0;

    let ethhdr: *const EthHdr = ptr_at(ctx, offset)?;
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
    offset += RudpHdr::LEN;

    Ok(TC_ACT_OK)
}

#[inline(always)]
fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();

    if start + offset + len > end {
        return Err(());
    }

    Ok((start + offset) as *const T)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
