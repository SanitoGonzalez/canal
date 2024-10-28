#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::xdp_action,
    macros::{map, xdp},
    maps::HashMap,
    programs::XdpContext,
};
use aya_log_ebpf::info;

use canal_common::RudpHdr;
use core::mem;
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr},
    udp::UdpHdr,
};

#[map]
static MYMAP: HashMap<u32, u32> = HashMap::<u32, u32>::with_max_entries(1024, 0);

#[xdp]
pub fn canal_ingress(ctx: XdpContext) -> u32 {
    match try_ingress(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

fn try_ingress(ctx: XdpContext) -> Result<u32, ()> {
    let mut offset: usize = 0;

    let ethhdr: *const EthHdr = ptr_at(&ctx, offset)?;
    offset += EthHdr::LEN;
    match unsafe { (*ethhdr).ether_type } {
        EtherType::Ipv4 => {}
        _ => return Ok(xdp_action::XDP_PASS),
    }

    let ipv4hdr: *const Ipv4Hdr = ptr_at(&ctx, offset)?;
    offset += Ipv4Hdr::LEN;
    match unsafe { (*ipv4hdr).proto } {
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

    //Determine if RUDP header with length field
    if ctx.data() + offset + unsafe { usize::from(u16::from_be((*rudphdr).length)) }
        != ctx.data_end()
    {
        return Ok(xdp_action::XDP_PASS);
    }

    if unsafe {
        RudpHdr::calc_checksum(&*udphdr, &*rudphdr, offset) != u16::from_be((*rudphdr).check)
    } {
        // DROP?
    }

    // Should not reach?
    Ok(xdp_action::XDP_PASS)
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
