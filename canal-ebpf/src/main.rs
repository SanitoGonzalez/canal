#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::xdp_action,
    // helpers::{bpf_timer_cancel, bpf_timer_init, bpf_timer_set_callback, bpf_timer_start},
    macros::xdp,
    programs::XdpContext
};
use aya_log_ebpf::info;

use canal_common::RudpHdr;
use core::mem;
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr},
    udp::UdpHdr,
};

// struct Retransmission {
//     pub timer: bpf_timer
// }

// #[map]
// static mut LISTEN_PORTS: HashMap<u16, u8> = HashMap::<u16, u8>::with_max_entries(64, 0);

// #[map]
// static mut ACTIVE_PORTS: HashMap<u16, u8> = HashMap::<u16, u8>::with_max_entries(32768, 0);

// #[map]
// static mut RETRANSMISSONS: HashMap<u32, Retransmission> = HashMap::<u32, Retransmission>::with_max_entries(32768, 0);

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
    info!(&ctx, " udp");

    let rudphdr: *mut RudpHdr = match ptr_at_mut(&ctx, offset) {
        Ok(hdr) => hdr,
        Err(_) => return Ok(xdp_action::XDP_PASS),
    };
    // offset += RudpHdr::LEN;
    info!(&ctx, " rudp?");

    // Checksum
    // if RudpHdr::calc_checksum(&unsafe{*udphdr}, &unsafe{*rudphdr}, offset, ctx.data_end())
    //         != u16::from_be(unsafe{*rudphdr}.check)
    // {
    //     // Checksum is inavlid
    // }

    // For experiment
    if unsafe{*udphdr}.dest == 30000 {
        info!(&ctx, " received a RDUP packet!");

        // Reflect with ACK
        reflect(ethhdr, ipv4hdr, udphdr);
        unsafe {
            (*rudphdr).control = RudpHdr::ACK;
            let seq = u16::from_be((*rudphdr).seq).wrapping_add(1);
            (*rudphdr).seq = seq.to_be();
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
        let tmp_addr = (*ethhdr).src_addr;
        (*ethhdr).src_addr = (*ethhdr).dst_addr;
        (*ethhdr).dst_addr = tmp_addr;

        // Swap IP addresses
        let tmp_addr = (*ipv4hdr).src_addr;
        (*ipv4hdr).src_addr = (*ipv4hdr).dst_addr;
        (*ipv4hdr).dst_addr = tmp_addr;

        // Swap UDP ports
        let tmp_port = (*udphdr).source;
        (*udphdr).source = (*udphdr).dest;
        (*udphdr).dest = tmp_port;
    }
}

// #[tc]
// fn rudp_egress(ctx: TcContext) -> i32 {
//     match try_egress(ctx) {
//         Ok(ret) => ret,
//         Err(_) => TC_ACT_SHOT
//     }
// }

// fn try_egress(ctx: TcContext) -> Result<i32, ()> {
    // let mut offset: usize = 0;

    // let ethhdr: *const EthHdr = ptr_at(ctx, offset)?;
    // offset += EthHdr::LEN;
    // match unsafe {*ethhdr}.ether_type {
    //     EtherType::Ipv4 => {},
    //     _ => return Ok(TC_ACT_OK)
    // }

    // let ipv4hdr: *const Ipv4Hdr = ptr_at(&ctx, offset)?;
    // offset += Ipv4Hdr::LEN;
    // match unsafe {*ipv4hdr}.proto {
    //     IpProto::Udp => {}
    //     _ => return Ok(TC_ACT_OK),
    // }

    // let udphdr: *const UdpHdr = ptr_at(&ctx, offset)?;
    // offset += UdpHdr::LEN;

    // let rudphdr: *const RudpHdr = match ptr_at(&ctx, offset) {
    //     Ok(hdr) => hdr,
    //     Err(_) => return Ok(TC_ACT_OK),
    // };
    // offset += RudpHdr::LEN;
// 
//     Ok(TC_ACT_OK)
// }

// #[inline(always)]
// fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, ()> {
//     let start = ctx.data();
//     let end = ctx.data_end();
//     let len = mem::size_of::<T>();

//     if start + offset + len > end {
//         return Err(());
//     }

//     Ok((start + offset) as *const T)
// }

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
