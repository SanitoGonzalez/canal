use anyhow::Context as _;
use clap::Parser;
use aya::{
    maps::{HashMap, MapData},
    programs::{Xdp, XdpFlags}
};
use log::{debug, warn};

#[derive(Debug, Parser)]
pub struct RudpContextOpt {
    #[clap(short, long, default_value = "eth0")]
    iface: String,
}

pub struct RudpContext {
    _ebpf: aya::Ebpf,
    listen_ports: HashMap<&mut MapData, u16, u8>,
}

impl RudpContext {
    pub fn new(opt: RudpContextOpt) -> anyhow::Result<Self> {
        // Bump the memlock rlimit. This is needed for older kernels that don't use the
        // new memcg based accounting, see https://lwn.net/Articles/837122/
        let rlim = libc::rlimit {
            rlim_cur: libc::RLIM_INFINITY,
            rlim_max: libc::RLIM_INFINITY,
        };
        let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
        if ret != 0 {
            debug!("remove limit on locked memory failed, ret is: {}", ret);
        }

        // This will include your eBPF object file as raw bytes at compile-time and load it at
        // runtime. This approach is recommended for most real-world use cases. If you would
        // like to specify the eBPF program at runtime rather than at compile-time, you can
        // reach for `Bpf::load_file` instead.
        let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
            env!("OUT_DIR"),
            "/canal"
        )))?;
        if let Err(e) = aya_log::EbpfLogger::init(&mut ebpf) {
            // This can happen if you remove all log statements from your eBPF program.
            warn!("failed to initialize eBPF logger: {}", e);
        }
        let RudpContextOpt { iface } = opt;
        let program: &mut Xdp = ebpf.program_mut("rudp_ingress").unwrap().try_into()?;

        program.load()?;
        program.attach(&iface, XdpFlags::default())
            .context("failed to attach the XDP program with default flags - try changing XdpFlags::default() to XdpFlags::SKB_MODE")?;

        let mut listen_ports = HashMap::try_from(ebpf.map_mut("LISTEN_PORTS").unwrap())?;

        Ok(RudpContext {
            _ebpf: ebpf,
            listen_ports
        })
    }
}