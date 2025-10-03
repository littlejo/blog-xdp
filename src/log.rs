use aya_log_ebpf::info;
use aya_ebpf::programs::XdpContext;
use network_types::{ip::Ipv4Hdr, eth::EthHdr, udp::UdpHdr};

pub trait DisplayHdr {
    fn log(&self, ctx: &XdpContext);
}

impl DisplayHdr for EthHdr {
    fn log(&self, ctx: &XdpContext) {
        info!(
            ctx,
            "EthHdr: src: {:mac} => dst: {:mac} ({})",
            self.src_addr,
            self.dst_addr,
            self.ether_type
        );
    }
}

impl DisplayHdr for Ipv4Hdr {
    fn log(&self, ctx: &XdpContext) {
        info!(
            ctx,
            "Ipv4Hdr: src: {:i} => dst: {:i} ({})", self.src_addr, self.dst_addr, self.proto as u8
        );
    }
}

impl DisplayHdr for UdpHdr {
    fn log(&self, ctx: &XdpContext) {
        info!(
            ctx,
            "UdpHdr: src: {} => dst: {}",
            self.src_port(),
            self.dst_port()
        );
    }
}

#[inline(always)]
pub fn display_hdr<T: DisplayHdr>(ctx: &XdpContext, hdr: *const T) {
    unsafe { &*hdr }.log(ctx);
}
