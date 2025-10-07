use network_types::{eth::EthHdr, ip::Ipv4Hdr, udp::UdpHdr};

pub enum Mode {
    Src,
    Dst,
}

pub trait HasAddr<A> {
    fn addr(&self, mode: Mode) -> A;
}

impl HasAddr<[u8; 6]> for EthHdr {
    #[inline(always)]
    fn addr(&self, mode: Mode) -> [u8; 6] {
        match mode {
            Mode::Src => self.src_addr,
            Mode::Dst => self.dst_addr,
        }
    }
}

impl HasAddr<[u8; 4]> for Ipv4Hdr {
    #[inline(always)]
    fn addr(&self, mode: Mode) -> [u8; 4] {
        match mode {
            Mode::Src => self.src_addr,
            Mode::Dst => self.dst_addr,
        }
    }
}

impl HasAddr<u16> for UdpHdr {
    #[inline(always)]
    fn addr(&self, mode: Mode) -> u16 {
        match mode {
            Mode::Src => self.src_port(),
            Mode::Dst => self.dst_port(),
        }
    }
}

#[inline(always)]
pub fn drop<H, A>(hdr: *const H, needle: A, mode: Mode) -> bool
where
    H: HasAddr<A>,
    A: PartialEq + Copy,
{
    let addr = unsafe { (*hdr).addr(mode) };
    addr == needle
}
