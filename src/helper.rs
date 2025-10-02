use aya_ebpf::programs::XdpContext;
use aya_ebpf_bindings::helpers::bpf_csum_diff;
use aya_log_ebpf::info;
use core::mem::size_of;
use network_types::{icmp::IcmpHdr, ip::Ipv4Hdr};

#[inline(always)]
pub fn csum_fold(mut csum: u64) -> u16 {
    for _i in 0..4 {
        if (csum >> 16) > 0 {
            csum = (csum & 0xffff) + (csum >> 16);
        }
    }
    !(csum as u16)
}

#[inline(always)]
pub fn iph_csum(iph: *mut Ipv4Hdr) -> u16 {
    unsafe {
        (*iph).check = [0, 0];
    }

    let csum: u64 =
        unsafe { bpf_csum_diff(0 as *mut u32, 0, iph as *mut u32, Ipv4Hdr::LEN as u32, 0) } as u64;

    csum_fold(csum).to_be()
}

#[inline(always)]
pub fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, u16> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = size_of::<T>();

    if start + offset + len > end {
        return Err(1);
    }

    Ok((start + offset) as *const T)
}

#[inline(always)]
pub fn ptr_at_mut<T>(ctx: &XdpContext, offset: usize) -> Result<*mut T, u16> {
    let ptr = ptr_at::<T>(ctx, offset)?;
    Ok(ptr as *mut T)
}

#[inline(always)]
pub fn log_icmp(ctx: &XdpContext, ipv4hdr: *mut Ipv4Hdr, icmphdr: *const IcmpHdr) {
    let type_ = unsafe { (*icmphdr).type_ };
    let dst_addr = unsafe { (*ipv4hdr).dst_addr };
    let src_addr = unsafe { (*ipv4hdr).src_addr };

    info!(ctx, "src={:i} dst={:i} ({})", src_addr, dst_addr, type_);
}
