//! `setjmp.h` implementation.
//!
//! See <https://pubs.opengroup.org/onlinepubs/9799919799/basedefs/setjmp.h.html>.

use core::arch::global_asm;

use crate::platform::types::{c_int, c_ulonglong};

macro_rules! platform_specific {
    ($($rust_arch:expr,$c_arch:expr,$ext:expr;)+) => {
        $(
            #[cfg(target_arch = $rust_arch)]
            global_asm!(include_str!(concat!("impl/", $c_arch, "/setjmp.", $ext)));
            #[cfg(target_arch = $rust_arch)]
            global_asm!(include_str!(concat!("impl/", $c_arch, "/sigsetjmp.", $ext)));
            #[cfg(target_arch = $rust_arch)]
            global_asm!(include_str!(concat!("impl/", $c_arch, "/longjmp.", $ext)));
        )+
    }
}

platform_specific! {
    "aarch64","aarch64", "s";
    "x86","i386","s";
    "x86_64","x86_64","s";
    "riscv64", "riscv64", "S";
}

// MIPS n32 needs two variants: the upstream files contain a
// `#ifndef __mips_soft_float` guard around the FP save/restore, but
// `global_asm!` is assembled without a preprocessor, so the guard never takes
// effect.  IRIX 7 is a `+soft-float` target, and `sdc1`/`ldc1` are rejected by
// the assembler there, so use copies with the FP block removed.
#[cfg(all(target_arch = "mips64", not(target_os = "irix7")))]
global_asm!(include_str!("impl/mipsn32/setjmp.S"));
#[cfg(all(target_arch = "mips64", not(target_os = "irix7")))]
global_asm!(include_str!("impl/mipsn32/sigsetjmp.S"));
#[cfg(all(target_arch = "mips64", not(target_os = "irix7")))]
global_asm!(include_str!("impl/mipsn32/longjmp.S"));

#[cfg(all(target_arch = "mips64", target_os = "irix7"))]
global_asm!(include_str!("impl/mipsn32-soft/setjmp.S"));
#[cfg(all(target_arch = "mips64", target_os = "irix7"))]
global_asm!(include_str!("impl/mipsn32-soft/sigsetjmp.S"));
#[cfg(all(target_arch = "mips64", target_os = "irix7"))]
global_asm!(include_str!("impl/mipsn32-soft/longjmp.S"));

//Each platform has different sizes for sigjmp_buf, currently only x86_64 is supported
unsafe extern "C" {
    /// See <https://pubs.opengroup.org/onlinepubs/9799919799/functions/setjmp.html>.
    pub unsafe fn setjmp(env: *mut c_ulonglong) -> c_int;
    /// See <https://pubs.opengroup.org/onlinepubs/9799919799/functions/sigsetjmp.html>.
    pub unsafe fn sigsetjmp(env: *mut c_ulonglong, savemask: c_int) -> c_int;
    /// See <https://pubs.opengroup.org/onlinepubs/9799919799/functions/longjmp.html>.
    pub unsafe fn longjmp(env: *mut c_ulonglong, val: c_int);
}

/// See <https://pubs.opengroup.org/onlinepubs/9799919799/functions/siglongjmp.html>.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn siglongjmp(env: *mut c_ulonglong, val: c_int) {
    unsafe { longjmp(env, val) };
}
