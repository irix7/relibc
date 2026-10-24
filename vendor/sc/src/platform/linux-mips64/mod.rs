//! MIPS n32 Linux syscall backend.
//!
//! This replaces the original `llvm_asm!` implementation, which no longer
//! compiles on any supported Rust toolchain (`llvm_asm!` was removed).
//!
//! Syscall numbers are generated from `asm/unistd_n32.h` (base 6000); the n32
//! table is *not* n64+1000, so `nr.rs` is n32-specific.

use core::arch::asm;

pub mod nr;

#[inline(always)]
unsafe fn result(nr: usize, err: usize) -> usize {
    if err == 0 {
        nr
    } else {
        (-(nr as isize)) as usize
    }
}

#[inline(always)]
pub unsafe fn syscall0(nr: usize) -> usize {
    let ret: usize;
    let err: usize;
    unsafe {
        asm!(
            "syscall",
            inout("$2") nr => ret,
            lateout("$7") err,
            options(nostack),
        );
    }
    result(ret, err)
}

#[inline(always)]
pub unsafe fn syscall1(nr: usize, a1: usize) -> usize {
    let ret: usize;
    let err: usize;
    unsafe {
        asm!(
            "syscall",
            inout("$2") nr => ret,
            in("$4") a1,
            lateout("$7") err,
            options(nostack),
        );
    }
    result(ret, err)
}

#[inline(always)]
pub unsafe fn syscall2(nr: usize, a1: usize, a2: usize) -> usize {
    let ret: usize;
    let err: usize;
    unsafe {
        asm!(
            "syscall",
            inout("$2") nr => ret,
            in("$4") a1,
            in("$5") a2,
            lateout("$7") err,
            options(nostack),
        );
    }
    result(ret, err)
}

#[inline(always)]
pub unsafe fn syscall3(nr: usize, a1: usize, a2: usize, a3: usize) -> usize {
    let ret: usize;
    let err: usize;
    unsafe {
        asm!(
            "syscall",
            inout("$2") nr => ret,
            in("$4") a1,
            in("$5") a2,
            in("$6") a3,
            lateout("$7") err,
            options(nostack),
        );
    }
    result(ret, err)
}

// With four or more arguments, $7 is both argument 4 and the error flag.
#[inline(always)]
pub unsafe fn syscall4(nr: usize, a1: usize, a2: usize, a3: usize, a4: usize) -> usize {
    let ret: usize;
    let err: usize;
    unsafe {
        asm!(
            "syscall",
            inout("$2") nr => ret,
            in("$4") a1,
            in("$5") a2,
            in("$6") a3,
            inout("$7") a4 => err,
            options(nostack),
        );
    }
    result(ret, err)
}

#[inline(always)]
pub unsafe fn syscall5(
    nr: usize,
    a1: usize,
    a2: usize,
    a3: usize,
    a4: usize,
    a5: usize,
) -> usize {
    let ret: usize;
    let err: usize;
    unsafe {
        asm!(
            "syscall",
            inout("$2") nr => ret,
            in("$4") a1,
            in("$5") a2,
            in("$6") a3,
            inout("$7") a4 => err,
            in("$8") a5,
            options(nostack),
        );
    }
    result(ret, err)
}

#[inline(always)]
pub unsafe fn syscall6(
    nr: usize,
    a1: usize,
    a2: usize,
    a3: usize,
    a4: usize,
    a5: usize,
    a6: usize,
) -> usize {
    let ret: usize;
    let err: usize;
    unsafe {
        asm!(
            "syscall",
            inout("$2") nr => ret,
            in("$4") a1,
            in("$5") a2,
            in("$6") a3,
            inout("$7") a4 => err,
            in("$8") a5,
            in("$9") a6,
            options(nostack),
        );
    }
    result(ret, err)
}

#[inline(always)]
pub unsafe fn syscall7(
    nr: usize,
    a1: usize,
    a2: usize,
    a3: usize,
    a4: usize,
    a5: usize,
    a6: usize,
    a7: usize,
) -> usize {
    let ret: usize;
    let err: usize;
    unsafe {
        asm!(
            "syscall",
            inout("$2") nr => ret,
            in("$4") a1,
            in("$5") a2,
            in("$6") a3,
            inout("$7") a4 => err,
            in("$8") a5,
            in("$9") a6,
            in("$10") a7,
            options(nostack),
        );
    }
    result(ret, err)
}
