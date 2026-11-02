//! crt0

#![no_std]
#![feature(asm_experimental_arch)]
#![feature(linkage)]

use core::{
    arch::global_asm,
    ffi::{c_char, c_int},
};

#[cfg(target_arch = "aarch64")]
global_asm!(
    "
    .globl _start
_start:
    mov x0, sp
    and sp, x0, #0xfffffffffffffff0 //align sp
    bl relibc_crt0
"
);

#[cfg(target_arch = "x86")]
global_asm!(
    "
    .globl _start
    .type _start, @function
_start:
    sub esp, 8

    mov DWORD PTR [esp], 0x00001F80
    # ldmxcsr [esp]
    mov WORD PTR [esp], 0x037F
    fldcw [esp]

    add esp, 8

    push esp
    call relibc_crt0
    .size _start, . - _start
"
);

#[cfg(target_arch = "x86_64")]
global_asm!(
    "
    .globl _start
    .type _start, @function
_start:
    mov rdi, rsp
    and rsp, 0xFFFFFFFFFFFFFFF0

    sub rsp, 8

    mov DWORD PTR [rsp], 0x00001F80
    ldmxcsr [rsp]
    mov WORD PTR [rsp], 0x037F
    fldcw [rsp]

    add rsp, 8

    call relibc_crt0
    .size _start, . - _start
"
);

#[cfg(target_arch = "riscv64")]
global_asm!(
    "
    .globl _start
_start:
    mv a0, sp
    la t0, relibc_crt0
    jalr ra, t0
"
);

// MIPS n32 (IRIX 7).  The kernel enters with the System V stack in `$sp`,
// `$a3` pointing at the auxiliary vector, and `$28` zero.  Establish the
// main-thread TCB (`self` at 0, `dtv` 0 at 4, `errno` at 8, libc-private at 12)
// before any Rust code runs, and stash `$a3` for `Stack::auxv`.  MIPS III has
// no `rdhwr`, so `$28` is the only thread pointer.
//
// `-mno-abicalls` is required by the target, so use an absolute `la`/`jalr`
// call rather than `$gp`-relative abicalls.
#[cfg(all(target_arch = "mips64", target_os = "irix7"))]
global_asm!(
    "
    .set noreorder
    .set mips3
    .globl _start
    .type _start, @function
_start:
    lui $8, %hi(__irix7_main_tcb)
    addiu $8, $8, %lo(__irix7_main_tcb)
    sw $8, 0($8)                # self
    sw $zero, 4($8)             # dtv: no ELF TLS on this target
    sw $zero, 8($8)             # errno
    sw $zero, 12($8)            # libc-private
    move $28, $8

    lui $9, %hi(__irix7_auxv)
    addiu $9, $9, %lo(__irix7_auxv)
    sw $7, 0($9)                # $a3 = auxv

    move $4, $sp
    la $25, relibc_crt0
    jalr $25
    nop
    .size _start, . - _start

    .bss
    .align 4
__irix7_main_tcb:
    .space 16
"
);

#[unsafe(no_mangle)]
pub unsafe extern "C" fn relibc_crt0(sp: usize) -> ! {
    // This wrapper ensures a dynamic libc.so can access a hidden main function
    //TODO: common definition of types
    unsafe extern "C" {
        fn main(argc: isize, argv: *mut *mut c_char, envp: *mut *mut c_char) -> c_int;
        fn relibc_start_v1(
            sp: usize,
            main: unsafe extern "C" fn(
                argc: isize,
                argv: *mut *mut c_char,
                envp: *mut *mut c_char,
            ) -> c_int,
        ) -> !;
    }
    unsafe { relibc_start_v1(sp, main) }
}

#[linkage = "weak"]
#[unsafe(no_mangle)]
pub extern "C" fn relibc_panic(_pi: &::core::panic::PanicInfo) -> ! {
    loop {}
}

#[panic_handler]
#[linkage = "weak"]
pub unsafe fn rust_begin_unwind(pi: &::core::panic::PanicInfo) -> ! {
    relibc_panic(pi)
}
