//! Auxiliary-vector types for the IRIX 7 native loader.
//!
//! The kernel uses its own compact numbering rather than the Linux one: the
//! vector is `[type, value]` pairs terminated by `AT_NULL`/0, and the C oracle
//! in `user/c-probe/abi.h` pins every value.  Keep this file in step with
//! `kernel/src/user.rs::initial_stack`.

pub const AT_NULL: usize = 0; /* End of vector */
pub const AT_PAGESZ: usize = 1; /* System page size */
pub const AT_ENTRY: usize = 2; /* Entry point of program */
pub const AT_PHDR: usize = 3; /* Program headers for program */
pub const AT_PHNUM: usize = 4; /* Number of program header entries */
// The v0 loader does not emit AT_PHENT; the constant exists because the
// static linker startup reads it, but the arm is unreachable.
pub const AT_PHENT: usize = 16;
pub const AT_BASE: usize = 5; /* Base address of interpreter */
pub const AT_RANDOM: usize = 6; /* Address of 16 random bytes */
pub const AT_EXECFN: usize = 7; /* Filename of executable */
pub const AT_UID: usize = 8; /* Real uid */
pub const AT_EUID: usize = 9; /* Effective uid */
pub const AT_GID: usize = 10; /* Real gid */
pub const AT_EGID: usize = 11; /* Effective gid */
pub const AT_HWCAP: usize = 12; /* Machine-dependent hints */
pub const AT_CLKTCK: usize = 13; /* Frequency of times() */
pub const AT_SECURE: usize = 14; /* Secure mode boolean */
pub const AT_PLATFORM: usize = 15; /* String identifying platform */
