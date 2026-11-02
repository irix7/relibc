//! Platform abstractions and environment.

use crate::{
    error::{Errno, ResultExt},
    io::{self, Read, Write},
    raw_cell::RawCell,
};
use alloc::{boxed::Box, vec::Vec};
use core::{
    cell::{Cell, UnsafeCell},
    fmt, ptr,
};

pub use self::allocator::*;

mod allocator;

pub mod logger;

pub use self::pal::{Pal, PalEpoll, PalPtrace, PalSignal, PalSocket};

mod pal;

pub use self::sys::Sys;

#[cfg(target_os = "linux")]
#[path = "linux/mod.rs"]
pub(crate) mod sys;

#[cfg(target_os = "redox")]
#[path = "redox/mod.rs"]
pub(crate) mod sys;

#[cfg(target_os = "irix7")]
#[path = "irix7/mod.rs"]
pub(crate) mod sys;

pub use self::rlb::{Line, RawLineBuffer};
pub mod rlb;

#[cfg(target_os = "irix7")]
#[path = "auxv_defs_irix7.rs"]
pub mod auxv_defs;

#[cfg(target_os = "linux")]
#[path = "auxv_defs.rs"]
pub mod auxv_defs;

#[cfg(target_os = "redox")]
pub use redox_rt::auxv_defs;

use self::types::{c_char, c_int};
pub mod types;

/// The global `errno` variable used internally in relibc.
#[cfg(not(target_os = "irix7"))]
#[thread_local]
pub static ERRNO: Cell<c_int> = Cell::new(0);

/// `errno` storage on the main-thread TCB.
///
/// The native image's `_start` sets `$28` to a 16-byte TCB: `self` at 0, `dtv`
/// at 4, `errno` at 8 and libc-private space at 12.  `__errno_location` is
/// therefore `TP + 8`, and this type reads and writes that slot directly.  The
/// target declares `has-thread-local: false`; there is no ELF TLS block.
#[cfg(target_os = "irix7")]
#[inline(always)]
fn thread_pointer() -> *mut c_int {
    let tp: usize;
    // SAFETY: reading `$28` has no side effects.  `_start` establishes the TCB
    // before any Rust code runs, and the kernel preserves `$28` across the
    // native gate.
    unsafe {
        core::arch::asm!("move {tp}, $28", tp = out(reg) tp, options(nomem, nostack));
    }
    tp as *mut c_int
}

#[cfg(target_os = "irix7")]
#[inline(always)]
fn errno_slot() -> *mut c_int {
    // TP points at the start of the TCB; errno is the third 32-bit word.
    unsafe { thread_pointer().cast::<u8>().add(8).cast::<c_int>() }
}

#[cfg(target_os = "irix7")]
pub struct TcbErrno;

#[cfg(target_os = "irix7")]
impl TcbErrno {
    pub fn get(&self) -> c_int {
        // SAFETY: the TCB is mapped and errno is a plain 32-bit word.
        unsafe { core::ptr::read_volatile(errno_slot()) }
    }
    pub fn set(&self, value: c_int) {
        // SAFETY: as above.
        unsafe { core::ptr::write_volatile(errno_slot(), value) };
    }
    pub fn as_ptr(&self) -> *mut c_int {
        errno_slot()
    }
}
#[cfg(target_os = "irix7")]
pub static ERRNO: TcbErrno = TcbErrno;

/// A `static` that POSIX leaves process-wide on this target.
///
/// Rust requires `static` items to be `Sync`, but `Cell` and `RefCell` are
/// deliberately not.  The remaining user is `h_errno`, which POSIX leaves
/// process-wide; pthread keys, cleanup handlers, thread-exit handlers and
/// errno live in the TCB and the `Pthread` record.
#[cfg(target_os = "irix7")]
pub struct SingleThread<T>(pub T);

// SAFETY: the cooperative kernel has no preemption and no signal delivery, so
// these process-wide values cannot be touched concurrently between syscalls.
#[cfg(target_os = "irix7")]
unsafe impl<T> Sync for SingleThread<T> {}

#[cfg(target_os = "irix7")]
impl<T> core::ops::Deref for SingleThread<T> {
    type Target = T;
    fn deref(&self) -> &T {
        &self.0
    }
}

/// The `argv` argument available to a program's `main` function.
// TODO: change remaining static mut to RawCell
pub static mut argv: *mut *mut c_char = ptr::null_mut();
pub static inner_argv: RawCell<Vec<*mut c_char>> = RawCell::new(Vec::new());
pub static mut program_invocation_name: *mut c_char = ptr::null_mut();
pub static mut program_invocation_short_name: *mut c_char = ptr::null_mut();

#[unsafe(no_mangle)]
pub static mut environ: *mut *mut c_char = ptr::null_mut();

pub static OUR_ENVIRON: RawCell<Vec<*mut c_char>> = RawCell::new(Vec::new());

/// Auxiliary-vector pointer handed to `_start` in `$a3`.
///
/// The kernel builds the System V stack and passes `$a3 = auxv`; `crt0`
/// stores that pointer here before entering Rust, and [`crate::start::Stack`]
/// returns it.  It is a plain word rather than an argument so the stack shape
/// stays exactly the System V one the kernel writes.
#[cfg(target_os = "irix7")]
#[unsafe(no_mangle)]
pub static mut __irix7_auxv: usize = 0;

/// Look up one auxiliary-vector entry.
///
/// The vector is the one the kernel passed in `$a3`; the numbering is the
/// native one in [`auxv_defs`], not Linux's.
#[cfg(target_os = "irix7")]
pub fn getauxval(kind: usize) -> usize {
    // SAFETY: the pointer is set by `_start` before Rust runs and points at a
    // kernel-built, AT_NULL-terminated array of [type, value] pairs.
    unsafe {
        let mut at = __irix7_auxv as *const usize;
        if at.is_null() {
            return 0;
        }
        while *at != 0 {
            if *at == kind {
                return *at.add(1);
            }
            at = at.add(2);
        }
        0
    }
}

pub fn environ_iter() -> impl Iterator<Item = *mut c_char> + 'static {
    unsafe {
        let mut ptrs = environ;

        core::iter::from_fn(move || {
            if ptrs.is_null() {
                None
            } else {
                let ptr = ptrs.read();
                if ptr.is_null() {
                    None
                } else {
                    ptrs = ptrs.add(1);
                    Some(ptr)
                }
            }
        })
    }
}

pub trait WriteByte: fmt::Write {
    fn write_u8(&mut self, byte: u8) -> fmt::Result;
}

impl<W: WriteByte> WriteByte for &mut W {
    fn write_u8(&mut self, byte: u8) -> fmt::Result {
        (**self).write_u8(byte)
    }
}

/// An implementation of [`core::fmt::Write`] for a file descriptor.
pub struct FileWriter(pub c_int, Option<Errno>);

impl FileWriter {
    pub fn new(fd: c_int) -> Self {
        Self(fd, None)
    }

    pub fn write(&mut self, buf: &[u8]) -> fmt::Result {
        let _ = Sys::write(self.0, buf).map_err(|err| {
            self.1 = Some(err);
            fmt::Error
        })?;
        Ok(())
    }
}

impl fmt::Write for FileWriter {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        if let Ok(()) = self.write(s.as_bytes()) {}; // TODO handle error
        Ok(())
    }
}

impl WriteByte for FileWriter {
    fn write_u8(&mut self, byte: u8) -> fmt::Result {
        if let Ok(()) = self.write(&[byte]) {}; // TODO handle error
        Ok(())
    }
}

/// An implementation of [`Read`] for a file descriptor.
pub struct FileReader(pub c_int);

impl FileReader {
    // TODO: This is a bad interface. Rustify
    pub fn read(&mut self, buf: &mut [u8]) -> isize {
        Sys::read(self.0, buf)
            .map(|u| u as isize)
            .or_minus_one_errno()
    }
}

impl Read for FileReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let i = Sys::read(self.0, buf)
            .map(|u| u as isize)
            .or_minus_one_errno(); // TODO
        if i >= 0 {
            Ok(i.cast_unsigned())
        } else {
            Err(io::Error::from_raw_os_error(-i as i32))
        }
    }
}

/// An implementation of [`Write`]/[`core::fmt::Write`] for a byte array.
pub struct StringWriter(pub *mut c_char, pub usize);
impl Write for StringWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if self.1 > 1 {
            let copy_size = buf.len().min(self.1 - 1);
            unsafe {
                ptr::copy_nonoverlapping(buf.as_ptr().cast(), self.0, copy_size);
                self.1 -= copy_size;

                self.0 = self.0.add(copy_size);
                *self.0 = 0;
            }
        }

        // Pretend the entire slice was written. This is because many functions
        // (like snprintf) expects a return value that reflects how many bytes
        // *would have* been written. So keeping track of this information is
        // good, and then if we want the *actual* written size we can just go
        // `cmp::min(written, maxlen)`.
        Ok(buf.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
impl fmt::Write for StringWriter {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        // can't fail
        self.write(s.as_bytes()).unwrap();
        Ok(())
    }
}
impl WriteByte for StringWriter {
    fn write_u8(&mut self, byte: u8) -> fmt::Result {
        // can't fail
        self.write(&[byte]).unwrap();
        Ok(())
    }
}

/// An implementation of [`Write`]/[`core::fmt::Write`] for a byte array,
/// without buffer overflow protection.
pub struct UnsafeStringWriter(pub *mut u8);
impl Write for UnsafeStringWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        unsafe {
            ptr::copy_nonoverlapping(buf.as_ptr(), self.0, buf.len());
            self.0 = self.0.add(buf.len());
            *self.0 = b'\0';
        }
        Ok(buf.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
impl fmt::Write for UnsafeStringWriter {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        // can't fail
        self.write(s.as_bytes()).unwrap();
        Ok(())
    }
}
impl WriteByte for UnsafeStringWriter {
    fn write_u8(&mut self, byte: u8) -> fmt::Result {
        // can't fail
        self.write(&[byte]).unwrap();
        Ok(())
    }
}

/// An implementation of [`Read`] for a byte array, without buffer over-read
/// protection.
pub struct UnsafeStringReader(pub *const u8);
impl Read for UnsafeStringReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        unsafe {
            for (i, inner) in buf.iter_mut().enumerate() {
                if *self.0 == 0 {
                    return Ok(i);
                }

                *inner = *self.0;
                self.0 = self.0.add(1);
            }
            Ok(buf.len())
        }
    }
}

/// A wrapper that keeps track of the number of bytes written with the
/// underlying writer `T`.
pub struct CountingWriter<T> {
    pub inner: T,
    pub written: usize,
}
impl<T> CountingWriter<T> {
    pub fn new(writer: T) -> Self {
        Self {
            inner: writer,
            written: 0,
        }
    }
}
impl<T: fmt::Write> fmt::Write for CountingWriter<T> {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        self.written += s.len();
        self.inner.write_str(s)
    }
}
impl<T: WriteByte> WriteByte for CountingWriter<T> {
    fn write_u8(&mut self, byte: u8) -> fmt::Result {
        self.written += 1;
        self.inner.write_u8(byte)
    }
}
impl<T: Write> Write for CountingWriter<T> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let res = self.inner.write(buf);
        if let Ok(written) = res {
            self.written += written;
        }
        res
    }
    fn write_all(&mut self, buf: &[u8]) -> io::Result<()> {
        match self.inner.write_all(buf) {
            Ok(()) => (),
            Err(ref err) if err.kind() == io::ErrorKind::WriteZero => (),
            Err(err) => return Err(err),
        }
        self.written += buf.len();
        Ok(())
    }
    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

// TODO: Set a global variable once get_auxvs is called, and then implement getauxval based on
// get_auxv.

#[cold]
pub unsafe fn auxv_iter<'a>(ptr: *const usize) -> impl Iterator<Item = [usize; 2]> + 'a {
    struct St(*const usize);
    impl Iterator for St {
        type Item = [usize; 2];

        fn next(&mut self) -> Option<Self::Item> {
            unsafe {
                if *self.0 == self::auxv_defs::AT_NULL {
                    return None;
                }
                let kind = *self.0;
                let value = *self.0.add(1);
                self.0 = self.0.add(2);

                Some([kind, value])
            }
        }
    }
    St(ptr)
}

#[cold]
#[cfg(not(target_os = "irix7"))]
pub unsafe fn get_auxvs(ptr: *const usize) -> Box<[[usize; 2]]> {
    //traverse the stack and collect argument environment variables
    let mut auxvs = unsafe { auxv_iter(ptr) }.collect::<Vec<_>>();

    auxvs.sort_unstable_by_key(|[kind, _]| *kind);
    auxvs.into_boxed_slice()
}

/// IRIX 7 supplies the auxiliary vector in `$a3`; parse it with the native
/// numbering in [`auxv_defs`].
#[cfg(target_os = "irix7")]
pub unsafe fn get_auxvs(ptr: *const usize) -> Box<[[usize; 2]]> {
    let mut auxvs = unsafe { auxv_iter(ptr) }.collect::<Vec<_>>();
    auxvs.sort_unstable_by_key(|[kind, _]| *kind);
    auxvs.into_boxed_slice()
}
// TODO: Find an auxv replacement for Redox's execv protocol
#[cold]
pub unsafe fn get_auxv_raw(ptr: *const usize, requested_kind: usize) -> Option<usize> {
    unsafe { auxv_iter(ptr) }.find_map(|[kind, value]| (kind == requested_kind).then_some(value))
}
pub fn get_auxv(auxvs: &[[usize; 2]], key: usize) -> Option<usize> {
    auxvs
        .binary_search_by_key(&key, |[entry_key, _]| *entry_key)
        .ok()
        .map(|idx| auxvs[idx][1])
}

#[cold]
#[cfg(target_os = "redox")]
// SAFETY: Must only be called when only one thread exists.
pub unsafe fn init(auxvs: Box<[[usize; 2]]>) {
    use self::auxv_defs::*;
    use redox_rt::proc::FdGuard;

    let Some(proc_fd) = get_auxv(&auxvs, AT_REDOX_PROC_FD) else {
        panic!("Missing proc and thread fd!");
    };
    let Some(ns_fd) = get_auxv(&auxvs, AT_REDOX_NS_FD) else {
        panic!("Missing namespace fd!");
    };
    unsafe {
        redox_rt::initialize(
            FdGuard::new(proc_fd).to_upper().unwrap(),
            if ns_fd == usize::MAX {
                None
            } else {
                Some(FdGuard::new(ns_fd).to_upper().unwrap())
            },
        );
        init_inner(auxvs)
    }
}
#[cold]
#[cfg(target_os = "redox")]
pub unsafe fn init_inner(auxvs: Box<[[usize; 2]]>) {
    use self::auxv_defs::*;
    use crate::header::sys_stat::S_ISVTX;
    use redox_rt::proc::FdGuard;
    use syscall::MODE_PERM;

    // TODO: Is it safe to assume setup_sighandler has been called at this point?
    redox_rt::sys::this_proc_call(
        syscall::CallFlags::empty(),
        &[redox_protocols::protocol::ProcCall::SyncSigPctl as u64],
    )
    .expect("failed to sync signal pctl");

    if let (Some(cwd_ptr), Some(cwd_len), Some(cwd_fd)) = (
        get_auxv(&auxvs, AT_REDOX_INITIAL_CWD_PTR),
        get_auxv(&auxvs, AT_REDOX_INITIAL_CWD_LEN),
        get_auxv(&auxvs, AT_REDOX_CWD_FD),
    ) {
        let cwd_bytes: &'static [u8] =
            unsafe { core::slice::from_raw_parts(cwd_ptr as *const u8, cwd_len) };
        if let (Ok(Ok(cwd_path)), Some(cwd_fd)) = (
            core::str::from_utf8(cwd_bytes).map(self::sys::path::CwdPath::from),
            (cwd_fd != usize::MAX).then(|| {
                FdGuard::new(cwd_fd)
                    .to_upper()
                    .expect("failed to move cwd fd to upper table")
            }),
        ) {
            self::sys::path::set_cwd_manual(cwd_path, cwd_fd)
                .expect("cwd_path is not valid redox path")
        }
    }

    let mut inherited_sigignmask = 0_u64;
    if let Some(mask) = get_auxv(&auxvs, AT_REDOX_INHERITED_SIGIGNMASK) {
        inherited_sigignmask |= mask as u64;
    }
    #[cfg(target_pointer_width = "32")]
    if let Some(mask) = get_auxv(&auxvs, AT_REDOX_INHERITED_SIGIGNMASK_HI) {
        inherited_sigignmask |= (mask as u64) << 32;
    }
    redox_rt::signal::apply_inherited_sigignmask(inherited_sigignmask);

    let mut inherited_sigprocmask = 0_u64;

    if let Some(mask) = get_auxv(&auxvs, AT_REDOX_INHERITED_SIGPROCMASK) {
        inherited_sigprocmask |= mask as u64;
    }
    #[cfg(target_pointer_width = "32")]
    if let Some(mask) = get_auxv(&auxvs, AT_REDOX_INHERITED_SIGPROCMASK_HI) {
        inherited_sigprocmask |= (mask as u64) << 32;
    }
    redox_rt::signal::set_sigmask(Some(inherited_sigprocmask), None).unwrap();

    if let Some(umask) = get_auxv(&auxvs, AT_REDOX_UMASK) {
        let _ =
            redox_rt::sys::swap_umask((umask as u32) & u32::from(MODE_PERM) & !(S_ISVTX as u32));
    }
}
#[expect(clippy::boxed_local)]
#[cfg(not(target_os = "redox"))]
pub unsafe fn init(_auxvs: Box<[[usize; 2]]>) {}
