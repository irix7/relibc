//! IRIX 7 native syscall backend for relibc.
//!
//! This is the v0 native gate: `syscall 0x1F7`, number in `$2`, arguments in
//! `$4`–`$7`, `CELL_E_*` status in `$2` and the value in `$3` on return.  The
//! kernel never returns a libc `errno`; [`STATUS_ERRNO`] maps the status to the
//! POSIX value this libc reports through `errno`.
//!
//! Real implementations are provided only for the calls the kernel actually
//! services.  Everything else returns `ENOSYS`, which is deliberate: silently
//! pretending to implement `fork`, sockets, signals or timers would misrepresent
//! the platform.
//!
//! Known limits of the v0 ABI:
//!
//! * `poll` ignores its timeout; `nanosleep` is a busy wait.
//! * `getentropy` reports success but the kernel zero-fills the buffer.
//! * There is no process, thread, signal or socket support, hence the ENOSYS
//!   stubs in [`PalSignal`], [`PalSocket`], [`PalEpoll`] and [`PalPtrace`].
//!
//! The file surface is the kernel's console/ramfs table: `lseek`, `pread`,
//! `pwrite`, `dup2`, `pipe2`, `getdents` and `fcntl F_GETFD`/`F_SETFD` map to
//! native calls, and everything else about files (creation, unlinking,
//! permissions) returns `ENOSYS`.

use core::{arch::asm, mem::size_of, num::NonZeroU64, ptr};

use super::{Pal, PalEpoll, PalPtrace, PalSignal, PalSocket, types::*};
use crate::{
    c_str::CStr,
    error::{Errno, Result},
    header::{
        bits_fcntl::SEEK_SET,
        dirent::dirent,
        errno::{EINVAL, EIO, ENOSYS},
        fcntl::AT_FDCWD,
        signal::{sigaction, sigevent, siginfo_t, sigval, stack_t},
        sys_epoll::epoll_event,
        sys_resource::{rlimit, rusage},
        sys_select::timeval,
        sys_socket::{msghdr, socklen_t},
        sys_stat::stat,
        sys_statvfs::statvfs,
        sys_time::timezone,
        sys_uio::iovec,
        sys_utsname::utsname,
        time::{itimerspec, timespec},
    },
    out::Out,
};

// ---------------------------------------------------------------------------
// Provisional syscall ABI
// ---------------------------------------------------------------------------

const SYS_WRITE: usize = 1;
const SYS_EXIT: usize = 2;
const SYS_MMAP: usize = 3;
const SYS_MUNMAP: usize = 4;
const SYS_MPROTECT: usize = 5;
const SYS_OPEN: usize = 6;
const SYS_CLOSE: usize = 7;
const SYS_FCNTL: usize = 8;
const SYS_DUP: usize = 9;
const SYS_GETCWD: usize = 10;
const SYS_POLL: usize = 11;
const SYS_SIGNAL: usize = 12;
const SYS_GETENTROPY: usize = 13;
const SYS_CLOCK_GETTIME: usize = 14;
const SYS_GETPID: usize = 15;
const SYS_READ: usize = 16;
const SYS_FSTAT: usize = 17;
const SYS_STAT: usize = 18;
const SYS_NANOSLEEP: usize = 20;
const SYS_CHDIR: usize = 21;
// 19 (`readdir`) and 22 (`pipe`) remain in the kernel for the static `std`
// shim; this PAL uses `getdents` and `pipe2`.
const SYS_LSEEK: usize = 25;
const SYS_PREAD: usize = 26;
const SYS_PWRITE: usize = 27;
const SYS_DUP2: usize = 28;
const SYS_PIPE2: usize = 29;
const SYS_GETDENTS: usize = 30;

/// The 16-byte `pread`/`pwrite` argument block (`native_abi::io_at`).
///
/// The native gate has four 32-bit argument registers, so a 64-bit `off_t`
/// cannot be passed directly.
#[repr(C)]
struct IoAt {
    buf: u32,
    len: u32,
    offset: off_t,
}

/// Map a `CELL_E_*` status to the POSIX `errno` value.
///
/// This mirrors `crates/native-abi/src/status.rs::status_to_errno` in the
/// kernel repository; the two tables are the shared error contract.
const STATUS_ERRNO: [c_int; 53] = [
    0,   // CELL_OK
    1,   // EPERM
    2,   // ENOENT
    4,   // EINTR
    5,   // EIO
    9,   // EBADF
    11,  // EAGAIN
    12,  // ENOMEM
    13,  // EACCES
    14,  // EFAULT
    16,  // EBUSY
    17,  // EEXIST
    22,  // EINVAL
    28,  // ENOSPC
    20,  // ENOTDIR
    21,  // EISDIR
    39,  // ENOTEMPTY
    95,  // ENOTSUP
    75,  // EOVERFLOW
    110, // ETIMEDOUT
    125, // ECANCELED
    9,   // E_REVOKED -> EBADF
    90,  // EMSGSIZE
    71,  // EPROTO
    111, // ECONNREFUSED
    107, // ENOTCONN
    98,  // EADDRINUSE
    101, // ENETUNREACH
    113, // EHOSTUNREACH
    36,  // ENAMETOOLONG
    40,  // ELOOP
    10,  // ECHILD
    3,   // ESRCH
    38,  // ENOSYS
    32,  // EPIPE
    34,  // ERANGE
    33,  // EDOM
    35,  // EDEADLK
    37,  // ENOLCK
    42,  // ENOMSG
    43,  // EIDRM
    25,  // ENOTTY
    29,  // ESPIPE
    26,  // ETXTBSY
    27,  // EFBIG
    31,  // EMLINK
    30,  // EROFS
    19,  // ENODEV
    6,   // ENXIO
    15,  // ENOTBLK
    7,   // E2BIG
    24,  // EMFILE
    23,  // ENFILE
];

/// Invoke the native gate.
///
/// The kernel writes the status to `$2` and the value to `$3`; every path that
/// does not exit returns through here so the status-to-errno mapping exists in
/// exactly one place.
#[inline(always)]
unsafe fn syscall(n: usize, a0: usize, a1: usize, a2: usize, a3: usize) -> Result<usize> {
    let status: usize;
    let value: usize;
    unsafe {
        asm!(
            "syscall 0x1F7",
            inout("$2") n => status,
            lateout("$3") value,
            in("$4") a0,
            in("$5") a1,
            in("$6") a2,
            in("$7") a3,
            options(nostack),
        );
    }
    if status == 0 {
        Ok(value)
    } else {
        let errno = STATUS_ERRNO.get(status).copied().unwrap_or(EIO);
        Err(Errno(errno))
    }
}

fn enosys<T>() -> Result<T> {
    Err(Errno(ENOSYS))
}

/// Fill a fixed-size C string array, truncating at the array length.
fn fill_name(field: &mut [c_char], name: &[u8]) {
    let len = name.len().min(field.len().saturating_sub(1));
    for (slot, byte) in field.iter_mut().zip(&name[..len]) {
        *slot = *byte as c_char;
    }
    field[len] = 0;
}

/// IRIX 7 native syscall implementation of [`Pal`].
pub struct Sys;

impl Sys {
    /// passthrough to the kernel's provisional poll(2).
    ///
    /// The kernel ignores the timeout and reports every non-closed descriptor
    /// as ready (console/null semantics), so this is only useful as a
    /// readiness check on the bring-up fd namespace.
    pub unsafe fn poll(fds: &mut [crate::header::poll::pollfd], _timeout: c_int) -> Result<c_int> {
        if fds.is_empty() {
            // No descriptors: the kernel would reject the dangling empty-slice
            // pointer in its range check.
            return Ok(0);
        }
        let ready = unsafe { syscall(SYS_POLL, fds.as_mut_ptr() as usize, fds.len(), 0, 0) }?;
        Ok(ready as c_int)
    }
}

impl Pal for Sys {
    fn faccessat(_fd: c_int, _path: CStr, _amode: c_int, _flags: c_int) -> Result<()> {
        // No access(2) in the provisional ABI. `stat` could answer F_OK, but
        // R_OK/W_OK/X_OK have no meaning in the bring-up namespace.
        enosys()
    }

    unsafe fn brk(_addr: *mut c_void) -> Result<*mut c_void> {
        // Allocation goes through mmap; the kernel has no program break.
        enosys()
    }

    fn chdir(path: CStr) -> Result<()> {
        unsafe { syscall(SYS_CHDIR, path.as_ptr() as usize, 0, 0, 0) }.map(|_| ())
    }

    fn clock_getres(_clk_id: clockid_t, _tp: Option<Out<timespec>>) -> Result<()> {
        enosys()
    }

    fn clock_gettime(clk_id: clockid_t, mut tp: Out<timespec>) -> Result<()> {
        // The kernel writes relibc's n32 `timespec` directly (16 bytes,
        // 64-bit seconds, 32-bit nanoseconds plus tail padding).
        unsafe {
            syscall(
                SYS_CLOCK_GETTIME,
                clk_id as usize,
                tp.as_mut_ptr() as usize,
                0,
                0,
            )
        }
        .map(|_| ())
    }

    unsafe fn clock_settime(_clk_id: clockid_t, _tp: *const timespec) -> Result<()> {
        enosys()
    }

    fn close(fildes: c_int) -> Result<()> {
        unsafe { syscall(SYS_CLOSE, fildes as usize, 0, 0, 0) }.map(|_| ())
    }

    fn dup(fildes: c_int) -> Result<c_int> {
        let fd = unsafe { syscall(SYS_DUP, fildes as usize, 0, 0, 0) }?;
        Ok(fd as c_int)
    }

    fn dup2(fildes: c_int, fildes2: c_int) -> Result<c_int> {
        let fd = unsafe { syscall(SYS_DUP2, fildes as usize, fildes2 as usize, 0, 0) }?;
        Ok(fd as c_int)
    }

    unsafe fn execve(
        _path: CStr,
        _argv: *const *mut c_char,
        _envp: *const *mut c_char,
    ) -> Result<()> {
        enosys()
    }

    unsafe fn fexecve(
        _fildes: c_int,
        _argv: *const *mut c_char,
        _envp: *const *mut c_char,
    ) -> Result<()> {
        enosys()
    }

    fn exit(status: c_int) -> ! {
        unsafe {
            let _ = syscall(SYS_EXIT, status as usize, 0, 0, 0);
        }
        unreachable!("the kernel always exits on SYS_EXIT")
    }

    unsafe fn exit_thread(_stack_base: *mut (), _stack_size: usize) -> ! {
        // There are no threads; leaving the process is the only correct action.
        Self::exit(0)
    }

    fn fchdir(_fildes: c_int) -> Result<()> {
        enosys()
    }

    fn fchmodat(_dirfd: c_int, _path: Option<CStr>, _mode: mode_t, _flags: c_int) -> Result<()> {
        enosys()
    }

    fn fchownat(
        _fildes: c_int,
        _path: CStr,
        _owner: uid_t,
        _group: gid_t,
        _flags: c_int,
    ) -> Result<()> {
        enosys()
    }

    fn fdatasync(_fildes: c_int) -> Result<()> {
        enosys()
    }

    fn flock(_fd: c_int, _operation: c_int) -> Result<()> {
        enosys()
    }

    fn fstat(fildes: c_int, mut buf: Out<stat>) -> Result<()> {
        // The kernel writes relibc's 136-byte n32 `struct stat` directly.
        unsafe { syscall(SYS_FSTAT, fildes as usize, buf.as_mut_ptr() as usize, 0, 0) }.map(|_| ())
    }

    fn fstatat(fildes: c_int, path: Option<CStr>, mut buf: Out<stat>, _flags: c_int) -> Result<()> {
        if let Some(path) = path {
            if !path.to_bytes().is_empty() {
                // The ABI has stat(path), not fstatat(dirfd, path).  Relative
                // paths resolve against the kernel cwd, so a non-AT_FDCWD
                // dirfd cannot be honoured.
                if fildes != AT_FDCWD {
                    return enosys();
                }
                unsafe {
                    syscall(
                        SYS_STAT,
                        path.as_ptr() as usize,
                        buf.as_mut_ptr() as usize,
                        0,
                        0,
                    )
                }?;
                return Ok(());
            }
        }
        Self::fstat(fildes, buf)
    }

    fn fstatvfs(_fildes: c_int, _buf: Out<statvfs>) -> Result<()> {
        enosys()
    }

    fn fcntl(fildes: c_int, cmd: c_int, arg: c_ulonglong) -> Result<c_int> {
        // The kernel treats fcntl as an unconditional success with no side
        // effects.  Passing it through keeps F_GETFD/F_SETFD working for stdio,
        // but no command is actually interpreted.
        let value = unsafe { syscall(SYS_FCNTL, fildes as usize, cmd as usize, arg as usize, 0) }?;
        Ok(value as c_int)
    }

    unsafe fn fork() -> Result<pid_t> {
        enosys()
    }

    fn fpath(_fildes: c_int, _out: &mut [u8]) -> Result<usize> {
        enosys()
    }

    fn fsync(_fildes: c_int) -> Result<()> {
        enosys()
    }

    fn ftruncate(_fildes: c_int, _length: off_t) -> Result<()> {
        enosys()
    }

    unsafe fn futex_wait(_addr: *mut u32, _val: u32, _deadline: Option<&timespec>) -> Result<()> {
        // One thread: no one can change the word while we look at it, so there
        // is nothing to wait for.  Reporting success keeps the generic mutex
        // path from treating an absent futex as a fatal error.
        Ok(())
    }

    unsafe fn futex_wake(_addr: *mut u32, _num: u32) -> Result<u32> {
        // As above: there are no waiters to wake.
        Ok(0)
    }

    unsafe fn utimensat(
        _dirfd: c_int,
        _path: CStr,
        _times: *const timespec,
        _flag: c_int,
    ) -> Result<()> {
        enosys()
    }

    fn getcwd(mut buf: Out<[u8]>) -> Result<()> {
        unsafe {
            syscall(
                SYS_GETCWD,
                buf.as_mut_ptr().as_mut_ptr() as usize,
                buf.len(),
                0,
                0,
            )
        }
        .map(|_| ())
    }

    fn getdents(fd: c_int, buf: &mut [u8], _opaque_offset: u64) -> Result<usize> {
        // The kernel owns the directory cookie.  `dir_seek` writes it back
        // with lseek, each record's d_off is the position that follows it, and
        // the kernel advances the descriptor as it fills the buffer.
        if buf.is_empty() {
            return Err(Errno(EINVAL));
        }
        unsafe {
            syscall(
                SYS_GETDENTS,
                fd as usize,
                buf.as_mut_ptr() as usize,
                buf.len(),
                0,
            )
        }
    }

    fn dir_seek(fd: c_int, opaque_offset: u64) -> Result<()> {
        if opaque_offset > i64::MAX as u64 {
            return Err(Errno(EINVAL));
        }
        Self::lseek(fd, opaque_offset as off_t, SEEK_SET).map(|_| ())
    }

    unsafe fn dent_reclen_offset(this_dent: &[u8], _offset: usize) -> Option<(u16, u64)> {
        if this_dent.len() < size_of::<dirent>() {
            return None;
        }
        // `getdents` writes a byte copy, so read unaligned.
        let dent = this_dent.as_ptr().cast::<dirent>();
        Some((
            unsafe { ptr::read_unaligned(ptr::addr_of!((*dent).d_reclen)) },
            unsafe { ptr::read_unaligned(ptr::addr_of!((*dent).d_off)) } as u64,
        ))
    }

    fn getegid() -> gid_t {
        0
    }

    fn geteuid() -> uid_t {
        0
    }

    fn getgid() -> gid_t {
        0
    }

    fn getgroups(_list: Out<[gid_t]>) -> Result<c_int> {
        // One user, no supplementary groups.
        Ok(0)
    }

    fn getpagesize() -> usize {
        4096
    }

    fn getpgid(_pid: pid_t) -> Result<pid_t> {
        enosys()
    }

    fn getpid() -> pid_t {
        unsafe { syscall(SYS_GETPID, 0, 0, 0, 0) }
            .map(|pid| pid as pid_t)
            .unwrap_or(0)
    }

    fn getppid() -> pid_t {
        // No process table; the loader runs one image.  Report "no parent".
        0
    }

    fn getpriority(_which: c_int, _who: id_t) -> Result<c_int> {
        enosys()
    }

    fn getrandom(buf: &mut [u8], _flags: c_uint) -> Result<usize> {
        // WARNING: the kernel's getentropy zero-fills the buffer.  This is a
        // bring-up stub, not a source of entropy.
        if buf.is_empty() {
            // Avoid asking the kernel to range-check a dangling empty slice.
            return Ok(0);
        }
        unsafe { syscall(SYS_GETENTROPY, buf.as_mut_ptr() as usize, buf.len(), 0, 0) }
    }

    fn getresgid(
        rgid: Option<Out<gid_t>>,
        egid: Option<Out<gid_t>>,
        sgid: Option<Out<gid_t>>,
    ) -> Result<()> {
        for mut out in [rgid, egid, sgid].into_iter().flatten() {
            out.write(0);
        }
        Ok(())
    }

    fn getresuid(
        ruid: Option<Out<uid_t>>,
        euid: Option<Out<uid_t>>,
        suid: Option<Out<uid_t>>,
    ) -> Result<()> {
        for mut out in [ruid, euid, suid].into_iter().flatten() {
            out.write(0);
        }
        Ok(())
    }

    fn getrlimit(_resource: c_int, _rlim: Out<rlimit>) -> Result<()> {
        enosys()
    }

    unsafe fn setrlimit(_resource: c_int, _rlim: *const rlimit) -> Result<()> {
        enosys()
    }

    fn getrusage(_who: c_int, _r_usage: Out<rusage>) -> Result<()> {
        enosys()
    }

    fn getsid(_pid: pid_t) -> Result<pid_t> {
        enosys()
    }

    fn gettid() -> pid_t {
        // Single-threaded: the thread id is the process id.
        Self::getpid()
    }

    fn gettimeofday(mut tp: Out<timeval>, tzp: Option<Out<timezone>>) -> Result<()> {
        let mut ts = timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        Self::clock_gettime(0 /* CLOCK_REALTIME */, Out::from_mut(&mut ts))?;
        tp.write(timeval {
            tv_sec: ts.tv_sec,
            tv_usec: (ts.tv_nsec / 1000) as suseconds_t,
        });
        if let Some(mut tz) = tzp {
            // The kernel has no timezone state.
            tz.write(timezone {
                tz_minuteswest: 0,
                tz_dsttime: 0,
            });
        }
        Ok(())
    }

    fn getuid() -> uid_t {
        0
    }

    fn linkat(
        _fd1: c_int,
        _oldpath: CStr,
        _fd2: c_int,
        _newpath: CStr,
        _flags: c_int,
    ) -> Result<()> {
        enosys()
    }

    fn lseek(fildes: c_int, offset: off_t, whence: c_int) -> Result<off_t> {
        // The 64-bit offset is split across `$a1` and `$a2` because the flat
        // gate has four 32-bit argument registers.
        let bits = offset as u64;
        let low = bits as u32;
        let high = (bits >> 32) as u32;
        let value = unsafe {
            syscall(
                SYS_LSEEK,
                fildes as usize,
                low as usize,
                high as usize,
                whence as usize,
            )
        }?;
        Ok(value as off_t)
    }

    fn mkdirat(_fildes: c_int, _path: CStr, _mode: mode_t) -> Result<()> {
        enosys()
    }

    fn mkfifoat(_dir_fd: c_int, _path: CStr, _mode: mode_t) -> Result<()> {
        enosys()
    }

    fn mknodat(_fildes: c_int, _path: CStr, _mode: mode_t, _dev: dev_t) -> Result<()> {
        enosys()
    }

    unsafe fn mlock(_addr: *const c_void, _len: usize) -> Result<()> {
        // No paging: everything is resident.  This is a true no-op, not a stub.
        Ok(())
    }

    unsafe fn mlockall(_flags: c_int) -> Result<()> {
        Ok(())
    }

    unsafe fn mmap(
        addr: *mut c_void,
        len: usize,
        prot: c_int,
        flags: c_int,
        _fildes: c_int,
        _off: off_t,
    ) -> Result<*mut c_void> {
        // Provisional mmap(addr, length, prot, flags): the kernel ignores the
        // address, protection and flags and bumps a fixed 1 MiB heap.
        let address =
            unsafe { syscall(SYS_MMAP, addr as usize, len, prot as usize, flags as usize) }?;
        Ok(address as *mut c_void)
    }

    unsafe fn mremap(
        _addr: *mut c_void,
        _len: usize,
        _new_len: usize,
        _flags: c_int,
        _args: *mut c_void,
    ) -> Result<*mut c_void> {
        enosys()
    }

    unsafe fn mprotect(addr: *mut c_void, len: usize, prot: c_int) -> Result<()> {
        unsafe { syscall(SYS_MPROTECT, addr as usize, len, prot as usize, 0) }.map(|_| ())
    }

    unsafe fn msync(_addr: *mut c_void, _len: usize, _flags: c_int) -> Result<()> {
        // No page cache to write back.
        Ok(())
    }

    unsafe fn munlock(_addr: *const c_void, _len: usize) -> Result<()> {
        Ok(())
    }

    unsafe fn madvise(_addr: *mut c_void, _len: usize, _flags: c_int) -> Result<()> {
        enosys()
    }

    unsafe fn munlockall() -> Result<()> {
        Ok(())
    }

    unsafe fn munmap(addr: *mut c_void, len: usize) -> Result<()> {
        // The v0 heap is one-way; the kernel returns success and releases the
        // mappings at process exit.
        unsafe { syscall(SYS_MUNMAP, addr as usize, len, 0, 0) }.map(|_| ())
    }

    unsafe fn nanosleep(rqtp: *const timespec, _rmtp: *mut timespec) -> Result<()> {
        // The kernel busy-waits and does not report the remaining time.
        unsafe { syscall(SYS_NANOSLEEP, rqtp as usize, 0, 0, 0) }.map(|_| ())
    }

    fn openat(dirfd: c_int, path: CStr, oflag: c_int, _mode: mode_t) -> Result<c_int> {
        if dirfd != AT_FDCWD {
            // Relative paths always resolve against the kernel cwd.
            return enosys();
        }
        let fd = unsafe { syscall(SYS_OPEN, path.as_ptr() as usize, oflag as usize, 0, 0) }?;
        Ok(fd as c_int)
    }

    fn pipe2(mut fildes: Out<[c_int; 2]>, flags: c_int) -> Result<()> {
        unsafe {
            syscall(
                SYS_PIPE2,
                fildes.as_mut_ptr().cast::<c_int>() as usize,
                flags as usize,
                0,
                0,
            )
        }
        .map(|_| ())
    }

    fn posix_fallocate(_fd: c_int, _offset: u64, _length: NonZeroU64) -> Result<()> {
        enosys()
    }

    fn posix_getdents(fildes: c_int, buf: &mut [u8]) -> Result<usize> {
        // POSIX-2024: read from the descriptor's current position, which the
        // kernel directory reads and advances.  A buffer too small for one
        // record is EINVAL, as the standard requires.
        if buf.is_empty() {
            return Err(Errno(EINVAL));
        }
        unsafe {
            syscall(
                SYS_GETDENTS,
                fildes as usize,
                buf.as_mut_ptr() as usize,
                buf.len(),
                0,
            )
        }
    }

    unsafe fn rlct_clone(
        _stack: *mut usize,
        _os_specific: &mut crate::ld_so::tcb::OsSpecific,
    ) -> Result<crate::pthread::OsTid, Errno> {
        enosys()
    }

    unsafe fn rlct_kill(_os_tid: crate::pthread::OsTid, _signal: usize) -> Result<()> {
        enosys()
    }

    fn current_os_tid() -> crate::pthread::OsTid {
        crate::pthread::OsTid {
            thread_id: self::Sys::getpid() as usize,
        }
    }

    fn read(fildes: c_int, buf: &mut [u8]) -> Result<usize> {
        if buf.is_empty() {
            // POSIX: a zero-length read succeeds.  The kernel's range check
            // rejects the dangling pointer of an empty Rust slice.
            return Ok(0);
        }
        let count = unsafe {
            syscall(
                SYS_READ,
                fildes as usize,
                buf.as_mut_ptr() as usize,
                buf.len(),
                0,
            )
        }?;
        Ok(count)
    }

    fn pread(fildes: c_int, buf: &mut [u8], offset: off_t) -> Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        let block = IoAt {
            buf: buf.as_mut_ptr() as usize as u32,
            len: buf.len() as u32,
            offset,
        };
        let count = unsafe {
            syscall(
                SYS_PREAD,
                fildes as usize,
                &block as *const IoAt as usize,
                0,
                0,
            )
        }?;
        Ok(count)
    }

    unsafe fn readv(fildes: c_int, iov: *const iovec, iovcnt: c_int) -> Result<usize> {
        // No readv syscall; loop over the vectors like the bring-up libc.
        let mut total = 0usize;
        for index in 0..iovcnt.max(0) as usize {
            let vector = unsafe { &*iov.add(index) };
            if vector.iov_len == 0 {
                continue;
            }
            let buf = unsafe {
                core::slice::from_raw_parts_mut(vector.iov_base.cast::<u8>(), vector.iov_len)
            };
            let count = Self::read(fildes, buf)?;
            total += count;
            if count < vector.iov_len {
                break;
            }
        }
        Ok(total)
    }

    fn readlinkat(_dirfd: c_int, _pathname: CStr, _out: &mut [u8]) -> Result<usize> {
        enosys()
    }

    fn renameat2(
        _old_dir: c_int,
        _old_path: CStr,
        _new_dir: c_int,
        _new_path: CStr,
        _flags: c_uint,
    ) -> Result<()> {
        enosys()
    }

    fn sched_yield() -> Result<()> {
        // Single-threaded; there is nothing to yield to.
        Ok(())
    }

    unsafe fn setgroups(_size: size_t, _list: *const gid_t) -> Result<()> {
        enosys()
    }

    fn setpgid(_pid: pid_t, _pgid: pid_t) -> Result<()> {
        enosys()
    }

    fn setpriority(_which: c_int, _who: id_t, _prio: c_int) -> Result<()> {
        enosys()
    }

    fn setresgid(_rgid: gid_t, _egid: gid_t, _sgid: gid_t) -> Result<()> {
        enosys()
    }

    fn setresuid(_ruid: uid_t, _euid: uid_t, _suid: uid_t) -> Result<()> {
        enosys()
    }

    fn setsid() -> Result<c_int> {
        enosys()
    }

    unsafe fn spawn(
        _program: CStr,
        _fac: Option<&crate::header::spawn::posix_spawn_file_actions_t>,
        _fat: Option<&crate::header::spawn::posix_spawnattr_t>,
        _argv: crate::iter::NulTerminated<*mut c_char>,
        _envp: Option<crate::iter::NulTerminated<*mut c_char>>,
    ) -> Result<pid_t> {
        enosys()
    }

    fn symlinkat(_path1: CStr, _fd: c_int, _path2: CStr) -> Result<()> {
        enosys()
    }

    fn sync() -> Result<()> {
        enosys()
    }

    fn timer_create(_clock_id: clockid_t, _evp: &sigevent) -> Result<timer_t> {
        enosys()
    }

    fn timer_delete(_timerid: timer_t) -> Result<()> {
        enosys()
    }

    fn timer_gettime(_timerid: timer_t) -> Result<itimerspec> {
        enosys()
    }

    fn timer_settime(
        _timerid: timer_t,
        _flags: c_int,
        _value: &itimerspec,
        _ovalue: Option<Out<itimerspec>>,
    ) -> Result<()> {
        enosys()
    }

    fn umask(_mask: mode_t) -> mode_t {
        // No file creation, so no umask state to keep.  Report the conventional
        // default rather than inventing persistence the kernel does not have.
        0o022
    }

    fn uname(mut utsname: Out<utsname>) -> Result<()> {
        // There is no uname syscall; these values describe the ABI the binary
        // was built for, not the running kernel.
        let mut name = utsname {
            sysname: [0; crate::header::sys_utsname::UTSLENGTH],
            nodename: [0; crate::header::sys_utsname::UTSLENGTH],
            release: [0; crate::header::sys_utsname::UTSLENGTH],
            version: [0; crate::header::sys_utsname::UTSLENGTH],
            machine: [0; crate::header::sys_utsname::UTSLENGTH],
            domainname: [0; crate::header::sys_utsname::UTSLENGTH],
        };
        fill_name(&mut name.sysname, b"IRIX 7");
        fill_name(&mut name.nodename, b"indy");
        fill_name(&mut name.release, b"7");
        fill_name(&mut name.version, b"provisional n32 PAL");
        fill_name(&mut name.machine, b"mips");
        fill_name(&mut name.domainname, b"");
        utsname.write(name);
        Ok(())
    }

    fn unlinkat(_fd: c_int, _path: CStr, _flags: c_int) -> Result<()> {
        enosys()
    }

    fn waitpid(_pid: pid_t, _stat_loc: Option<Out<c_int>>, _options: c_int) -> Result<pid_t> {
        enosys()
    }

    fn write(fildes: c_int, buf: &[u8]) -> Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        let count = unsafe {
            syscall(
                SYS_WRITE,
                fildes as usize,
                buf.as_ptr() as usize,
                buf.len(),
                0,
            )
        }?;
        Ok(count)
    }

    fn pwrite(fildes: c_int, buf: &[u8], offset: off_t) -> Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        let block = IoAt {
            buf: buf.as_ptr() as usize as u32,
            len: buf.len() as u32,
            offset,
        };
        let count = unsafe {
            syscall(
                SYS_PWRITE,
                fildes as usize,
                &block as *const IoAt as usize,
                0,
                0,
            )
        }?;
        Ok(count)
    }

    unsafe fn writev(fildes: c_int, iov: *const iovec, iovcnt: c_int) -> Result<usize> {
        let mut total = 0usize;
        for index in 0..iovcnt.max(0) as usize {
            let vector = unsafe { &*iov.add(index) };
            if vector.iov_len == 0 {
                continue;
            }
            let buf = unsafe {
                core::slice::from_raw_parts(vector.iov_base.cast::<u8>(), vector.iov_len)
            };
            let count = Self::write(fildes, buf)?;
            total += count;
            if count < vector.iov_len {
                break;
            }
        }
        Ok(total)
    }

    fn verify() -> bool {
        // The only platform check available: the ABI's getpid must answer.
        unsafe { syscall(SYS_GETPID, 0, 0, 0, 0) }
            .map(|pid| pid != 0)
            .unwrap_or(false)
    }
}

// ---------------------------------------------------------------------------
// Sub-traits: all unsupported by the provisional kernel.
// ---------------------------------------------------------------------------

impl PalEpoll for Sys {
    fn epoll_create1(_flags: c_int) -> Result<c_int> {
        enosys()
    }

    unsafe fn epoll_ctl(
        _epfd: c_int,
        _op: c_int,
        _fd: c_int,
        _event: *mut epoll_event,
    ) -> Result<()> {
        enosys()
    }

    unsafe fn epoll_pwait(
        _epfd: c_int,
        _events: *mut epoll_event,
        _maxevents: c_int,
        _timeout: c_int,
        _sigmask: *const crate::header::bits_sigset_t::sigset_t,
    ) -> Result<usize> {
        enosys()
    }
}

impl PalPtrace for Sys {
    unsafe fn ptrace(
        _request: c_int,
        _pid: pid_t,
        _addr: *mut c_void,
        _data: *mut c_void,
    ) -> Result<c_int> {
        enosys()
    }
}

impl PalSignal for Sys {
    #[expect(deprecated)]
    fn getitimer(_which: c_int, _out: &mut crate::header::sys_time::itimerval) -> Result<()> {
        enosys()
    }

    fn kill(_pid: pid_t, _sig: c_int) -> Result<()> {
        enosys()
    }

    fn sigqueue(_pid: pid_t, _sig: c_int, _val: sigval) -> Result<()> {
        enosys()
    }

    fn killpg(_pgrp: pid_t, _sig: c_int) -> Result<()> {
        enosys()
    }

    fn raise(_sig: c_int) -> Result<()> {
        enosys()
    }

    #[expect(deprecated)]
    fn setitimer(
        _which: c_int,
        _new: &crate::header::sys_time::itimerval,
        _old: Option<&mut crate::header::sys_time::itimerval>,
    ) -> Result<()> {
        enosys()
    }

    fn sigaction(
        _sig: c_int,
        _act: Option<&sigaction>,
        _oact: Option<&mut sigaction>,
    ) -> Result<()> {
        enosys()
    }

    unsafe fn sigaltstack(_ss: Option<&stack_t>, _old_ss: Option<&mut stack_t>) -> Result<()> {
        enosys()
    }

    fn sigpending(_set: &mut crate::header::bits_sigset_t::sigset_t) -> Result<()> {
        enosys()
    }

    fn sigprocmask(
        _how: c_int,
        _set: Option<&crate::header::bits_sigset_t::sigset_t>,
        _oset: Option<&mut crate::header::bits_sigset_t::sigset_t>,
    ) -> Result<()> {
        enosys()
    }

    fn sigsuspend(_mask: &crate::header::bits_sigset_t::sigset_t) -> Errno {
        Errno(ENOSYS)
    }

    fn sigtimedwait(
        _set: &crate::header::bits_sigset_t::sigset_t,
        _sig: Option<&mut siginfo_t>,
        _tp: Option<&timespec>,
    ) -> Result<c_int> {
        enosys()
    }
}

impl PalSocket for Sys {
    fn accept(_socket: c_int, _address_dst: Option<&mut [u8]>) -> Result<(c_int, socklen_t)> {
        enosys()
    }

    fn bind(_socket: c_int, _address_raw: &[u8]) -> Result<()> {
        enosys()
    }

    fn connect(_socket: c_int, _address_raw: &[u8]) -> Result<c_int> {
        enosys()
    }

    fn getpeername(_socket: c_int, _address_dst: &mut [u8]) -> Result<socklen_t> {
        enosys()
    }

    fn getsockname(_socket: c_int, _address_dst: &mut [u8]) -> Result<socklen_t> {
        enosys()
    }

    fn getsockopt(
        _socket: c_int,
        _level: c_int,
        _option_name: c_int,
        _option_value: &mut [u8],
    ) -> Result<socklen_t> {
        enosys()
    }

    fn listen(_socket: c_int, _backlog: c_int) -> Result<()> {
        enosys()
    }

    fn recvfrom(
        _socket: c_int,
        _buf: Out<[u8]>,
        _flags: c_int,
        _address_raw: Option<&mut [u8]>,
    ) -> Result<(usize, socklen_t)> {
        enosys()
    }

    unsafe fn recvmsg(_socket: c_int, _msg: *mut msghdr, _flags: c_int) -> Result<usize> {
        enosys()
    }

    unsafe fn sendmsg(_socket: c_int, _msg: *const msghdr, _flags: c_int) -> Result<usize> {
        enosys()
    }

    fn sendto(
        _socket: c_int,
        _buf: &[u8],
        _flags: c_int,
        _dest_addr: Option<&[u8]>,
    ) -> Result<usize> {
        enosys()
    }

    fn setsockopt(
        _socket: c_int,
        _level: c_int,
        _option_name: c_int,
        _option_value: &[u8],
    ) -> Result<()> {
        enosys()
    }

    fn shutdown(_socket: c_int, _how: c_int) -> Result<()> {
        enosys()
    }

    fn socket(_domain: c_int, _kind: c_int, _protocol: c_int) -> Result<c_int> {
        enosys()
    }

    fn socketpair(
        _domain: c_int,
        _kind: c_int,
        _protocol: c_int,
        _sv: &mut [c_int; 2],
    ) -> Result<()> {
        enosys()
    }
}

// The shim reinterprets no structure in place, but both ends of every
// conversion are pinned here so an ABI change fails the build rather than the
// first stat() at runtime.
const _: () = {
    use crate::header::{dirent::dirent, poll::pollfd, time::timespec};
    use core::mem::offset_of;

    assert!(size_of::<stat>() == 136);
    assert!(offset_of!(stat, st_nlink) == 16);
    assert!(offset_of!(stat, st_mode) == 20);
    assert!(offset_of!(stat, st_size) == 40);
    assert!(offset_of!(stat, st_blksize) == 48);
    assert!(offset_of!(stat, st_blocks) == 56);
    assert!(offset_of!(stat, st_atim) == 64);
    assert!(offset_of!(stat, st_mtim) == 80);
    assert!(offset_of!(stat, st_ctim) == 96);
    assert!(offset_of!(stat, _pad) == 112);

    assert!(size_of::<timespec>() == 16);
    assert!(offset_of!(timespec, tv_sec) == 0);
    assert!(offset_of!(timespec, tv_nsec) == 8);

    assert!(size_of::<dirent>() == 280);
    assert!(offset_of!(dirent, d_ino) == 0);
    assert!(offset_of!(dirent, d_off) == 8);
    assert!(offset_of!(dirent, d_reclen) == 16);
    assert!(offset_of!(dirent, d_type) == 18);
    assert!(offset_of!(dirent, d_name) == 19);

    assert!(size_of::<IoAt>() == 16);
    assert!(offset_of!(IoAt, buf) == 0);
    assert!(offset_of!(IoAt, len) == 4);
    assert!(offset_of!(IoAt, offset) == 8);

    assert!(size_of::<pollfd>() == 8);
    assert!(offset_of!(pollfd, revents) == 6);
};
