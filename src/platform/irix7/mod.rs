//! IRIX 7 native syscall backend for relibc.
//!
//! This is a **scaffold over the provisional IRIX 7 kernel syscall ABI**, not the
//! final capability-based PAL.  The kernel currently exposes 21 flat, numbered
//! syscalls to a statically loaded n32 user image:
//!
//! ```text
//!   $2 = number, $4..$7 = arguments, $2 = result
//!   0xffff_ffff means "failed"; there is no error-code channel
//! ```
//!
//! Real implementations are provided only for the calls the kernel actually
//! services (the hello/fs probe set).  Everything else returns `ENOSYS`, which
//! is deliberate: silently pretending to implement `fork`, sockets, signals or
//! timers would misrepresent the platform.
//!
//! Known mismatches that the shim papers over and the report records:
//!
//! * The kernel's `struct stat` is a private 128-byte layout, not relibc's n32
//!   `struct stat`; [`copy_stat`] translates field by field.
//! * The kernel's `readdir` is `(fd, index, buf, len)` returning a type byte,
//!   not `getdents`.  [`Sys::getdents`] synthesises relibc `dirent` records and
//!   uses the opaque offset as the kernel directory index.
//! * The kernel returns `-1` for every failure, so errno values below are
//!   best-effort guesses (`EBADF`, `ENOENT`, `EIO`), not kernel-provided codes.
//! * `getentropy` succeeds but the kernel fills the buffer with zeroes.
//! * `poll` ignores its timeout; `nanosleep` is a busy wait.
//! * There is no process, thread, signal or socket support, hence the ENOSYS
//!   stubs in [`PalSignal`], [`PalSocket`], [`PalEpoll`] and [`PalPtrace`].

use core::{
    arch::asm,
    mem::size_of,
    num::NonZeroU64,
    ptr,
};

use super::{Pal, PalEpoll, PalPtrace, PalSignal, PalSocket, types::*};
use crate::{
    c_str::CStr,
    error::{Errno, Result},
    header::{
        dirent::dirent,
        errno::{EBADF, EINVAL, EIO, ENOENT, ENOMEM, ENOSYS, ERANGE},
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
const SYS_READDIR: usize = 19;
const SYS_NANOSLEEP: usize = 20;
const SYS_CHDIR: usize = 21;

/// The kernel returns all ones from `$2` when a syscall fails.
const SYS_ERROR: usize = usize::MAX;

// MIPS `syscall`: number in `$2`, arguments in `$4`..`$7`, result in `$2`.
#[inline(always)]
unsafe fn syscall0(n: usize) -> usize {
    let result: usize;
    unsafe {
        asm!(
            "syscall",
            inout("$2") n => result,
            out("$4") _,
            out("$5") _,
            out("$6") _,
            out("$7") _,
            options(nostack),
        );
    }
    result
}

#[inline(always)]
unsafe fn syscall1(n: usize, a0: usize) -> usize {
    let result: usize;
    unsafe {
        asm!(
            "syscall",
            inout("$2") n => result,
            inout("$4") a0 => _,
            out("$5") _,
            out("$6") _,
            out("$7") _,
            options(nostack),
        );
    }
    result
}

#[inline(always)]
unsafe fn syscall2(n: usize, a0: usize, a1: usize) -> usize {
    let result: usize;
    unsafe {
        asm!(
            "syscall",
            inout("$2") n => result,
            inout("$4") a0 => _,
            inout("$5") a1 => _,
            out("$6") _,
            out("$7") _,
            options(nostack),
        );
    }
    result
}

#[inline(always)]
unsafe fn syscall3(n: usize, a0: usize, a1: usize, a2: usize) -> usize {
    let result: usize;
    unsafe {
        asm!(
            "syscall",
            inout("$2") n => result,
            inout("$4") a0 => _,
            inout("$5") a1 => _,
            inout("$6") a2 => _,
            out("$7") _,
            options(nostack),
        );
    }
    result
}

#[inline(always)]
unsafe fn syscall4(n: usize, a0: usize, a1: usize, a2: usize, a3: usize) -> usize {
    let result: usize;
    unsafe {
        asm!(
            "syscall",
            inout("$2") n => result,
            inout("$4") a0 => _,
            inout("$5") a1 => _,
            inout("$6") a2 => _,
            inout("$7") a3 => _,
            options(nostack),
        );
    }
    result
}

/// Map the kernel's success/`0xffff_ffff` convention onto [`Result`].
///
/// There is no errno channel, so [`EIO`] is the generic answer.  Individual
/// call sites narrow it where the kernel's behaviour makes the cause obvious.
fn e_raw(ret: usize) -> Result<usize> {
    if ret == SYS_ERROR {
        Err(Errno(EIO))
    } else {
        Ok(ret)
    }
}

fn enosys<T>() -> Result<T> {
    Err(Errno(ENOSYS))
}

/// The kernel's private `struct stat` (`kernel/src/user.rs::KernelStat`).
///
/// This is **not** relibc's n32 `struct stat`; see [`copy_stat`].
#[repr(C)]
struct KernelStat {
    st_dev: u64,
    st_ino: u64,
    st_mode: u32,
    st_nlink: u32,
    st_uid: u32,
    st_gid: u32,
    st_rdev: u64,
    st_size: i64,
    st_blksize: i32,
    _pad: u32,
    st_blocks: i64,
    st_atim: [i64; 2],
    st_mtim: [i64; 2],
    st_ctim: [i64; 2],
    spare: [u8; 16],
}

fn copy_stat(from: &KernelStat, to: *mut stat) {
    // SAFETY: callers pass a non-NULL, aligned `struct stat` pointer.
    unsafe {
        (*to).st_dev = from.st_dev;
        (*to).st_ino = from.st_ino;
        (*to).st_nlink = from.st_nlink as nlink_t;
        (*to).st_mode = from.st_mode as mode_t;
        (*to).st_uid = from.st_uid as uid_t;
        (*to).st_gid = from.st_gid as gid_t;
        (*to).st_rdev = from.st_rdev;
        (*to).st_size = from.st_size;
        (*to).st_blksize = from.st_blksize as blksize_t;
        (*to).st_blocks = from.st_blocks;
        (*to).st_atim = timespec {
            tv_sec: from.st_atim[0],
            tv_nsec: from.st_atim[1] as c_long,
        };
        (*to).st_mtim = timespec {
            tv_sec: from.st_mtim[0],
            tv_nsec: from.st_mtim[1] as c_long,
        };
        (*to).st_ctim = timespec {
            tv_sec: from.st_ctim[0],
            tv_nsec: from.st_ctim[1] as c_long,
        };
        (*to)._pad = [0; 24];
    }
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
        let ret = unsafe { syscall2(SYS_POLL, fds.as_mut_ptr() as usize, fds.len()) };
        if ret == SYS_ERROR {
            Err(Errno(EIO))
        } else {
            Ok(ret as c_int)
        }
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
        e_raw(unsafe { syscall1(SYS_CHDIR, path.as_ptr() as usize) }).map(|_| ())
    }

    fn clock_getres(_clk_id: clockid_t, _tp: Option<Out<timespec>>) -> Result<()> {
        enosys()
    }

    fn clock_gettime(clk_id: clockid_t, mut tp: Out<timespec>) -> Result<()> {
        // The kernel writes { i64 sec, i32 nsec, u32 pad }, which is exactly
        // relibc's n32 `timespec` (16 bytes including tail padding).
        e_raw(unsafe { syscall2(SYS_CLOCK_GETTIME, clk_id as usize, tp.as_mut_ptr() as usize) })
            .map(|_| ())
    }

    unsafe fn clock_settime(_clk_id: clockid_t, _tp: *const timespec) -> Result<()> {
        enosys()
    }

    fn close(fildes: c_int) -> Result<()> {
        let ret = unsafe { syscall1(SYS_CLOSE, fildes as usize) };
        if ret == SYS_ERROR {
            Err(Errno(EBADF))
        } else {
            Ok(())
        }
    }

    fn dup(fildes: c_int) -> Result<c_int> {
        let ret = unsafe { syscall1(SYS_DUP, fildes as usize) };
        if ret == SYS_ERROR {
            Err(Errno(EBADF))
        } else {
            Ok(ret as c_int)
        }
    }

    fn dup2(_fildes: c_int, _fildes2: c_int) -> Result<c_int> {
        // dup(2) can only allocate the next free descriptor.
        enosys()
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
            syscall1(SYS_EXIT, status as usize);
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
        let mut kernel = KernelStat {
            st_dev: 0,
            st_ino: 0,
            st_mode: 0,
            st_nlink: 0,
            st_uid: 0,
            st_gid: 0,
            st_rdev: 0,
            st_size: 0,
            st_blksize: 0,
            _pad: 0,
            st_blocks: 0,
            st_atim: [0; 2],
            st_mtim: [0; 2],
            st_ctim: [0; 2],
            spare: [0; 16],
        };
        let ret = unsafe {
            syscall2(
                SYS_FSTAT,
                fildes as usize,
                ptr::from_mut(&mut kernel) as usize,
            )
        };
        if ret == SYS_ERROR {
            return Err(Errno(EBADF));
        }
        copy_stat(&kernel, buf.as_mut_ptr());
        Ok(())
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
                let mut kernel = KernelStat {
                    st_dev: 0,
                    st_ino: 0,
                    st_mode: 0,
                    st_nlink: 0,
                    st_uid: 0,
                    st_gid: 0,
                    st_rdev: 0,
                    st_size: 0,
                    st_blksize: 0,
                    _pad: 0,
                    st_blocks: 0,
                    st_atim: [0; 2],
                    st_mtim: [0; 2],
                    st_ctim: [0; 2],
                    spare: [0; 16],
                };
                let ret = unsafe {
                    syscall2(
                        SYS_STAT,
                        path.as_ptr() as usize,
                        ptr::from_mut(&mut kernel) as usize,
                    )
                };
                if ret == SYS_ERROR {
                    return Err(Errno(ENOENT));
                }
                copy_stat(&kernel, buf.as_mut_ptr());
                return Ok(());
            }
        }
        Self::fstat(fildes, buf)
    }

    fn fstatvfs(_fildes: c_int, _buf: Out<statvfs>) -> Result<()> {
        enosys()
    }

    fn fcntl(fildes: c_int, cmd: c_int, arg: c_ulonglong) -> Result<c_int> {
        // The kernel's fcntl is an unconditional success with no side effects
        // (traps.rs case 8).  Passing it through keeps F_GETFD/F_SETFD working
        // for stdio, but no command is actually interpreted.
        Ok(
            e_raw(unsafe { syscall3(SYS_FCNTL, fildes as usize, cmd as usize, arg as usize) })?
                as c_int,
        )
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
        enosys()
    }

    unsafe fn futex_wake(_addr: *mut u32, _num: u32) -> Result<u32> {
        enosys()
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
        let ret = unsafe {
            syscall2(
                SYS_GETCWD,
                buf.as_mut_ptr().as_mut_ptr() as usize,
                buf.len(),
            )
        };
        if ret == SYS_ERROR {
            Err(Errno(ERANGE))
        } else {
            Ok(())
        }
    }

    fn getdents(fd: c_int, buf: &mut [u8], opaque_offset: u64) -> Result<usize> {
        // relibc wants getdents records; the kernel offers
        // readdir(fd, index, name, len) -> type.  Emit one record per call and
        // let the caller's opaque offset act as the kernel index.
        let dent_size = size_of::<dirent>();
        if buf.len() < dent_size {
            // relibc's DIR grows the buffer and retries on EINVAL.
            return Err(Errno(EINVAL));
        }
        if opaque_offset > u32::MAX as u64 {
            return Err(Errno(EINVAL));
        }
        let mut name = [0u8; 256];
        let kind = unsafe {
            syscall4(
                SYS_READDIR,
                fd as usize,
                opaque_offset as usize,
                name.as_mut_ptr() as usize,
                name.len(),
            )
        };
        match kind {
            0 => Ok(0),
            SYS_ERROR => Err(Errno(EBADF)),
            kind => {
                let mut dent = dirent {
                    d_ino: opaque_offset + 1,
                    d_off: (opaque_offset + 1) as off_t,
                    d_reclen: dent_size as c_ushort,
                    d_type: kind as c_uchar,
                    d_name: [0; 256],
                };
                let len = name
                    .iter()
                    .position(|byte| *byte == 0)
                    .unwrap_or(name.len() - 1);
                for (slot, byte) in dent.d_name.iter_mut().zip(&name[..len]) {
                    *slot = *byte as c_char;
                }
                // SAFETY: buf is at least `dent_size` bytes and may be
                // unaligned, so copy rather than casting to `*mut dirent`.
                unsafe {
                    ptr::copy_nonoverlapping(
                        ptr::from_ref(&dent).cast::<u8>(),
                        buf.as_mut_ptr(),
                        dent_size,
                    );
                }
                Ok(dent_size)
            }
        }
    }

    fn dir_seek(_fd: c_int, _opaque_offset: u64) -> Result<()> {
        // No lseek(2) in the ABI.  The caller keeps the opaque offset and
        // passes it back to getdents, so there is nothing to do here.
        Ok(())
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
        unsafe { syscall0(SYS_GETPID) as pid_t }
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
        e_raw(unsafe {
            syscall2(SYS_GETENTROPY, buf.as_mut_ptr() as usize, buf.len())
        })
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

    fn lseek(_fildes: c_int, _offset: off_t, _whence: c_int) -> Result<off_t> {
        // File descriptors carry an implicit offset in the kernel, but there
        // is no way to read or set it.
        enosys()
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
        let ret = unsafe { syscall4(SYS_MMAP, addr as usize, len, prot as usize, flags as usize) };
        if ret == SYS_ERROR {
            Err(Errno(ENOMEM))
        } else {
            Ok(ret as *mut c_void)
        }
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
        e_raw(unsafe { syscall3(SYS_MPROTECT, addr as usize, len, prot as usize) }).map(|_| ())
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
        e_raw(unsafe { syscall2(SYS_MUNMAP, addr as usize, len) }).map(|_| ())
    }

    unsafe fn nanosleep(rqtp: *const timespec, _rmtp: *mut timespec) -> Result<()> {
        // The kernel busy-waits and does not report the remaining time.
        e_raw(unsafe { syscall1(SYS_NANOSLEEP, rqtp as usize) }).map(|_| ())
    }

    fn openat(dirfd: c_int, path: CStr, oflag: c_int, _mode: mode_t) -> Result<c_int> {
        if dirfd != AT_FDCWD {
            // Relative paths always resolve against the kernel cwd.
            return enosys();
        }
        let ret = unsafe { syscall3(SYS_OPEN, path.as_ptr() as usize, oflag as usize, 0) };
        if ret == SYS_ERROR {
            Err(Errno(ENOENT))
        } else {
            Ok(ret as c_int)
        }
    }

    fn pipe2(_fildes: Out<[c_int; 2]>, _flags: c_int) -> Result<()> {
        enosys()
    }

    fn posix_fallocate(_fd: c_int, _offset: u64, _length: NonZeroU64) -> Result<()> {
        enosys()
    }

    fn posix_getdents(_fildes: c_int, _buf: &mut [u8]) -> Result<usize> {
        // The default implementation needs lseek to read and advance the
        // directory position; the ABI has neither.  Use readdir(3) instead.
        enosys()
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
        let ret = unsafe {
            syscall3(
                SYS_READ,
                fildes as usize,
                buf.as_mut_ptr() as usize,
                buf.len(),
            )
        };
        if ret == SYS_ERROR {
            Err(Errno(EBADF))
        } else {
            Ok(ret)
        }
    }

    fn pread(_fildes: c_int, _buf: &mut [u8], _offset: off_t) -> Result<usize> {
        enosys()
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
        let ret = unsafe { syscall3(SYS_WRITE, fildes as usize, buf.as_ptr() as usize, buf.len()) };
        if ret == SYS_ERROR {
            Err(Errno(EBADF))
        } else {
            Ok(ret)
        }
    }

    fn pwrite(_fildes: c_int, _buf: &[u8], _offset: off_t) -> Result<usize> {
        enosys()
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
        let pid = unsafe { syscall0(SYS_GETPID) };
        pid != SYS_ERROR && pid != 0
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
    use core::mem::offset_of;
    use crate::header::{dirent::dirent, poll::pollfd, time::timespec};

    assert!(size_of::<KernelStat>() == 128);
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

    assert!(size_of::<pollfd>() == 8);
    assert!(offset_of!(pollfd, revents) == 6);
};
