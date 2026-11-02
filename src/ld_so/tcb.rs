use alloc::vec::Vec;
use core::{
    mem,
    ops::{Deref, DerefMut},
    ptr, slice,
};
use generic_rt::GenericTcb;

use crate::{
    header::sys_mman,
    ld_so::linker::Linker,
    platform::{Pal, Sys},
    pthread::Pthread,
    sync::mutex::Mutex,
};

use super::linker::DlError;

#[repr(C)]
#[derive(Debug, Clone)]
pub struct Master {
    /// Pointer to initial data
    pub ptr: *const u8,
    /// Length of initial data in bytes
    pub image_size: usize,
    pub segment_size: usize,
    /// Offset in TLS to copy initial data to
    pub offset: usize,
}

impl Master {
    /// The initial data for this TLS region
    pub unsafe fn data(&self) -> &'static [u8] {
        unsafe { slice::from_raw_parts(self.ptr, self.image_size) }
    }
}

#[cfg(target_os = "linux")]
pub type OsSpecific = ();

/// IRIX 7: no signal-frame or TLS state exists yet.
#[cfg(target_os = "irix7")]
pub type OsSpecific = ();

#[cfg(target_os = "redox")]
pub type OsSpecific = redox_rt::signal::RtSigarea;

#[derive(Debug)]
#[repr(C)]
// FIXME: Only return &Tcb, and use interior mutability, since it contains the Pthread struct
pub struct Tcb {
    pub generic: GenericTcb<OsSpecific>,
    /// Pointer to a list of initial TLS data
    pub masters_ptr: *mut Master,
    /// Size of the masters list in bytes (multiple of `mem::size_of::<Master>()`)
    pub masters_len: usize,
    /// Index of last copied Master
    pub num_copied_masters: usize,
    /// Pointer to dynamic linker
    pub linker_ptr: *const Mutex<Linker>,
    /// Underlying pthread_t struct, pthread_self() returns &self.pthread
    pub pthread: Pthread,

    // Dynamic TLS Vector
    pub dtv_ptr: *mut *mut u8,
    // Number of DTV entries.
    pub dtv_len: usize,
}

#[cfg(target_os = "redox")]
const _: () = {
    if mem::size_of::<Tcb>() > syscall::PAGE_SIZE {
        panic!("too large TCB!");
    }
};

impl Tcb {
    /// Create a new TCB
    ///
    /// `size` is the size of the TLS in bytes.
    #[expect(unsafe_op_in_unsafe_fn)]
    pub unsafe fn new(size: usize) -> Result<&'static mut Self, DlError> {
        let page_size = Sys::getpagesize();
        let (_abi_page, tls, tcb_page) = Self::os_new(size.next_multiple_of(page_size))?;

        let tcb_ptr = tcb_page.as_mut_ptr().cast::<Self>();
        ptr::write(
            tcb_ptr,
            Self {
                generic: GenericTcb {
                    tls_end: tls.as_mut_ptr().add(tls.len()),
                    tls_len: tls.len(),
                    tcb_ptr: tcb_ptr.cast(),
                    tcb_len: tcb_page.len(),
                    os_specific: OsSpecific::default(),
                },
                masters_ptr: ptr::null_mut(),
                masters_len: 0,
                num_copied_masters: 0,
                linker_ptr: ptr::null(),
                pthread: Pthread::new(tcb_ptr, 0),

                dtv_ptr: ptr::null_mut(),
                dtv_len: 0,
            },
        );

        Ok(&mut *tcb_ptr)
    }

    /// Build the main thread's TCB inside the buffer `_start` reserved.
    ///
    /// `tp` is the 16-byte ABI header the kernel and `_start` agree on; the
    /// relibc [`Tcb`] is appended at `tp + 16`.  The buffer is 1024 bytes in
    /// `crt0`, and `pthread::init` asserts the appended record fits.
    #[cfg(target_os = "irix7")]
    pub unsafe fn init_main(tp: *mut u8) -> &'static mut Self {
        let tcb_ptr = unsafe { tp.add(16).cast::<Self>() };
        unsafe {
            ptr::write(
                tcb_ptr,
                Self {
                    generic: GenericTcb {
                        tls_end: tp.add(16),
                        tls_len: 0,
                        tcb_ptr: tcb_ptr.cast(),
                        tcb_len: mem::size_of::<Self>(),
                        os_specific: OsSpecific::default(),
                    },
                    masters_ptr: ptr::null_mut(),
                    masters_len: 0,
                    num_copied_masters: 0,
                    linker_ptr: ptr::null(),
                    pthread: Pthread::new(tcb_ptr, 1),
                    dtv_ptr: ptr::null_mut(),
                    dtv_len: 0,
                },
            );
            &mut *tcb_ptr
        }
    }

    /// Get the current TCB
    pub unsafe fn current() -> Option<&'static mut Self> {
        unsafe { Some(&mut *GenericTcb::<OsSpecific>::current_ptr()?.cast()) }
    }

    /// A slice for all of the TLS data
    pub unsafe fn tls(&self) -> Option<&'static mut [u8]> {
        if self.tls_end.is_null() || self.tls_len == 0 {
            None
        } else {
            unsafe {
                let tls_start = self.tls_end.sub(self.tls_len);
                Some(slice::from_raw_parts_mut(tls_start, self.tls_len))
            }
        }
    }

    /// The initial images for TLS
    pub fn masters(&self) -> Option<&'static mut [Master]> {
        if self.masters_ptr.is_null() || self.masters_len == 0 {
            None
        } else {
            Some(unsafe {
                slice::from_raw_parts_mut(
                    self.masters_ptr,
                    self.masters_len / mem::size_of::<Master>(),
                )
            })
        }
    }

    /// Copy data from masters
    pub unsafe fn copy_masters(&mut self) -> Result<(), DlError> {
        //TODO: Complain if masters or tls exist without the other
        if let Some(tls) = unsafe { self.tls() }
            && let Some(masters) = self.masters()
        {
            for (i, master) in masters.iter().skip(self.num_copied_masters).enumerate() {
                if master.image_size == 0 {
                    continue;
                }

                let master_idx = self.num_copied_masters + i;
                let range = if cfg!(any(target_arch = "x86", target_arch = "x86_64")) {
                    // x86{_64} TLS layout is backwards
                    self.tls_len - master.offset..self.tls_len - master.offset + master.image_size
                } else if cfg!(target_arch = "aarch64") {
                    // AArch64 p_vaddr is ignored for first master, this is experimentally determined
                    let start = if master_idx == 0 { 0 } else { master.offset };
                    start..start + master.image_size
                } else {
                    master.offset..master.offset + master.image_size
                };
                if let Some(tls_data) = tls.get_mut(range) {
                    let data = unsafe { master.data() };
                    #[cfg(feature = "trace_tls")]
                    log::trace!(
                        "tls master: {:p}, {:#x}: {:p}, {:#x}",
                        data.as_ptr(),
                        data.len(),
                        tls_data.as_mut_ptr(),
                        tls_data.len()
                    );
                    tls_data.copy_from_slice(data);
                } else {
                    return Err(DlError::Malformed);
                }
            }
            self.num_copied_masters = masters.len();
        }

        Ok(())
    }

    /// The initial images for TLS
    pub unsafe fn append_masters(&mut self, mut new_masters: Vec<Master>) {
        if self.masters_ptr.is_null() {
            self.masters_ptr = new_masters.as_mut_ptr();
            self.masters_len = new_masters.len() * mem::size_of::<Master>();
            mem::forget(new_masters);
        } else {
            // XXX: [`Vec::from_raw_parts`] cannot be used here as the masters were originally
            // allocated by the ld.so allocator and that would violate that function's invariants.
            let mut masters = self.masters().unwrap().to_vec();
            masters.extend(new_masters);

            self.masters_ptr = masters.as_mut_ptr();
            self.masters_len = masters.len() * mem::size_of::<Master>();
            mem::forget(masters);
        }
    }

    /// Activate TLS
    pub unsafe fn activate(
        &mut self,
        #[cfg(target_os = "redox")] thr_fd: Option<redox_rt::proc::FdGuardUpper>,
    ) {
        unsafe {
            Self::os_arch_activate(
                &self.os_specific,
                self.tls_end as usize,
                self.tls_len,
                #[cfg(target_os = "redox")]
                thr_fd,
            )
        };
    }

    pub fn setup_dtv(&mut self, n: usize) {
        if self.dtv_ptr.is_null() {
            let mut dtv = vec![ptr::null_mut(); n];

            if let Some(masters) = self.masters() {
                for (i, master) in masters.iter().enumerate() {
                    let tls = unsafe { self.tls().unwrap() };
                    let offset = if cfg!(any(target_arch = "x86", target_arch = "x86_64")) {
                        // x86{_64} TLS layout is backwards
                        self.tls_len - master.offset
                    } else if cfg!(target_arch = "aarch64") {
                        // AArch64 p_vaddr is ignored for first master
                        if i == 0 { 0 } else { master.offset }
                    } else {
                        master.offset
                    };

                    dtv[i] = unsafe { tls.as_mut_ptr().add(offset) };
                }
            }

            let (ptr, len, _) = dtv.into_raw_parts();

            self.dtv_ptr = ptr;
            self.dtv_len = len;
        } else {
            // Resize DTV.
            //
            // XXX: [`Vec::from_raw_parts`] cannot be used here as the DTV was originally allocated
            // by the ld.so allocator and that would violate that function's invariants.
            let mut dtv = self.dtv_mut().to_vec();
            dtv.resize(n, ptr::null_mut());

            let (ptr, len, _) = dtv.into_raw_parts();
            self.dtv_ptr = ptr;
            self.dtv_len = len;
        }
    }

    pub fn dtv_mut(&mut self) -> &'static mut [*mut u8] {
        if self.dtv_len != 0 {
            unsafe { slice::from_raw_parts_mut(self.dtv_ptr, self.dtv_len) }
        } else {
            &mut []
        }
    }

    /// Mapping with correct flags for TCB and TLS
    #[expect(unsafe_op_in_unsafe_fn)]
    unsafe fn map(size: usize) -> Result<&'static mut [u8], DlError> {
        let ptr = Sys::mmap(
            ptr::null_mut(),
            size,
            sys_mman::PROT_READ | sys_mman::PROT_WRITE,
            sys_mman::MAP_ANONYMOUS | sys_mman::MAP_PRIVATE,
            -1,
            0,
        )
        .map_err(|_| DlError::Oom)?;

        ptr::write_bytes(ptr.cast::<u8>(), 0, size);
        Ok(slice::from_raw_parts_mut(ptr.cast::<u8>(), size))
    }

    /// OS specific code to create a new TLS and TCB - Linux and Redox
    ///
    /// Memory layout:
    ///
    /// ```text
    /// 0          page_size                   size       (size + page_size * 2)
    /// |----------|---------------------------|----------|
    /// +++++++++++++++++++++++++++++++++++++++++++++++++++
    /// | ABI Page | TLS                       | TCB Page |
    /// +++++++++++++++++++++++++++++++++++++++++++++++++++
    ///     ^ $tp (aarch64)                    ^ $tp (x86_64)
    /// ```
    ///
    /// `$tp` refers to the architecture specific thread pointer.
    ///
    /// **Note**: On x86{_64}, the TLS layout is backwards (i.e. the first byte of the TLS is at
    /// the end of the TLS region).
    ///
    /// ABI page layout for aarch64:
    /// ```text
    /// 0                     4096
    /// +---------------------+
    /// | ABI Page            |
    /// +---------------------+
    ///                     ^
    ///                     |
    ///                     +-------> (page_size - 16): pointer to the start of the TCB page
    /// ```
    ///
    /// ABI page layout for riscv64:
    ///
    /// ```text
    /// 0                     4096
    /// +---------------------+
    /// | ABI Page            |
    /// +---------------------+
    ///                      ^
    ///                      |
    ///                      +-------> (page_size - 8): pointer to the start of the TCB page
    /// ```
    ///
    /// For x86_64, the ABI page is not used.
    #[allow(clippy::type_complexity)]
    #[cfg(any(target_os = "linux", target_os = "redox"))]
    unsafe fn os_new(
        size: usize,
    ) -> Result<(&'static mut [u8], &'static mut [u8], &'static mut [u8]), DlError> {
        let page_size = Sys::getpagesize();

        // MIPS n32 uses TLS_DTV_AT_TP: the hardware thread pointer is
        // TLS block start + TLS_TCB_OFFSET (0x7000), and the TCB lives at
        // the thread pointer. Reserve that gap in the mapping.
        #[cfg(target_arch = "mips64")]
        {
            const TLS_TCB_OFFSET: usize = 0x7000;
            assert!(size <= TLS_TCB_OFFSET);
            let abi_tls_tcb = unsafe { Self::map(page_size + TLS_TCB_OFFSET + page_size)? };
            let (abi, tls_tcb) = abi_tls_tcb.split_at_mut(page_size);
            let (tls_gap, tcb) = tls_tcb.split_at_mut(TLS_TCB_OFFSET);
            let tls = &mut tls_gap[..size];
            return Ok((abi, tls, tcb));
        }

        #[cfg(not(target_arch = "mips64"))]
        {
            let abi_tls_tcb = unsafe { Self::map(page_size + size + page_size)? };
            let (abi, tls_tcb) = abi_tls_tcb.split_at_mut(page_size);
            let (tls, tcb) = tls_tcb.split_at_mut(size);
            Ok((abi, tls, tcb))
        }
    }

    /// IRIX 7: allocate the 16-byte ABI header and append relibc's TCB.
    ///
    /// `$28` points at the header, not at [`Tcb`], because the first 16 bytes
    /// are the kernel/libc contract: `self`, `dtv`, `errno` and a libc-private
    /// word.  The returned `tcb` slice starts after the header, so
    /// [`Tcb::new`] writes relibc's record there and `$28 + 16` is the
    /// [`Tcb`] pointer.
    #[cfg(target_os = "irix7")]
    unsafe fn os_new(
        size: usize,
    ) -> Result<(&'static mut [u8], &'static mut [u8], &'static mut [u8]), DlError> {
        let page_size = Sys::getpagesize();
        let total = (16 + mem::size_of::<Self>() + size).next_multiple_of(page_size);
        let mapping = unsafe { Self::map(total)? };
        let (header, rest) = mapping.split_at_mut(16);
        let (tls, tcb) = rest.split_at_mut(size);

        let self_ptr = header.as_mut_ptr() as usize as u32;
        header[0..4].copy_from_slice(&self_ptr.to_ne_bytes());
        header[4..8].copy_from_slice(&0u32.to_ne_bytes());
        header[8..12].copy_from_slice(&0i32.to_ne_bytes());
        header[12..16].copy_from_slice(&0u32.to_ne_bytes());

        Ok((header, tls, tcb))
    }

    /// OS and architecture specific code to activate TLS - Linux x86_64
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    unsafe fn os_arch_activate(_os: &(), tls_end: usize, _tls_len: usize) {
        const ARCH_SET_FS: usize = 0x1002;
        unsafe {
            syscall!(ARCH_PRCTL, ARCH_SET_FS, tls_end);
        }
    }

    #[cfg(all(target_os = "linux", target_arch = "mips64"))]
    unsafe fn os_arch_activate(_os: &(), tls_end: usize, tls_len: usize) {
        // MIPS n32: TP = TLS block start + 0x7000. `set_thread_area` takes
        // the thread-pointer value directly and installs it in userlocal.
        const TLS_TCB_OFFSET: usize = 0x7000;
        let tp = tls_end - tls_len + TLS_TCB_OFFSET;
        unsafe {
            syscall!(SET_THREAD_AREA, tp);
        }
    }

    #[cfg(all(target_os = "linux", target_arch = "aarch64"))]
    unsafe fn os_arch_activate(_os: &(), tls_end: usize, tls_len: usize) {
        // Uses ABI page
        let abi_ptr = tls_end - tls_len - 16;
        unsafe {
            core::ptr::write(abi_ptr as *mut usize, tls_end);
            core::arch::asm!(
                "msr tpidr_el0, {}",
                in(reg) abi_ptr,
            );
        }
    }

    /// IRIX 7: `$28` is the thread pointer.
    ///
    /// [`Self::os_new`] places the ABI header immediately before the TCB, so
    /// the header is 16 bytes below `tls_end` (the TCB's own address).
    #[cfg(target_os = "irix7")]
    unsafe fn os_arch_activate(_os: &(), tls_end: usize, _tls_len: usize) {
        let tp = tls_end - 16;
        unsafe {
            core::arch::asm!(
                "move $28, {tp}",
                tp = in(reg) tp,
                options(nostack, nomem),
            );
        }
    }

    #[cfg(target_os = "redox")]
    unsafe fn os_arch_activate(
        os: &OsSpecific,
        tls_end: usize,
        tls_len: usize,
        thr_fd: Option<redox_rt::proc::FdGuardUpper>,
    ) {
        unsafe {
            if let Some(thr_fd) = thr_fd {
                os.thr_fd.get().write(Some(thr_fd));
            }
            redox_rt::tcb_activate(os, tls_end, tls_len)
        }
    }
}

impl Deref for Tcb {
    type Target = GenericTcb<OsSpecific>;

    fn deref(&self) -> &Self::Target {
        &self.generic
    }
}
impl DerefMut for Tcb {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.generic
    }
}
