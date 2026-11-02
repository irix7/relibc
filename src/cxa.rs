use crate::platform::types::{c_int, c_void};
use alloc::vec::Vec;
use core::cell::RefCell;
use spin::Mutex;

#[derive(Clone, Copy)]
struct CxaAtExitFunc {
    func: extern "C" fn(*mut c_void),
    arg: usize,
    dso: usize,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct CxaThreadAtExitFunc {
    pub(crate) func: extern "C" fn(*mut c_void),
    pub(crate) obj: *mut c_void,
    pub(crate) dso: *mut c_void,
}

static CXA_ATEXIT_FUNCS: Mutex<Vec<Option<CxaAtExitFunc>>> = Mutex::new(Vec::new());
#[cfg(not(target_os = "irix7"))]
#[thread_local]
static DTORS: RefCell<Vec<CxaThreadAtExitFunc>> = RefCell::new(Vec::new());

#[cfg(not(target_os = "irix7"))]
fn with_dtors<R>(f: impl FnOnce(&mut Vec<CxaThreadAtExitFunc>) -> R) -> R {
    f(&mut DTORS.borrow_mut())
}

#[cfg(target_os = "irix7")]
fn with_dtors<R>(f: impl FnOnce(&mut Vec<CxaThreadAtExitFunc>) -> R) -> R {
    let thread =
        crate::pthread::current_thread().expect("thread atexit handler without a current thread");
    f(&mut thread.thread_dtors.borrow_mut())
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn __cxa_atexit(
    func: Option<extern "C" fn(*mut c_void)>,
    arg: *mut c_void,
    dso: *mut c_void,
) -> c_int {
    let Some(func) = func else {
        return 0;
    };

    let entry = CxaAtExitFunc {
        func,
        arg: arg as usize,
        dso: dso as usize,
    };

    let mut funcs = CXA_ATEXIT_FUNCS.lock();

    for slot in funcs.iter_mut() {
        if slot.is_none() {
            *slot = Some(entry);
            return 0;
        }
    }

    // No empty slots
    funcs.push(Some(entry));
    0
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn __cxa_finalize(dso: *mut c_void) {
    let mut funcs = CXA_ATEXIT_FUNCS.lock();

    let dso_usize = dso as usize;

    for slot in funcs.iter_mut().rev() {
        if let Some(entry) = slot.as_ref()
            && (dso.is_null() || entry.dso == dso_usize)
            && let Some(entry_to_run) = slot.take()
        {
            (entry_to_run.func)(entry_to_run.arg as *mut c_void);
        }
    }

    // clean up remaining list
    if dso.is_null() {
        funcs.clear();
    } else {
        funcs.retain(Option::is_some);
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn __cxa_thread_atexit_impl(
    func: extern "C" fn(*mut c_void),
    obj: *mut c_void,
    dso: *mut c_void,
) {
    let entry = CxaThreadAtExitFunc { func, obj, dso };
    with_dtors(|handlers| handlers.push(entry));
}

// called internally
pub unsafe fn __cxa_thread_finalize() {
    while let Some(entry) = with_dtors(|handlers| handlers.pop()) {
        (entry.func)(entry.obj);
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn _ITM_deregisterTMCloneTable(_ptr: *mut c_void) {
    // No-op
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn _ITM_registerTMCloneTable(_ptr: *mut c_void, _len: usize) {
    // No-op
}
