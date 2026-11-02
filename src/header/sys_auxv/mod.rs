//! `sys/auxv.h` implementation.
//!
//! Non-POSIX, see <https://www.man7.org/linux/man-pages/man3/getauxval.3.html>.

use crate::platform::types::c_ulong;

pub use crate::platform::auxv_defs::*;

/// See <https://www.man7.org/linux/man-pages/man3/getauxval.3.html>.
#[unsafe(no_mangle)]
pub extern "C" fn getauxval(t: c_ulong) -> c_ulong {
    #[cfg(target_os = "irix7")]
    {
        return crate::platform::getauxval(t as usize) as c_ulong;
    }
    #[cfg(not(target_os = "irix7"))]
    {
        let _ = t;
        0
    }
}
