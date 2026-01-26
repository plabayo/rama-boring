#[cfg(target_env = "musl")]
#[allow(non_camel_case_types)]
pub type time_t = i64; // musl 1.2+ time_t is always i64

#[cfg(not(target_env = "musl"))]
pub use libc::time_t;

pub use libc::{c_char, c_int, c_long, c_uchar, c_uint, c_ulong, c_void, size_t, strlen};
