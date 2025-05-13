#![allow(unsafe_code)]

use std::ffi::CStr;
use tracing::debug;

/// Callback function to WolfSSL's [`set_logging_callback`] (which conforms to [`WolfsslLoggingCallback`])
/// It will pass the log message to [`tracing`] via `debug` macro.
/// This is marked `unsafe` to match the `bindgen`-generated function type for FFI compatibility.
/// # SAFETY
/// The caller must originate from the WolfSSL library's logging callback,
/// as it is not designed to be used or called from Rust.
#[allow(non_snake_case)]
pub unsafe extern "C" fn wolfssl_tracing_callback(
    _logLevel: std::os::raw::c_int,
    logMessage: *const std::os::raw::c_char,
) {
    if logMessage.is_null() {
        return;
    }
    // SAFETY: Based on the safety requirements for CStr
    // https://doc.rust-lang.org/std/ffi/struct.CStr.html#safety
    // We check the pointer is not null, and the string pointed will be
    // null terminated since it is generated as snprintf from wolfssl
    // Ref: https://github.com/wolfSSL/wolfssl/blob/master/wolfcrypt/src/logging.c
    let c_str = unsafe { CStr::from_ptr(logMessage) };
    let msg = c_str.to_str().unwrap_or("Unable to decode C string");
    debug!(msg);
}
