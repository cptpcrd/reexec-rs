#![cfg_attr(docsrs, feature(doc_cfg))]

use std::borrow::Cow;
use std::path::Path;

#[cfg_attr(unix, path = "unix/mod.rs")]
#[cfg_attr(windows, path = "windows.rs")]
mod imp;

#[cfg(any(target_os = "solaris", target_os = "illumos"))]
use libc::___errno as errno_ptr;
#[cfg(any(target_os = "android", target_os = "netbsd", target_os = "openbsd"))]
use libc::__errno as errno_ptr;
#[cfg(any(target_os = "linux", target_os = "dragonfly", target_os = "redox"))]
use libc::__errno_location as errno_ptr;
#[cfg(any(target_os = "freebsd", target_os = "macos"))]
use libc::__error as errno_ptr;
#[cfg(windows)]
extern "cdecl" {
    #[link_name = "_errno"]
    fn errno_ptr() -> *mut libc::c_int;
}

/// Re-execute the currently running program with the specified `argv` and `envp`.
///
/// The error from `execve()` is returned. If it was impossible to get the path of this process's
/// executable, `ENOENT` or `EACCES` may be returned instead.
///
/// On Unix-like systems, this function is async-signal-safe.
///
/// # Safety
///
/// All the unsafety of a standard C `execve()` call.
///
/// You should not use this function unless you are familiar with the issues surrounding the
/// interactions with `execve()` and all of the following:
///
/// - Multithreaded programs (and async-signal-safe functions)
/// - Thread-safety of accessing the environment (especially in Rust)
///
/// If any of these are unfamiliar, you should not be using this function.
#[inline]
pub unsafe fn reexecve(argv: *const *const libc::c_char, envp: *const *const libc::c_char) -> i32 {
    imp::reexecve(argv, envp)
}

/// Re-execute the currently running program with the specified `argv` and `envp`.
///
/// This is a Windows-specific version of [`reexecve()`] that takes `argv` and `envp` as pointers
/// to arrays of wide strings.
#[cfg_attr(docsrs, doc(cfg(windows)))]
#[cfg(windows)]
#[inline]
pub unsafe fn wreexecve(
    argv: *const *const libc::wchar_t,
    envp: *const *const libc::wchar_t,
) -> i32 {
    imp::wreexecve(argv, envp)
}

/// If possible, get a path that can be used to re-execute this program.
///
/// The returned path should always be absolute. (If this is necessary for security reasons, you
/// may want to verify this explicitly.)
///
/// Note that this may not be the actual path to the executable; e.g. it may be a special path in
/// `/proc` that points to the executable.
#[inline]
pub fn get_reexec_path() -> Result<Cow<'static, Path>, i32> {
    imp::get_reexec_path()
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::ffi::OsStr;
    use std::fs;
    use std::io;

    #[cfg(unix)]
    use std::os::unix::prelude::*;
    #[cfg(windows)]
    use std::os::windows::prelude::*;

    #[cfg(unix)]
    pub(crate) fn check_path_bytes(path: &[u8]) {
        check_path(OsStr::from_bytes(path));
    }

    pub(crate) fn check_path(path: &OsStr) {
        fn check_same_meta(m1: &fs::Metadata, m2: &fs::Metadata) {
            #[cfg(unix)]
            {
                assert_eq!(m1.dev(), m2.dev());
                assert_eq!(m1.ino(), m2.ino());
            }

            #[cfg(windows)]
            {
                // The Windows equivalents of dev() and ino() are in nightly. For now, just compare
                // the file type and all the file times, which gets us pretty close.
                assert_eq!(m1.file_type(), m2.file_type());
                assert_eq!(m1.creation_time(), m2.creation_time());
                assert_eq!(m1.last_access_time(), m2.last_access_time());
                assert_eq!(m1.last_write_time(), m2.last_write_time());
            }
        }

        let f1 = match fs::File::open(path) {
            Ok(f) => f,
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::NotFound | io::ErrorKind::PermissionDenied
                ) =>
            {
                return;
            }
            Err(e) => panic!("{}", e),
        };

        let exe = std::env::current_exe().unwrap();
        let f2 = fs::File::open(exe).unwrap();

        let m1 = f1.metadata().unwrap();
        let m2 = f2.metadata().unwrap();
        check_same_meta(&m1, &m2);
    }

    #[test]
    fn test_get_reexec_path() {
        check_path(get_reexec_path().unwrap().as_ref().as_ref());
    }
}
