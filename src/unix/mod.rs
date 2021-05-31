use std::borrow::Cow;
use std::ffi::{OsStr, OsString};
use std::os::unix::prelude::*;
use std::path::Path;

mod reexec_path;
mod sys;

use crate::errno_ptr;

#[inline]
unsafe fn eaccess(path: *const libc::c_char, amode: libc::c_int) -> libc::c_int {
    #[cfg(not(target_os = "android"))]
    return sys::faccessat(libc::AT_FDCWD, path, amode, libc::AT_EACCESS);
    #[cfg(target_os = "android")]
    return libc::access(path, amode);
}

pub unsafe fn reexecve(argv: *const *const libc::c_char, envp: *const *const libc::c_char) -> i32 {
    let mut eno = libc::ENOENT;
    let eno_ptr = errno_ptr();

    macro_rules! try_exec {
        ($prog:expr $(,)?) => {
            libc::execve($prog as *const libc::c_char, argv, envp);

            eno = *eno_ptr;
            if !matches!(eno, libc::ENOENT | libc::EACCES) {
                return eno;
            }
        };
    }

    // Order is important:
    // - First we try a special path under /proc, if available. This only requires an execve() to
    //   test it, and on some OSes it will point to the original executable even if it's been
    //   unlink()ed or rename()d.
    // - If that failed, on some OSes there's a defined way to ask the kernel for the path. This may
    //   update across rename()s (though not unlink()s).
    // - Finally, when launching the program, some kernels may put the program's path in a place
    //   where the process can access it (either as a pointer or by copying into a buffer). That
    //   won't update across rename()s (and definitely not unlink()s), but it's the best we can do.

    if let Some(path) = reexec_path::get_procfs() {
        try_exec!(path.as_ptr());
    }

    // The compiler will optimize this out if it's not needed
    let mut buf = [0u8; libc::PATH_MAX as usize];

    if reexec_path::get_procinfo(&mut buf).is_some() {
        try_exec!(buf.as_ptr());
    }

    if let Some(path) = reexec_path::get_initial_static() {
        try_exec!(path);
    }

    if reexec_path::get_initial_buffered(&mut buf).is_some() {
        try_exec!(buf.as_ptr());
    }

    #[cfg(target_os = "openbsd")]
    if reexec_path::get_openbsd(&mut buf).is_some() {
        try_exec!(buf.as_ptr());
    }

    eno
}

pub fn get_reexec_path() -> Result<Cow<'static, Path>, i32> {
    unsafe {
        let mut eno = libc::ENOENT;
        let eno_ptr = errno_ptr();

        macro_rules! try_static_path {
            ($ptr:expr, $len:expr $(,)?) => {
                if eaccess($ptr, libc::X_OK) == 0 {
                    return Ok(Cow::Borrowed(
                        OsStr::from_bytes(std::slice::from_raw_parts($ptr as *const u8, $len))
                            .as_ref(),
                    ));
                }

                if *eno_ptr == libc::EACCES {
                    eno = libc::EACCES;
                }
            };
        }

        macro_rules! try_buffered_path {
            ($buf:expr, $len:expr $(,)?) => {
                if eaccess($buf.as_ptr() as *const _, libc::X_OK) == 0 {
                    return Ok(Cow::Owned(OsString::from_vec($buf[..$len].into()).into()));
                }

                if *eno_ptr == libc::EACCES {
                    eno = libc::EACCES;
                }
            };
        }

        // Order is important, as described in reexecve()

        if let Some(path) = reexec_path::get_procfs() {
            try_static_path!(path.as_ptr() as *const libc::c_char, path.len() - 1);
        }

        // The compiler will optimize this out if it's not needed
        let mut buf = [0u8; libc::PATH_MAX as usize];

        if let Some(n) = reexec_path::get_procinfo(&mut buf) {
            try_buffered_path!(
                buf,
                n.unwrap_or_else(|| libc::strlen(buf.as_ptr() as *const _)),
            );
        }

        if let Some(path) = reexec_path::get_initial_static() {
            try_static_path!(path, libc::strlen(path));
        }

        if let Some(n) = reexec_path::get_initial_buffered(&mut buf) {
            try_buffered_path!(
                buf,
                n.unwrap_or_else(|| libc::strlen(buf.as_ptr() as *const _)),
            );
        }

        #[cfg(target_os = "openbsd")]
        if let Some((n, dev, ino)) = reexec_path::get_openbsd(&mut buf) {
            if eaccess(buf.as_ptr() as *const _, libc::X_OK) == 0 {
                let path = &buf[..n];

                return Ok(Cow::Owned(if path.first() == Some(&b'/') {
                    OsString::from_vec(path.into()).into()
                } else {
                    // The working directory might change between now and when we call execve();
                    // canonicalize the path and check that it's still the right file

                    let path = Path::new(OsStr::from_bytes(path))
                        .canonicalize()
                        .map_err(|e| e.raw_os_error().unwrap())?;

                    let meta = path.metadata().map_err(|e| e.raw_os_error().unwrap())?;
                    if meta.dev() != dev as u64 || meta.ino() != ino as u64 {
                        return Err(libc::ENOENT);
                    }

                    path
                }));
            } else {
                eno = *eno_ptr;
            }
        }

        Err(eno)
    }
}
