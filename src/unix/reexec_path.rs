#![allow(unreachable_code, unused_variables)]

#[allow(unused_imports)]
use crate::imp::sys;

/// If possible, return a path under `/proc` that may refer to the current program.
#[inline]
pub fn get_procfs_reexec() -> Result<&'static [u8], ()> {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    return Ok(b"/proc/self/exe\0");

    #[cfg(any(target_os = "solaris", target_os = "illumos"))]
    return Ok(b"/proc/self/object/a.out\0");

    #[cfg(any(target_os = "netbsd", target_os = "dragonfly"))]
    return Ok(b"/proc/curproc/file\0");

    Err(())
}

/// If possible, `readlink()` a symlink under `/proc` that may refer to the current program.
#[inline]
pub fn get_procfs_readlink(buf: &mut [u8]) -> Result<usize, ()> {
    #[allow(unused_assignments, unused_mut)]
    let mut path: Option<&[u8]> = None;

    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        path = Some(b"/proc/self/exe\0");
    }
    #[cfg(any(target_os = "solaris", target_os = "illumos"))]
    {
        path = Some(b"/proc/self/path/a.out\0");
    }
    #[cfg(target_os = "netbsd")]
    {
        path = Some(b"/proc/curproc/exe\0");
    }

    if let Some(path) = path {
        let mut n = unsafe {
            libc::readlink(
                path.as_ptr() as *const _,
                buf.as_mut_ptr() as *mut _,
                buf.len(),
            )
        } as usize;

        if n != 0 && n < buf.len() - 1 {
            // Some OSes may add a trailing NUL byte
            if buf[n - 1] == 0 {
                n -= 1;
            }
            return Ok(n);
        }
    }

    Err(())
}

/// If possible, get the path of the currently running program via OS-specific kernel interfaces.
#[inline]
pub fn get_procinfo(buf: &mut [u8]) -> Result<Option<usize>, ()> {
    // FreeBSD/DragonFlyBSD/NetBSD let you get the path with sysctl()
    #[cfg(any(target_os = "freebsd", target_os = "dragonfly", target_os = "netbsd"))]
    {
        // The MIBs are slightly different
        #[cfg(any(target_os = "freebsd", target_os = "dragonfly"))]
        let mib = [
            libc::CTL_KERN,
            libc::KERN_PROC,
            libc::KERN_PROC_PATHNAME,
            -1,
        ];
        #[cfg(target_os = "netbsd")]
        let mib = [
            libc::CTL_KERN,
            libc::KERN_PROC,
            libc::KERN_PROC_ARGS,
            -1,
            libc::KERN_PROC_PATHNAME,
        ];

        let mut len = buf.len();
        if unsafe {
            libc::sysctl(
                mib.as_ptr(),
                mib.len() as _,
                buf.as_mut_ptr() as *mut _,
                &mut len,
                std::ptr::null(),
                0,
            )
        } == 0
            && len > 1
        {
            return Ok(Some(len - 1));
        }
    }

    // macOS has proc_pidpath()
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    {
        let n = unsafe {
            sys::proc_pidpath(libc::getpid(), buf.as_mut_ptr() as *mut _, buf.len() as _)
        };
        if n > 0 {
            return Ok(Some(n as usize));
        }
    }

    // Redox has the sys:exe special file, which contains the path to the process's executable
    #[cfg(target_os = "redox")]
    {
        let fd = unsafe {
            libc::open(
                b"sys:exe\0".as_ptr() as *const _,
                libc::O_RDONLY | libc::O_CLOEXEC,
            )
        };

        if fd >= 0 {
            let mut n = 0;
            while n < buf.len() {
                match unsafe { libc::read(fd, buf.as_mut_ptr().add(n) as *mut _, buf.len() - n) } {
                    // Error reading from the file; abort
                    -1 => {
                        // Set n=0 to ensure that the (incomplete) name is not actually returned
                        n = 0;
                        break;
                    }
                    // EOF
                    0 => break,
                    // Add the count and continue reading
                    count => n += count as usize,
                }
            }

            unsafe {
                libc::close(fd);
            }
            // Only return the path if it isn't empty (i.e. not present) and it isn't full (i.e.
            // too long)
            if (1..buf.len() - 1).contains(&n) {
                return Ok(Some(n as usize));
            }
        }
    }

    Err(())
}

/// Get the path that the process was started with as a static string.
#[inline]
pub fn get_initial_static() -> Result<*const libc::c_char, ()> {
    // On Linux, if /proc isn't mounted, getauxval(AT_EXECFN) might still give us the original path
    #[cfg(any(
        target_os = "linux",
        all(target_os = "android", target_pointer_width = "64"),
    ))]
    {
        let path = unsafe { libc::getauxval(libc::AT_EXECFN) } as *const libc::c_char;
        if !path.is_null() && unsafe { *path } == b'/' as _ {
            return Ok(path);
        }
    }

    #[cfg(any(target_os = "solaris", target_os = "illumos"))]
    {
        let path = unsafe { sys::getexecname() };
        if !path.is_null() && unsafe { *path } == b'/' as _ {
            return Ok(path);
        }
    }

    Err(())
}

/// Get the path that the process was started with (and store it into a buffer)
#[inline]
pub fn get_initial_buffered(buf: &mut [u8]) -> Result<Option<usize>, ()> {
    // Fallback in case the sysctl() method fails on FreeBSD for some reason
    #[cfg(target_os = "freebsd")]
    {
        if unsafe {
            sys::elf_aux_info(sys::AT_EXECPATH, buf.as_mut_ptr() as *mut _, buf.len() as _)
        } == 0
            && buf[0] == b'/'
        {
            return Ok(None);
        }
    }

    Err(())
}

/// The OpenBSD method.
///
/// This retrieves `argv[0]` and gets a `kinfo_file` struct for this program's executable file. If
/// `argv[0]` contains a `/`, it then `stat()`s it to check if that matches the metadata in the
/// `kinfo_file` we just retrieved. If everything matches, we found the executable.
#[cfg(target_os = "openbsd")]
pub fn get_openbsd(buf: &mut [u8]) -> Result<(usize, libc::dev_t, libc::ino_t), ()> {
    const PTR_SIZE: usize = std::mem::size_of::<*const u8>();

    let pid = unsafe { libc::getpid() };

    // Get the current process's command line
    let cmdline_mib = [
        libc::CTL_KERN,
        libc::KERN_PROC_ARGS,
        pid,
        libc::KERN_PROC_ARGV,
    ];
    let mut cmdline_buf = [0; sys::ARG_MAX];
    let mut cmdline_len = cmdline_buf.len();
    if unsafe {
        libc::sysctl(
            cmdline_mib.as_ptr(),
            cmdline_mib.len() as _,
            cmdline_buf.as_mut_ptr() as *mut _,
            &mut cmdline_len,
            std::ptr::null_mut(),
            0,
        )
    } != 0
    {
        return Err(());
    }

    // Extract argv[0]
    let mut arg0 = &cmdline_buf[..];
    while &arg0[..PTR_SIZE] != [0; PTR_SIZE].as_ref() {
        arg0 = &arg0[PTR_SIZE..];
    }
    arg0 = &arg0[PTR_SIZE..];
    arg0 = &arg0[..arg0.iter().position(|&ch| ch == 0).ok_or(())?];

    // Now try to get a kinfo_file for the executable
    // This is the first filled-in item, so we only need a 1-element buffer
    let kfile_mib = [
        libc::CTL_KERN,
        libc::KERN_FILE,
        sys::KERN_FILE_BYPID,
        pid,
        std::mem::size_of::<sys::kinfo_file>() as _,
        1,
    ];
    let mut kfile = std::mem::MaybeUninit::<sys::kinfo_file>::zeroed();
    let mut kfile_len = std::mem::size_of::<sys::kinfo_file>();
    if unsafe {
        libc::sysctl(
            kfile_mib.as_ptr(),
            kfile_mib.len() as _,
            kfile.as_mut_ptr() as *mut _,
            &mut kfile_len,
            std::ptr::null_mut(),
            0,
        )
    } != 0
    {
        // Even if we fail with ENOMEM, the first item may be filled in
        if unsafe { *crate::errno_ptr() } != libc::ENOMEM {
            return Err(());
        }
    }

    // The kernel should have initialized this structure
    if kfile_len == 0 {
        return Err(());
    }
    let kfile = unsafe { kfile.assume_init() };
    // And it should contain information on the executable file
    if kfile.fd_fd != sys::KERN_FILE_TEXT {
        return Err(());
    }

    let dev = kfile.va_fsid as libc::dev_t;
    let ino = kfile.va_fileid as libc::ino_t;

    unsafe fn check_path(path: *const u8, dev: libc::dev_t, ino: libc::ino_t) -> bool {
        // stat() it and make sure the device ID/inode match
        let mut st = std::mem::MaybeUninit::uninit();
        if libc::stat(path as *const _, st.as_mut_ptr()) != 0 {
            return false;
        }

        let st = st.assume_init();
        st.st_ino == ino && st.st_dev == dev
    }

    if arg0.contains(&b'/') {
        if unsafe { check_path(arg0.as_ptr(), dev, ino) } {
            buf[..arg0.len()].copy_from_slice(arg0);
            buf[arg0.len()] = 0;
            return Ok((arg0.len(), dev, ino));
        }
    }

    Err(())
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::tests::check_path_bytes;

    #[test]
    fn test_get_procfs_reexec() {
        if let Ok(path) = get_procfs_reexec() {
            check_path_bytes(path.split_last().unwrap().1);
        }
    }

    #[test]
    fn test_get_procfs_readlink() {
        let mut buf = [0; libc::PATH_MAX as usize];

        if let Ok(n) = get_procfs_readlink(&mut buf) {
            check_path_bytes(&buf[..n]);
        }
    }

    #[test]
    fn test_get_procinfo() {
        let mut buf = [0; libc::PATH_MAX as usize];

        if let Ok(n) = get_procinfo(&mut buf) {
            check_path_bytes(
                &buf[..n.unwrap_or_else(|| unsafe { libc::strlen(buf.as_ptr() as *const _) })],
            );
        }
    }

    #[test]
    fn test_get_initial_static() {
        if let Ok(path) = get_initial_static() {
            check_path_bytes(unsafe {
                std::slice::from_raw_parts(path as *const _, libc::strlen(path))
            });
        }
    }

    #[test]
    fn test_get_initial_buffered() {
        let mut buf = [0; libc::PATH_MAX as usize];

        if let Ok(n) = get_initial_buffered(&mut buf) {
            check_path_bytes(
                &buf[..n.unwrap_or_else(|| unsafe { libc::strlen(buf.as_ptr() as *const _) })],
            );
        }
    }

    #[cfg(target_os = "openbsd")]
    #[test]
    fn test_get_openbsd() {
        let mut buf = [0; libc::PATH_MAX as usize];

        if let Ok((n, _, _)) = get_openbsd(&mut buf) {
            check_path_bytes(&buf[..n]);
        }
    }
}
