use std::borrow::Cow;
use std::ffi::OsString;
use std::os::windows::prelude::*;
use std::path::{Path, PathBuf};

use winapi::{
    shared::minwindef::MAX_PATH, um::processthreadsapi::GetCurrentProcess,
    um::winbase::QueryFullProcessImageNameA, um::winbase::QueryFullProcessImageNameW,
};

use crate::errno_ptr;

pub unsafe fn reexecve(argv: *const *const libc::c_char, envp: *const *const libc::c_char) -> i32 {
    let mut buf = [0; MAX_PATH];
    let mut len = buf.len() as _;
    if QueryFullProcessImageNameA(GetCurrentProcess(), 0, buf.as_mut_ptr(), &mut len) == 0 {
        return libc::ENOENT;
    }

    libc::execve(buf.as_ptr(), argv, envp);
    *errno_ptr()
}

pub unsafe fn wreexecve(
    argv: *const *const libc::wchar_t,
    envp: *const *const libc::wchar_t,
) -> i32 {
    let mut buf = [0; MAX_PATH];
    let mut len = buf.len() as _;
    if QueryFullProcessImageNameW(GetCurrentProcess(), 0, buf.as_mut_ptr(), &mut len) == 0 {
        return libc::ENOENT;
    }

    libc::wexecve(buf.as_ptr(), argv, envp);
    *errno_ptr()
}

#[inline]
pub fn get_reexec_path() -> Result<Cow<'static, Path>, i32> {
    get_exe_path()
}

pub fn get_exe_path() -> Result<Cow<'static, Path>, i32> {
    let mut buf = [0; MAX_PATH];
    let mut len = buf.len() as _;
    if unsafe {
        QueryFullProcessImageNameW(GetCurrentProcess(), 0, buf.as_mut_ptr(), &mut len) == 0
    } {
        return Err(libc::ENOENT);
    }
    let path = PathBuf::from(OsString::from_wide(&buf[..len as usize]));

    // Check that the path exists and is a regular file
    // TODO: Is there a way to check if the path is executable?
    if !matches!(path.metadata(), Ok(m) if m.is_file()) {
        return Err(libc::ENOENT);
    }

    Ok(Cow::Owned(path))
}
