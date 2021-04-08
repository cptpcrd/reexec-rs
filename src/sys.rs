#[cfg(target_os = "openbsd")]
pub const ARG_MAX: usize = 512 * 1024;
#[cfg(target_os = "openbsd")]
pub const KERN_FILE_TEXT: libc::c_int = -1;
#[cfg(target_os = "openbsd")]
pub const KERN_FILE_BYPID: libc::c_int = 2;
#[cfg(target_os = "openbsd")]
pub const KI_MNAMELEN: usize = 96;
#[cfg(target_os = "openbsd")]
pub const KI_MAXCOMLEN: usize = 24;
#[cfg(target_os = "openbsd")]
pub const KI_UNPPATHLEN: usize = 104;

#[cfg(target_os = "openbsd")]
#[derive(Copy, Clone)]
#[repr(C)]
pub struct kinfo_file {
    pub f_fileaddr: u64,
    pub f_flag: u32,
    pub f_iflags: u32,
    pub f_type: u32,
    pub f_count: u32,
    pub f_msgcount: u32,
    pub f_usecount: u32,
    pub f_ucred: u64,
    pub f_uid: u32,
    pub f_gid: u32,
    pub f_ops: u64,
    pub f_offset: u64,
    pub f_data: u64,
    pub f_rxfer: u64,
    pub f_rwfer: u64,
    pub f_seek: u64,
    pub f_rbytes: u64,
    pub f_wbytes: u64,

    pub v_un: u64,
    pub v_type: u32,
    pub v_tag: u32,
    pub v_flag: u32,
    pub va_rdev: u32,
    pub v_data: u64,
    pub v_mount: u64,
    pub va_fileid: u64,
    pub va_size: u64,
    pub va_mode: u32,
    pub va_fsid: u32,
    pub f_mntonname: [libc::c_char; KI_MNAMELEN],

    pub so_type: u32,
    pub so_state: u32,
    pub so_pcb: u64,

    pub so_protocol: u32,
    pub so_family: u32,
    pub inp_ppcb: u64,
    pub inp_lport: u32,
    pub inp_laddru: [u32; 4],
    pub inp_fport: u32,
    pub inp_faddru: [u32; 4],
    pub unp_conn: u64,

    pub pipe_peer: u64,
    pub pipe_state: u32,

    pub kq_count: u32,
    pub kq_state: u32,

    __unused1: u32,

    pub p_pid: u32,
    pub fd_fd: i32,
    pub fd_ofileflags: u32,
    pub p_uid: u32,
    pub p_gid: u32,
    pub p_tid: u32,
    pub p_comm: [libc::c_char; KI_MAXCOMLEN],

    pub inp_rtableid: u32,
    pub so_splice: u64,
    pub so_splicelen: i64,

    pub so_rcv_cc: u64,
    pub so_snd_cc: u64,
    pub unp_refs: u64,
    pub unp_nextref: u64,
    pub unp_addr: u64,
    pub unp_path: [libc::c_char; KI_UNPPATHLEN],
    pub inp_proto: u32,
    pub t_state: u32,
    pub t_rcv_wnd: u64,
    pub t_snd_wnd: u64,
    pub t_snd_cwnd: u64,

    pub va_nlink: u32,
}
