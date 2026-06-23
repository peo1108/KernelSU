#![allow(clippy::unreadable_literal)]

use crate::ksu_uapi;
use anyhow::{Context, Result, bail};
use std::ffi::c_char;
use std::fs;
use std::os::fd::RawFd;
use std::sync::OnceLock;

// Global driver fd cache
static DRIVER_FD: OnceLock<RawFd> = OnceLock::new();
static INFO_CACHE: OnceLock<ksu_uapi::ksu_get_info_cmd> = OnceLock::new();

pub const NON_ROOT_DEFAULT_PROFILE_KEY: &str = "$";
pub const NOBODY_UID: u32 = 9999;
pub const KERNEL_SU_DOMAIN: &str = "u:r:ksu:s0";
pub const FLAG_KSU_NO_NEW_PRIVS: u64 = 1;

#[derive(Debug, Clone)]
#[allow(clippy::struct_excessive_bools)]
pub struct AppProfile {
    pub name: String,
    pub current_uid: i32,
    pub allow_su: bool,
    pub root_use_default: bool,
    pub root_template: Option<String>,
    pub uid: i32,
    pub gid: i32,
    pub groups: Vec<i32>,
    pub capabilities: Vec<i32>,
    pub context: String,
    pub namespace: i32,
    pub non_root_use_default: bool,
    pub umount_modules: bool,
    pub rules: String,
    pub flags: u64,
}

impl AppProfile {
    #[must_use]
    pub fn default_for(name: &str, uid: u32) -> Self {
        Self {
            name: name.to_string(),
            current_uid: uid as i32,
            allow_su: false,
            root_use_default: true,
            root_template: None,
            uid: 0,
            gid: 0,
            groups: Vec::new(),
            capabilities: Vec::new(),
            context: KERNEL_SU_DOMAIN.to_string(),
            namespace: 0,
            non_root_use_default: true,
            umount_modules: true,
            rules: String::new(),
            flags: FLAG_KSU_NO_NEW_PRIVS,
        }
    }

    #[must_use]
    pub const fn has_custom_profile(&self) -> bool {
        if self.allow_su {
            !self.root_use_default
        } else {
            !self.non_root_use_default
        }
    }
}

fn scan_driver_fd() -> Option<RawFd> {
    let fd_dir = fs::read_dir("/proc/self/fd").ok()?;

    for entry in fd_dir.flatten() {
        if let Ok(fd_num) = entry.file_name().to_string_lossy().parse::<i32>() {
            let link_path = format!("/proc/self/fd/{fd_num}");
            if let Ok(target) = fs::read_link(&link_path) {
                let target_str = target.to_string_lossy();
                if target_str.contains("[ksu_driver]") {
                    return Some(fd_num);
                }
            }
        }
    }

    None
}

// Get cached driver fd
fn init_driver_fd() -> Option<RawFd> {
    let fd = scan_driver_fd();
    if fd.is_none() {
        let mut fd = -1;
        unsafe {
            libc::syscall(
                libc::SYS_reboot,
                ksu_uapi::KSU_INSTALL_MAGIC1,
                ksu_uapi::KSU_INSTALL_MAGIC2,
                0,
                &mut fd,
            );
        };
        if fd >= 0 { Some(fd) } else { None }
    } else {
        fd
    }
}

// ioctl wrapper using libc
fn ksuctl<T>(request: u32, arg: *mut T) -> std::io::Result<i32> {
    use std::io;

    let fd = *DRIVER_FD.get_or_init(|| init_driver_fd().unwrap_or(-1));
    unsafe {
        let ret = libc::ioctl(fd as libc::c_int, request as i32, arg);
        if ret < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(ret)
        }
    }
}

// API implementations
pub fn get_info() -> ksu_uapi::ksu_get_info_cmd {
    *INFO_CACHE.get_or_init(|| {
        let mut cmd = ksu_uapi::ksu_get_info_cmd {
            version: 0,
            flags: 0,
            features: 0,
            uapi_version: 0,
        };
        if ksuctl(ksu_uapi::KSU_IOCTL_GET_INFO, &raw mut cmd).is_err() {
            let _ = ksuctl(ksu_uapi::KSU_IOCTL_GET_INFO_LEGACY, &raw mut cmd);
        }
        cmd
    })
}

pub fn get_version() -> i32 {
    get_info().version as i32
}

pub fn is_late_load() -> bool {
    get_info().flags & ksu_uapi::KSU_GET_INFO_FLAG_LATE_LOAD != 0
}

pub fn is_uapi_version_mismatch() -> bool {
    get_info().uapi_version != ksu_uapi::KERNEL_SU_UAPI_VERSION
}

pub fn grant_root() -> std::io::Result<()> {
    ksuctl(ksu_uapi::KSU_IOCTL_GRANT_ROOT, std::ptr::null_mut::<u8>())?;
    Ok(())
}

fn report_event(event: u32) {
    let mut cmd = ksu_uapi::ksu_report_event_cmd { event };
    let _ = ksuctl(ksu_uapi::KSU_IOCTL_REPORT_EVENT, &raw mut cmd);
}

pub fn report_post_fs_data() {
    report_event(ksu_uapi::EVENT_POST_FS_DATA);
}

pub fn report_boot_complete() {
    report_event(ksu_uapi::EVENT_BOOT_COMPLETED);
}

pub fn report_module_mounted() {
    report_event(ksu_uapi::EVENT_MODULE_MOUNTED);
}

pub fn check_kernel_safemode() -> bool {
    let mut cmd = ksu_uapi::ksu_check_safemode_cmd { in_safe_mode: 0 };
    let _ = ksuctl(ksu_uapi::KSU_IOCTL_CHECK_SAFEMODE, &raw mut cmd);
    cmd.in_safe_mode != 0
}

pub fn set_sepolicy(payload: *const u8, payload_len: u64) -> std::io::Result<i32> {
    let mut ioctl_cmd = crate::ksu_uapi::ksu_set_sepolicy_cmd {
        data_len: payload_len,
        data: payload as u64,
    };

    ksuctl(ksu_uapi::KSU_IOCTL_SET_SEPOLICY, &raw mut ioctl_cmd)
}

/// Get feature value and support status from kernel
/// Returns (value, supported)
pub fn get_feature(feature_id: u32) -> std::io::Result<(u64, bool)> {
    let mut cmd = ksu_uapi::ksu_get_feature_cmd {
        feature_id,
        value: 0,
        supported: 0,
    };
    ksuctl(ksu_uapi::KSU_IOCTL_GET_FEATURE, &raw mut cmd)?;
    Ok((cmd.value, cmd.supported != 0))
}

/// Set feature value in kernel
pub fn set_feature(feature_id: u32, value: u64) -> std::io::Result<()> {
    let mut cmd = ksu_uapi::ksu_set_feature_cmd { feature_id, value };
    ksuctl(ksu_uapi::KSU_IOCTL_SET_FEATURE, &raw mut cmd)?;
    Ok(())
}

pub fn get_su_request_fd() -> std::io::Result<RawFd> {
    let mut cmd = ksu_uapi::ksu_get_su_request_fd_cmd { flags: 0 };
    let result = ksuctl(ksu_uapi::KSU_IOCTL_GET_SU_REQUEST_FD, &raw mut cmd)?;
    Ok(result)
}

pub fn respond_su_request(request_id: u64, allow: bool) -> std::io::Result<()> {
    let mut cmd = ksu_uapi::ksu_respond_su_request_cmd {
        request_id,
        allow: u8::from(allow),
    };
    ksuctl(ksu_uapi::KSU_IOCTL_RESPOND_SU_REQUEST, &raw mut cmd)?;
    Ok(())
}

fn ensure_profile_key(key: &str) -> Result<()> {
    if key.is_empty() {
        bail!("profile key is empty");
    }
    if key.len() >= ksu_uapi::KSU_MAX_PACKAGE_NAME as usize {
        bail!("profile key too long: {key}");
    }
    if key.as_bytes().contains(&0) {
        bail!("profile key contains nul byte");
    }
    Ok(())
}

fn write_c_string(dst: &mut [c_char], value: &str) -> Result<()> {
    if value.len() >= dst.len() {
        bail!("string too long");
    }
    if value.as_bytes().contains(&0) {
        bail!("string contains nul byte");
    }
    dst.fill(0);
    for (idx, byte) in value.as_bytes().iter().enumerate() {
        dst[idx] = *byte as c_char;
    }
    Ok(())
}

fn read_c_string(src: &[c_char]) -> String {
    let bytes = src
        .iter()
        .copied()
        .take_while(|v| *v != 0)
        .collect::<Vec<_>>();
    String::from_utf8_lossy(&bytes).to_string()
}

fn caps_to_list(bits: u64) -> Vec<i32> {
    (0..64).filter(|cap| bits & (1u64 << cap) != 0).collect()
}

fn cap_list_to_bits(caps: &[i32]) -> Result<u64> {
    let mut bits = 0u64;
    for cap in caps {
        if !(0..64).contains(cap) {
            bail!("invalid capability: {cap}");
        }
        bits |= 1u64 << *cap;
    }
    Ok(bits)
}

fn raw_profile_from_app_profile(profile: &AppProfile) -> Result<ksu_uapi::app_profile> {
    ensure_profile_key(&profile.name)?;
    let mut raw = unsafe { std::mem::zeroed::<ksu_uapi::app_profile>() };
    raw.version = ksu_uapi::KSU_APP_PROFILE_VER;
    write_c_string(&mut raw.key, &profile.name)?;
    raw.curr_uid = profile.current_uid;
    raw.allow_su = profile.allow_su;

    if profile.allow_su {
        if profile.groups.len() > ksu_uapi::KSU_MAX_GROUPS as usize {
            bail!("too many groups");
        }
        unsafe {
            let rp_config = &mut raw.__bindgen_anon_1.rp_config;
            rp_config.use_default = profile.root_use_default;
            if let Some(template) = &profile.root_template {
                write_c_string(&mut rp_config.template_name, template)?;
            }
            rp_config.profile.uid = profile.uid;
            rp_config.profile.gid = profile.gid;
            rp_config.profile.groups_count =
                u32::try_from(profile.groups.len()).context("groups count overflows u32")?;
            for (idx, group) in profile.groups.iter().enumerate() {
                rp_config.profile.groups[idx] = *group;
            }
            rp_config.profile.capabilities.effective = cap_list_to_bits(&profile.capabilities)?;
            rp_config.profile.capabilities.permitted = rp_config.profile.capabilities.effective;
            write_c_string(&mut rp_config.profile.selinux_domain, &profile.context)?;
            rp_config.profile.namespaces = profile.namespace;
            rp_config.profile.flags = profile.flags;
        }
    } else {
        unsafe {
            let nrp_config = &mut raw.__bindgen_anon_1.nrp_config;
            nrp_config.use_default = profile.non_root_use_default;
            nrp_config.profile.umount_modules = profile.umount_modules;
        }
    }

    Ok(raw)
}

fn app_profile_from_raw(raw: &ksu_uapi::app_profile) -> AppProfile {
    let mut profile = AppProfile::default_for(&read_c_string(&raw.key), raw.curr_uid as u32);
    profile.allow_su = raw.allow_su;
    if raw.allow_su {
        unsafe {
            let rp_config = &raw.__bindgen_anon_1.rp_config;
            let group_count =
                (rp_config.profile.groups_count as usize).min(ksu_uapi::KSU_MAX_GROUPS as usize);
            profile.root_use_default = rp_config.use_default;
            profile.root_template = {
                let template = read_c_string(&rp_config.template_name);
                (!template.is_empty()).then_some(template)
            };
            profile.uid = rp_config.profile.uid;
            profile.gid = rp_config.profile.gid;
            profile.groups = rp_config.profile.groups[..group_count].to_vec();
            profile.capabilities = caps_to_list(rp_config.profile.capabilities.effective);
            profile.context = read_c_string(&rp_config.profile.selinux_domain);
            profile.namespace = rp_config.profile.namespaces;
            profile.flags = rp_config.profile.flags;
        }
    } else {
        unsafe {
            let nrp_config = &raw.__bindgen_anon_1.nrp_config;
            profile.non_root_use_default = nrp_config.use_default;
            profile.umount_modules = nrp_config.profile.umount_modules;
        }
    }
    profile
}

pub fn get_app_profile(key: &str, uid: u32) -> Result<(AppProfile, bool)> {
    ensure_profile_key(key)?;
    let mut raw = unsafe { std::mem::zeroed::<ksu_uapi::app_profile>() };
    raw.version = ksu_uapi::KSU_APP_PROFILE_VER;
    write_c_string(&mut raw.key, key)?;
    raw.curr_uid = i32::try_from(uid).context("uid overflows i32")?;

    let mut cmd = ksu_uapi::ksu_get_app_profile_cmd { profile: raw };
    match ksuctl(ksu_uapi::KSU_IOCTL_GET_APP_PROFILE, &raw mut cmd) {
        Ok(_) => Ok((app_profile_from_raw(&cmd.profile), true)),
        Err(_) => Ok((AppProfile::default_for(key, uid), false)),
    }
}

pub fn set_app_profile(profile: &AppProfile) -> Result<()> {
    let raw = raw_profile_from_app_profile(profile)?;
    let mut cmd = ksu_uapi::ksu_set_app_profile_cmd { profile: raw };
    ksuctl(ksu_uapi::KSU_IOCTL_SET_APP_PROFILE, &raw mut cmd)
        .context("set app profile ioctl failed")?;
    Ok(())
}

pub fn uid_should_umount(uid: u32) -> bool {
    let mut cmd = ksu_uapi::ksu_uid_should_umount_cmd {
        uid,
        should_umount: 0,
    };
    let _ = ksuctl(ksu_uapi::KSU_IOCTL_UID_SHOULD_UMOUNT, &raw mut cmd);
    cmd.should_umount != 0
}

pub fn get_allow_list_count(allow: bool) -> u32 {
    let mut cmd = ksu_uapi::ksu_get_allow_list_cmd {
        uids: [0; 128],
        count: 0,
        allow: u8::from(allow),
    };
    let _ = ksuctl(ksu_uapi::KSU_IOCTL_GET_ALLOW_LIST, &raw mut cmd);
    cmd.count
}

pub fn is_default_umount_modules() -> Result<bool> {
    let (profile, _) = get_app_profile(NON_ROOT_DEFAULT_PROFILE_KEY, NOBODY_UID)?;
    Ok(profile.umount_modules)
}

pub fn set_default_umount_modules(umount_modules: bool) -> Result<()> {
    let mut profile = AppProfile::default_for(NON_ROOT_DEFAULT_PROFILE_KEY, NOBODY_UID);
    profile.umount_modules = umount_modules;
    set_app_profile(&profile)
}

pub fn set_app_profile_allow_su(key: &str, uid: u32, allow: bool) -> Result<()> {
    let mut profile = AppProfile::default_for(key, uid);
    profile.allow_su = allow;
    profile.root_use_default = true;
    set_app_profile(&profile)
}

pub fn get_wrapped_fd(fd: RawFd) -> std::io::Result<RawFd> {
    let mut cmd = ksu_uapi::ksu_get_wrapper_fd_cmd {
        fd: fd as u32,
        flags: 0,
    };
    let result = ksuctl(ksu_uapi::KSU_IOCTL_GET_WRAPPER_FD, &raw mut cmd)?;
    Ok(result)
}

pub fn get_sulog_fd() -> std::io::Result<RawFd> {
    let mut cmd = ksu_uapi::ksu_get_sulog_fd_cmd { flags: 0 };
    let result = ksuctl(ksu_uapi::KSU_IOCTL_GET_SULOG_FD, &raw mut cmd)?;
    Ok(result)
}

/// Get mark status for a process (pid=0 returns total marked count)
pub fn mark_get(pid: i32) -> std::io::Result<u32> {
    let mut cmd = ksu_uapi::ksu_manage_mark_cmd {
        operation: ksu_uapi::KSU_MARK_GET,
        pid,
        result: 0,
    };
    ksuctl(ksu_uapi::KSU_IOCTL_MANAGE_MARK, &raw mut cmd)?;
    Ok(cmd.result)
}

/// Mark a process (pid=0 marks all processes)
pub fn mark_set(pid: i32) -> std::io::Result<()> {
    let mut cmd = ksu_uapi::ksu_manage_mark_cmd {
        operation: ksu_uapi::KSU_MARK_MARK,
        pid,
        result: 0,
    };
    ksuctl(ksu_uapi::KSU_IOCTL_MANAGE_MARK, &raw mut cmd)?;
    Ok(())
}

/// Unmark a process (pid=0 unmarks all processes)
pub fn mark_unset(pid: i32) -> std::io::Result<()> {
    let mut cmd = ksu_uapi::ksu_manage_mark_cmd {
        operation: ksu_uapi::KSU_MARK_UNMARK,
        pid,
        result: 0,
    };
    ksuctl(ksu_uapi::KSU_IOCTL_MANAGE_MARK, &raw mut cmd)?;
    Ok(())
}

/// Refresh mark for all running processes
pub fn mark_refresh() -> std::io::Result<()> {
    let mut cmd = ksu_uapi::ksu_manage_mark_cmd {
        operation: ksu_uapi::KSU_MARK_REFRESH,
        pid: 0,
        result: 0,
    };
    ksuctl(ksu_uapi::KSU_IOCTL_MANAGE_MARK, &raw mut cmd)?;
    Ok(())
}

pub fn nuke_ext4_sysfs(mnt: &str) -> anyhow::Result<()> {
    let c_mnt = std::ffi::CString::new(mnt)?;
    let mut ioctl_cmd = ksu_uapi::ksu_nuke_ext4_sysfs_cmd {
        arg: c_mnt.as_ptr() as u64,
    };
    ksuctl(ksu_uapi::KSU_IOCTL_NUKE_EXT4_SYSFS, &raw mut ioctl_cmd)?;
    Ok(())
}

/// Wipe all entries from umount list
pub fn umount_list_wipe() -> std::io::Result<()> {
    let mut cmd = ksu_uapi::ksu_add_try_umount_cmd {
        arg: 0,
        flags: 0,
        mode: ksu_uapi::KSU_UMOUNT_WIPE,
    };
    ksuctl(ksu_uapi::KSU_IOCTL_ADD_TRY_UMOUNT, &raw mut cmd)?;
    Ok(())
}

/// Add mount point to umount list
pub fn umount_list_add(path: &str, flags: u32) -> anyhow::Result<()> {
    let c_path = std::ffi::CString::new(path)?;
    let mut cmd = ksu_uapi::ksu_add_try_umount_cmd {
        arg: c_path.as_ptr() as u64,
        flags,
        mode: ksu_uapi::KSU_UMOUNT_ADD,
    };
    ksuctl(ksu_uapi::KSU_IOCTL_ADD_TRY_UMOUNT, &raw mut cmd)?;
    Ok(())
}

/// Delete mount point from umount list
pub fn umount_list_del(path: &str) -> anyhow::Result<()> {
    let c_path = std::ffi::CString::new(path)?;
    let mut cmd = ksu_uapi::ksu_add_try_umount_cmd {
        arg: c_path.as_ptr() as u64,
        flags: 0,
        mode: ksu_uapi::KSU_UMOUNT_DEL,
    };
    ksuctl(ksu_uapi::KSU_IOCTL_ADD_TRY_UMOUNT, &raw mut cmd)?;
    Ok(())
}

/// Set current process's process group to init_group (pgid = 0)
pub fn set_init_pgrp() -> std::io::Result<()> {
    ksuctl(
        ksu_uapi::KSU_IOCTL_SET_INIT_PGRP,
        std::ptr::null_mut::<u8>(),
    )?;
    Ok(())
}

pub fn set_ksu_no_new_privs() -> anyhow::Result<()> {
    let result = ksuctl(
        ksu_uapi::KSU_IOCTL_DISABLE_ESCAPE_TO_ROOT,
        std::ptr::null_mut::<u8>(),
    )?;
    if result != 0 {
        bail!("unexpected result: {result}");
    }
    Ok(())
}
