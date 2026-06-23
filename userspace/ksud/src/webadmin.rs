use anyhow::{Context, Result, bail, ensure};
use serde_json::{Value, json};
use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::fd::{FromRawFd, OwnedFd};
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::{defs, ksucalls, module, profile, utils};

const LISTEN_ADDR: &str = "127.0.0.1:9700";
const TOKEN_PATH: &str = concat!("/data/adb/ksu/", "webadmin.token");
const AUTOSTART_PATH: &str = concat!("/data/adb/ksu/", "webadmin.autostart");
const PID_PATH: &str = concat!("/data/adb/ksu/", "webadmin.pid");
const READ_BUF_SIZE: usize = 8192;
const EVENT_HEADER_SIZE: usize = 24;
const DROPPED_RECORD_TYPE: u16 = 0xffff;
const JSON_BODY_LIMIT: usize = 2 * 1024 * 1024;
const MODULE_UPLOAD_LIMIT: usize = 256 * 1024 * 1024;

#[derive(Debug, Clone)]
struct SuRequest {
    request_id: u64,
    deadline_ms: u64,
    uid: u32,
    euid: u32,
    pid: u32,
    tgid: u32,
    ppid: u32,
    comm: String,
    path: String,
    argv: String,
    packages: Vec<String>,
}

#[derive(Default)]
struct WebState {
    pending: HashMap<u64, SuRequest>,
}

struct HttpRequest {
    method: String,
    path: String,
    headers: HashMap<String, String>,
    body: Vec<u8>,
    upload_path: Option<PathBuf>,
}

struct EventHeader {
    record_type: u16,
    payload_len: u32,
}

fn ensure_working_dir() -> Result<()> {
    utils::ensure_dir_exists(Path::new(defs::WORKING_DIR))
}

fn to_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

fn generate_token() -> Result<String> {
    let mut bytes = [0u8; 32];
    File::open("/dev/urandom")
        .context("open /dev/urandom")?
        .read_exact(&mut bytes)
        .context("read random token")?;
    Ok(to_hex(&bytes))
}

fn read_or_create_token() -> Result<String> {
    ensure_working_dir()?;
    let path = Path::new(TOKEN_PATH);
    if path.exists() {
        return Ok(fs::read_to_string(path)?.trim().to_string());
    }

    let token = generate_token()?;
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(path)
        .context("create webadmin token")?;
    file.write_all(token.as_bytes())?;
    file.write_all(b"\n")?;
    file.sync_all()?;
    Ok(token)
}

pub fn print_token() -> Result<()> {
    println!("{}", read_or_create_token()?);
    Ok(())
}

pub fn set_autostart(enabled: bool) -> Result<()> {
    ensure_working_dir()?;
    if enabled {
        fs::write(AUTOSTART_PATH, b"1\n")?;
        println!("webadmin autostart enabled");
    } else {
        let _ = fs::remove_file(AUTOSTART_PATH);
        println!("webadmin autostart disabled");
    }
    Ok(())
}

pub fn maybe_spawn_autostart() {
    if Path::new(AUTOSTART_PATH).exists()
        && let Err(err) = spawn()
    {
        log::warn!("failed to autostart webadmin: {err:#}");
    }
}

pub fn spawn() -> Result<()> {
    if is_running() {
        println!("webadmin already running at http://{LISTEN_ADDR}");
        return Ok(());
    }

    if utils::create_daemon(true)? {
        let current_exe = std::env::current_exe().context("resolve current ksud path")?;
        let mut command = Command::new(current_exe);
        command
            .arg("web")
            .arg("serve")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .current_dir("/");
        Err(command.exec()).context("exec webadmin server")
    } else {
        println!("webadmin starting at http://{LISTEN_ADDR}");
        Ok(())
    }
}

pub fn stop() -> Result<()> {
    let pid = fs::read_to_string(PID_PATH)
        .context("webadmin pid file not found")?
        .trim()
        .parse::<i32>()
        .context("invalid webadmin pid")?;
    let ret = unsafe { libc::kill(pid, libc::SIGTERM) };
    if ret != 0 {
        bail!(
            "failed to stop webadmin: {}",
            std::io::Error::last_os_error()
        );
    }
    let _ = fs::remove_file(PID_PATH);
    println!("webadmin stopped");
    Ok(())
}

pub fn status() {
    let token_exists = Path::new(TOKEN_PATH).exists();
    let autostart = Path::new(AUTOSTART_PATH).exists();
    let listening = is_running();
    println!("listen: {LISTEN_ADDR}");
    println!("running: {listening}");
    println!("token: {token_exists}");
    println!("autostart: {autostart}");
}

fn is_running() -> bool {
    let Ok(addr) = LISTEN_ADDR.parse() else {
        return false;
    };
    TcpStream::connect_timeout(&addr, Duration::from_millis(300)).is_ok()
}

fn is_module_install_request(method: &str, path: &str) -> bool {
    method == "POST" && path.split('?').next() == Some("/api/v1/modules/install")
}

fn temp_upload_path() -> Result<PathBuf> {
    ensure_working_dir()?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    Ok(Path::new(defs::WORKING_DIR)
        .join(format!("webadmin-upload-{}-{now}.zip", std::process::id())))
}

fn parse_http_request(stream: &mut TcpStream) -> Result<HttpRequest> {
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;

    let mut buf = Vec::new();
    let mut tmp = [0u8; 1024];
    let header_end;
    loop {
        let n = stream.read(&mut tmp)?;
        if n == 0 {
            bail!("connection closed before request");
        }
        buf.extend_from_slice(&tmp[..n]);
        if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            header_end = pos + 4;
            break;
        }
        if buf.len() > 64 * 1024 {
            bail!("request headers too large");
        }
    }

    let header_text = std::str::from_utf8(&buf[..header_end]).context("invalid request headers")?;
    let mut lines = header_text.split("\r\n");
    let request_line = lines.next().context("missing request line")?;
    let mut request_parts = request_line.split_whitespace();
    let method = request_parts.next().context("missing method")?.to_string();
    let path = request_parts.next().context("missing path")?.to_string();
    let mut headers = HashMap::new();
    for line in lines {
        if line.is_empty() {
            continue;
        }
        if let Some((name, value)) = line.split_once(':') {
            headers.insert(name.trim().to_ascii_lowercase(), value.trim().to_string());
        }
    }

    let content_len = headers
        .get("content-length")
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(0);

    let mut body = Vec::new();
    let upload_path = if is_module_install_request(&method, &path) {
        if content_len > MODULE_UPLOAD_LIMIT {
            bail!("module zip too large");
        }
        let path = temp_upload_path()?;
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(&path)
            .context("create upload temp file")?;
        let mut written = 0usize;
        let initial = &buf[header_end..];
        let initial_len = initial.len().min(content_len);
        file.write_all(&initial[..initial_len])?;
        written += initial_len;
        while written < content_len {
            let n = stream.read(&mut tmp)?;
            if n == 0 {
                bail!("connection closed before body");
            }
            let remaining = content_len - written;
            let take = n.min(remaining);
            file.write_all(&tmp[..take])?;
            written += take;
        }
        file.sync_all()?;
        Some(path)
    } else {
        if content_len > JSON_BODY_LIMIT {
            bail!("request body too large");
        }
        body = buf[header_end..].to_vec();
        while body.len() < content_len {
            let n = stream.read(&mut tmp)?;
            if n == 0 {
                bail!("connection closed before body");
            }
            body.extend_from_slice(&tmp[..n]);
        }
        body.truncate(content_len);
        None
    };

    Ok(HttpRequest {
        method,
        path,
        headers,
        body,
        upload_path,
    })
}

fn write_response(
    stream: &mut TcpStream,
    status: &str,
    content_type: &str,
    body: &[u8],
) -> Result<()> {
    let header = format!(
        "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(header.as_bytes())?;
    stream.write_all(body)?;
    Ok(())
}

fn write_json(stream: &mut TcpStream, status: &str, value: &Value) -> Result<()> {
    let body = serde_json::to_vec(value)?;
    write_response(stream, status, "application/json", &body)
}

fn origin_allowed(req: &HttpRequest) -> bool {
    req.headers
        .get("origin")
        .is_none_or(|origin| origin == "http://127.0.0.1:9700" || origin == "http://localhost:9700")
}

fn is_authorized(req: &HttpRequest, token: &str) -> bool {
    req.headers
        .get("authorization")
        .and_then(|value| value.strip_prefix("Bearer "))
        .is_some_and(|provided| provided == token)
}

fn parse_json_body(req: &HttpRequest) -> Result<Value> {
    if !req
        .headers
        .get("content-type")
        .is_some_and(|v| v.starts_with("application/json"))
    {
        bail!("expected application/json");
    }
    Ok(serde_json::from_slice(&req.body)?)
}

fn api_error(message: &str, code: &str) -> Value {
    json!({ "error": message, "code": code })
}

fn bool_from_body(body: &Value, key: &str) -> Option<bool> {
    body.get(key).and_then(Value::as_bool)
}

fn validate_package_name(package: &str) -> Result<()> {
    ensure!(!package.is_empty(), "package is empty");
    ensure!(
        package.len() < ksu_uapi_max_package_name(),
        "package name too long"
    );
    ensure!(
        !package.as_bytes().contains(&0),
        "package contains nul byte"
    );
    ensure!(
        package == ksucalls::NON_ROOT_DEFAULT_PROFILE_KEY
            || package
                .chars()
                .all(|c| { c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | ':') }),
        "invalid package name"
    );
    Ok(())
}

const fn ksu_uapi_max_package_name() -> usize {
    256
}

fn query_param(path: &str, name: &str) -> Option<String> {
    let query = path.split_once('?')?.1;
    for pair in query.split('&') {
        let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
        if key == name {
            return Some(percent_decode(value));
        }
    }
    None
}

fn percent_decode(value: &str) -> String {
    const fn hex_value(byte: u8) -> Option<u8> {
        match byte {
            b'0'..=b'9' => Some(byte - b'0'),
            b'a'..=b'f' => Some(byte - b'a' + 10),
            b'A'..=b'F' => Some(byte - b'A' + 10),
            _ => None,
        }
    }

    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut idx = 0usize;
    while idx < bytes.len() {
        if bytes[idx] == b'%'
            && idx + 2 < bytes.len()
            && let (Some(high), Some(low)) = (hex_value(bytes[idx + 1]), hex_value(bytes[idx + 2]))
        {
            out.push((high << 4) | low);
            idx += 3;
        } else if bytes[idx] == b'+' {
            out.push(b' ');
            idx += 1;
        } else {
            out.push(bytes[idx]);
            idx += 1;
        }
    }
    String::from_utf8_lossy(&out).to_string()
}

fn profile_rules(package: &str) -> String {
    let path = Path::new(defs::PROFILE_SELINUX_DIR).join(package);
    fs::read_to_string(path).unwrap_or_default()
}

fn profile_to_json(profile: &ksucalls::AppProfile, has_profile: bool) -> Value {
    json!({
        "name": &profile.name,
        "currentUid": profile.current_uid,
        "allowSu": profile.allow_su,
        "rootUseDefault": profile.root_use_default,
        "rootTemplate": &profile.root_template,
        "uid": profile.uid,
        "gid": profile.gid,
        "groups": &profile.groups,
        "capabilities": &profile.capabilities,
        "context": &profile.context,
        "namespace": profile.namespace,
        "nonRootUseDefault": profile.non_root_use_default,
        "umountModules": profile.umount_modules,
        "rules": &profile.rules,
        "flags": profile.flags,
        "hasProfile": has_profile,
        "hasCustomProfile": profile.has_custom_profile(),
    })
}

fn int_vec_from_json(body: &Value, key: &str) -> Result<Vec<i32>> {
    let Some(values) = body.get(key).and_then(Value::as_array) else {
        return Ok(Vec::new());
    };
    values
        .iter()
        .map(|v| {
            let value = v
                .as_i64()
                .with_context(|| format!("{key} must contain integers"))?;
            i32::try_from(value).with_context(|| format!("{key} value overflows i32"))
        })
        .collect()
}

fn profile_from_json(
    body: &Value,
    uid: u32,
    fallback_package: &str,
) -> Result<ksucalls::AppProfile> {
    let name = body
        .get("name")
        .and_then(Value::as_str)
        .unwrap_or(fallback_package);
    validate_package_name(name)?;
    ensure!(
        name == fallback_package,
        "profile package does not match route"
    );
    let current_uid = body
        .get("currentUid")
        .and_then(Value::as_i64)
        .unwrap_or_else(|| i64::from(uid));
    ensure!(
        current_uid == i64::from(uid),
        "profile uid does not match route"
    );

    let mut profile = ksucalls::AppProfile::default_for(name, uid);
    profile.allow_su = bool_from_body(body, "allowSu").unwrap_or(false);
    profile.root_use_default = bool_from_body(body, "rootUseDefault").unwrap_or(true);
    profile.root_template = body
        .get("rootTemplate")
        .and_then(Value::as_str)
        .filter(|v| !v.is_empty())
        .map(ToString::to_string);
    profile.uid = body
        .get("uid")
        .and_then(Value::as_i64)
        .map(i32::try_from)
        .transpose()
        .context("uid overflows i32")?
        .unwrap_or(0);
    profile.gid = body
        .get("gid")
        .and_then(Value::as_i64)
        .map(i32::try_from)
        .transpose()
        .context("gid overflows i32")?
        .unwrap_or(0);
    profile.groups = int_vec_from_json(body, "groups")?;
    profile.capabilities = int_vec_from_json(body, "capabilities")?;
    profile.context = body
        .get("context")
        .and_then(Value::as_str)
        .unwrap_or(ksucalls::KERNEL_SU_DOMAIN)
        .to_string();
    profile.namespace = body
        .get("namespace")
        .and_then(Value::as_i64)
        .map(i32::try_from)
        .transpose()
        .context("namespace overflows i32")?
        .unwrap_or(0);
    ensure!((0..=2).contains(&profile.namespace), "invalid namespace");
    profile.non_root_use_default = bool_from_body(body, "nonRootUseDefault").unwrap_or(true);
    profile.umount_modules = bool_from_body(body, "umountModules").unwrap_or(true);
    profile.rules = body
        .get("rules")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    profile.flags = body
        .get("flags")
        .and_then(Value::as_u64)
        .unwrap_or(ksucalls::FLAG_KSU_NO_NEW_PRIVS);
    Ok(profile)
}

const fn feature_names() -> [(&'static str, u32, &'static str); 6] {
    [
        ("su_compat", 0, "SU compatibility mode"),
        ("kernel_umount", 1, "Kernel umount"),
        ("sulog", 2, "SU log"),
        ("adb_root", 3, "ADB root"),
        ("selinux_hide", 4, "SELinux hide"),
        ("web_su_prompt", 5, "Local web SU prompt"),
    ]
}

fn feature_id_by_name(name: &str) -> Option<u32> {
    feature_names()
        .iter()
        .find_map(|(feature_name, id, _)| (*feature_name == name).then_some(*id))
}

fn feature_state(name: &str, id: u32, description: &str) -> Value {
    let (value, supported) = ksucalls::get_feature(id).unwrap_or((0, false));
    json!({
        "name": name,
        "id": id,
        "description": description,
        "value": value,
        "enabled": value != 0,
        "supported": supported,
    })
}

fn handle_status() -> Value {
    let info = ksucalls::get_info();
    json!({
        "kernel_version": info.version,
        "kernel_flags": info.flags,
        "kernel_features": info.features,
        "kernel_uapi_version": info.uapi_version,
        "ksud_version_code": defs::VERSION_CODE.trim(),
        "ksud_version_name": defs::VERSION_NAME.trim(),
        "safe_mode": ksucalls::check_kernel_safemode(),
    })
}

fn handle_features() -> Value {
    let features = feature_names()
        .iter()
        .map(|(name, id, description)| feature_state(name, *id, description))
        .collect::<Vec<_>>();
    json!({ "features": features })
}

fn handle_feature_patch(req: &HttpRequest, feature_name: &str) -> Result<Value> {
    let id = feature_id_by_name(feature_name).context("unknown feature")?;
    let body = parse_json_body(req)?;
    let value = body
        .get("value")
        .and_then(Value::as_u64)
        .context("missing numeric value")?;
    ksucalls::set_feature(id, value).context("set feature")?;

    let mut config = crate::feature::load_binary_config().unwrap_or_default();
    config.insert(id, value);
    crate::feature::save_binary_config(&config).context("save feature config")?;

    Ok(json!({ "ok": true, "name": feature_name, "value": value }))
}

fn get_prop(name: &str) -> String {
    utils::getprop(name).unwrap_or_default()
}

fn read_trimmed(path: &str) -> String {
    fs::read_to_string(path)
        .map(|v| v.trim().to_string())
        .unwrap_or_default()
}

fn selinux_status() -> String {
    match read_trimmed("/sys/fs/selinux/enforce").as_str() {
        "1" => "enforcing".to_string(),
        "0" => "permissive".to_string(),
        _ => "unknown".to_string(),
    }
}

fn seccomp_status() -> String {
    let Ok(status) = fs::read_to_string("/proc/self/status") else {
        return "unknown".to_string();
    };
    status
        .lines()
        .find_map(|line| line.strip_prefix("Seccomp:").map(str::trim))
        .map_or("unknown", |value| match value {
            "0" => "disabled",
            "1" => "strict",
            "2" => "filter",
            _ => "unknown",
        })
        .to_string()
}

fn handle_home(state: &Arc<Mutex<WebState>>) -> Value {
    let info = ksucalls::get_info();
    let modules = module::collect_modules();
    let packages = package_index();
    json!({
        "status": {
            "kernelVersion": info.version,
            "kernelFlags": info.flags,
            "kernelFeatures": info.features,
            "kernelUapiVersion": info.uapi_version,
            "managerUapiVersion": crate::ksu_uapi::KERNEL_SU_UAPI_VERSION,
            "ksudVersionCode": defs::VERSION_CODE.trim(),
            "ksudVersionName": defs::VERSION_NAME.trim(),
            "safeMode": ksucalls::check_kernel_safemode(),
            "lkmMode": info.flags & crate::ksu_uapi::KSU_GET_INFO_FLAG_LKM != 0,
            "lateLoad": info.flags & crate::ksu_uapi::KSU_GET_INFO_FLAG_LATE_LOAD != 0,
            "manager": info.flags & crate::ksu_uapi::KSU_GET_INFO_FLAG_MANAGER != 0,
            "prBuild": info.flags & crate::ksu_uapi::KSU_GET_INFO_FLAG_PR_BUILD != 0,
        },
        "device": {
            "model": get_prop("ro.product.model"),
            "manufacturer": get_prop("ro.product.manufacturer"),
            "device": get_prop("ro.product.device"),
            "android": get_prop("ro.build.version.release"),
            "sdk": get_prop("ro.build.version.sdk"),
            "fingerprint": get_prop("ro.build.fingerprint"),
        },
        "security": {
            "selinux": selinux_status(),
            "seccomp": seccomp_status(),
        },
        "counts": {
            "superusers": ksucalls::get_allow_list_count(true),
            "apps": packages.len(),
            "modules": modules.len(),
            "pendingRequests": state.lock().expect("web state poisoned").pending.len(),
        },
        "links": [
            {"label": "KernelSU", "url": "https://kernelsu.org/"},
            {"label": "GitHub", "url": "https://github.com/tiann/KernelSU"}
        ]
    })
}

fn package_index() -> HashMap<u32, Vec<String>> {
    let mut by_uid: HashMap<u32, Vec<String>> = HashMap::new();
    let Ok(content) = fs::read_to_string("/data/system/packages.list") else {
        return by_uid;
    };
    for line in content.lines() {
        let mut parts = line.split_whitespace();
        let Some(pkg) = parts.next() else {
            continue;
        };
        let Some(uid) = parts.next().and_then(|v| v.parse::<u32>().ok()) else {
            continue;
        };
        by_uid.entry(uid).or_default().push(pkg.to_string());
    }
    by_uid
}

fn handle_apps() -> Value {
    let mut apps = package_index()
        .into_iter()
        .map(|(uid, mut packages)| {
            packages.sort();
            let package = packages.first().cloned().unwrap_or_default();
            let (mut profile, has_profile) = ksucalls::get_app_profile(&package, uid)
                .unwrap_or_else(|_| (ksucalls::AppProfile::default_for(&package, uid), false));
            profile.rules = profile_rules(&package);
            json!({
                "uid": uid,
                "label": package,
                "package": package,
                "packages": packages,
                "allowSu": profile.allow_su,
                "hasProfile": has_profile,
                "hasCustomProfile": profile.has_custom_profile(),
                "umountModules": profile.umount_modules,
                "uidShouldUmount": ksucalls::uid_should_umount(uid),
                "profile": profile_to_json(&profile, has_profile),
            })
        })
        .collect::<Vec<_>>();
    apps.sort_by(|a, b| {
        let left = a.get("label").and_then(Value::as_str).unwrap_or_default();
        let right = b.get("label").and_then(Value::as_str).unwrap_or_default();
        left.cmp(right)
    });
    json!({ "apps": apps })
}

fn handle_app_profile_get(req: &HttpRequest, uid: u32) -> Result<Value> {
    let package = query_param(&req.path, "package").context("missing package query")?;
    validate_package_name(&package)?;
    let (mut profile, has_profile) = ksucalls::get_app_profile(&package, uid)?;
    profile.rules = profile_rules(&package);
    Ok(json!({ "profile": profile_to_json(&profile, has_profile) }))
}

fn handle_app_profile_put(req: &HttpRequest, uid: u32) -> Result<Value> {
    let package = query_param(&req.path, "package").context("missing package query")?;
    validate_package_name(&package)?;
    let body = parse_json_body(req)?;
    let profile = profile_from_json(&body, uid, &package)?;
    if !profile.rules.trim().is_empty() {
        profile::set_sepolicy(profile.name.clone(), profile.rules.clone())
            .context("set profile sepolicy")?;
    }
    ksucalls::set_app_profile(&profile)?;
    Ok(json!({ "ok": true, "profile": profile_to_json(&profile, true) }))
}

fn settings_value() -> Value {
    let features = feature_names()
        .iter()
        .map(|(name, id, description)| feature_state(name, *id, description))
        .collect::<Vec<_>>();
    json!({
        "features": features,
        "defaultUmountModules": ksucalls::is_default_umount_modules().unwrap_or(true),
        "webadminAutostart": Path::new(AUTOSTART_PATH).exists(),
    })
}

fn handle_settings() -> Value {
    json!({ "settings": settings_value() })
}

fn persist_feature_value(id: u32, value: u64) -> Result<()> {
    ksucalls::set_feature(id, value).context("set feature")?;
    let mut config = crate::feature::load_binary_config().unwrap_or_default();
    config.insert(id, value);
    crate::feature::save_binary_config(&config).context("save feature config")?;
    Ok(())
}

fn handle_settings_patch(req: &HttpRequest) -> Result<Value> {
    let body = parse_json_body(req)?;
    if let Some(features) = body.get("features").and_then(Value::as_object) {
        for (name, value) in features {
            let id =
                feature_id_by_name(name).with_context(|| format!("unknown feature: {name}"))?;
            let enabled = value
                .as_bool()
                .or_else(|| value.as_u64().map(|v| v != 0))
                .context("feature values must be boolean or integer")?;
            persist_feature_value(id, u64::from(enabled))?;
            if name == "adb_root" {
                let _ = Command::new("setprop")
                    .args(["ctl.restart", "adbd"])
                    .stdin(Stdio::null())
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .status();
            }
        }
    }
    if let Some(default_umount) = bool_from_body(&body, "defaultUmountModules") {
        ksucalls::set_default_umount_modules(default_umount)?;
    }
    if let Some(autostart) = bool_from_body(&body, "webadminAutostart") {
        set_autostart(autostart)?;
    }
    Ok(json!({ "ok": true, "settings": settings_value() }))
}

fn string_from_nul(bytes: &[u8]) -> String {
    let end = bytes.iter().position(|b| *b == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).to_string()
}

fn read_u16_le(bytes: &[u8], off: usize) -> Option<u16> {
    Some(u16::from_le_bytes(
        bytes.get(off..off + 2)?.try_into().ok()?,
    ))
}

fn read_u32_le(bytes: &[u8], off: usize) -> Option<u32> {
    Some(u32::from_le_bytes(
        bytes.get(off..off + 4)?.try_into().ok()?,
    ))
}

fn read_u64_le(bytes: &[u8], off: usize) -> Option<u64> {
    Some(u64::from_le_bytes(
        bytes.get(off..off + 8)?.try_into().ok()?,
    ))
}

fn parse_event_header(bytes: &[u8]) -> Option<EventHeader> {
    Some(EventHeader {
        record_type: read_u16_le(bytes, 0)?,
        payload_len: read_u32_le(bytes, 4)?,
    })
}

fn parse_su_request(payload: &[u8], packages: &HashMap<u32, Vec<String>>) -> Option<SuRequest> {
    let request_id = read_u64_le(payload, 8)?;
    let deadline_ms = read_u64_le(payload, 16)?;
    let uid = read_u32_le(payload, 24)?;
    let euid = read_u32_le(payload, 28)?;
    let process_id = read_u32_le(payload, 32)?;
    let tgid = read_u32_le(payload, 36)?;
    let parent_pid = read_u32_le(payload, 40)?;
    let comm = string_from_nul(payload.get(44..60)?);
    let path = string_from_nul(payload.get(60..188)?);
    let argv = string_from_nul(payload.get(188..444)?);
    let packages = packages.get(&uid).cloned().unwrap_or_default();

    Some(SuRequest {
        request_id,
        deadline_ms,
        uid,
        euid,
        pid: process_id,
        tgid,
        ppid: parent_pid,
        comm,
        path,
        argv,
        packages,
    })
}

fn request_to_json(request: &SuRequest) -> Value {
    json!({
        "request_id": request.request_id,
        "deadline_ms": request.deadline_ms,
        "uid": request.uid,
        "euid": request.euid,
        "pid": request.pid,
        "tgid": request.tgid,
        "ppid": request.ppid,
        "comm": request.comm,
        "path": request.path,
        "argv": request.argv,
        "packages": request.packages,
    })
}

fn su_request_reader(state: &Arc<Mutex<WebState>>) {
    let fd = match ksucalls::get_su_request_fd() {
        Ok(fd) => fd,
        Err(err) => {
            log::warn!("webadmin: failed to open su request fd: {err}");
            return;
        }
    };
    let _owned_fd = unsafe { OwnedFd::from_raw_fd(fd) };
    let mut buf = [0u8; READ_BUF_SIZE];

    loop {
        let read_len =
            unsafe { libc::read(fd, buf.as_mut_ptr().cast::<libc::c_void>(), buf.len()) };
        if read_len < 0 {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            log::warn!("webadmin: su request fd read failed: {err}");
            break;
        }
        if read_len == 0 {
            log::warn!("webadmin: su request fd closed");
            break;
        }

        let mut offset = 0usize;
        let read_len = read_len as usize;
        while offset + EVENT_HEADER_SIZE <= read_len {
            let Some(header) = parse_event_header(&buf[offset..offset + EVENT_HEADER_SIZE]) else {
                break;
            };
            let frame_len = EVENT_HEADER_SIZE.saturating_add(header.payload_len as usize);
            if offset + frame_len > read_len {
                break;
            }
            let payload = &buf[offset + EVENT_HEADER_SIZE..offset + frame_len];
            if header.record_type != DROPPED_RECORD_TYPE {
                let packages = package_index();
                if let Some(request) = parse_su_request(payload, &packages) {
                    state
                        .lock()
                        .expect("web state poisoned")
                        .pending
                        .insert(request.request_id, request);
                }
            }
            offset += frame_len;
        }
    }
}

fn handle_su_requests(state: &Arc<Mutex<WebState>>) -> Value {
    let requests = state
        .lock()
        .expect("web state poisoned")
        .pending
        .values()
        .map(request_to_json)
        .collect::<Vec<_>>();
    json!({ "requests": requests })
}

fn handle_su_decision(
    req: &HttpRequest,
    state: &Arc<Mutex<WebState>>,
    request_id: u64,
) -> Result<Value> {
    let body = parse_json_body(req)?;
    let decision = body
        .get("decision")
        .and_then(Value::as_str)
        .context("missing decision")?;
    let allow = match decision {
        "allow" => true,
        "deny" => false,
        _ => bail!("decision must be allow or deny"),
    };
    let remember = body
        .get("remember")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let request = state
        .lock()
        .expect("web state poisoned")
        .pending
        .get(&request_id)
        .cloned()
        .context("request not found")?;

    if allow
        && remember
        && let Some(package) = request.packages.first()
    {
        ksucalls::set_app_profile_allow_su(package, request.uid, true)
            .with_context(|| format!("remember app profile for {package}"))?;
    }

    let respond_result = ksucalls::respond_su_request(request_id, allow);
    state
        .lock()
        .expect("web state poisoned")
        .pending
        .remove(&request_id);
    respond_result.context("respond su request")?;
    Ok(json!({ "ok": true, "request_id": request_id, "allow": allow, "remember": remember }))
}

fn handle_modules() -> Value {
    json!({ "modules": module::collect_modules() })
}

fn handle_module_action(action: &str, id: &str) -> Result<Value> {
    module::validate_module_id(id)?;
    utils::switch_mnt_ns(1).context("switch to global mount namespace")?;
    match action {
        "enable" => module::enable_module(id)?,
        "disable" => module::disable_module(id)?,
        "uninstall" => module::uninstall_module(id)?,
        "restore" => module::undo_uninstall_module(id)?,
        "action" => module::run_action(id)?,
        _ => bail!("unknown module action"),
    }
    Ok(json!({ "ok": true, "id": id, "action": action }))
}

fn handle_module_install(req: &HttpRequest) -> Result<Value> {
    let upload_path = req.upload_path.as_ref().context("missing upload")?;
    let metadata = fs::metadata(upload_path).context("stat upload")?;
    ensure!(metadata.len() > 0, "empty upload");
    ensure!(
        metadata.len() <= MODULE_UPLOAD_LIMIT as u64,
        "module zip too large"
    );
    utils::switch_mnt_ns(1).context("switch to global mount namespace")?;
    let zip = upload_path
        .to_str()
        .context("upload path is not valid utf-8")?
        .to_string();
    module::install_module(&zip)?;
    Ok(json!({ "ok": true, "action": "install" }))
}

fn content_type_for(path: &Path) -> &'static str {
    match path
        .extension()
        .and_then(|v| v.to_str())
        .unwrap_or_default()
    {
        "html" => "text/html; charset=utf-8",
        "css" => "text/css; charset=utf-8",
        "js" => "application/javascript; charset=utf-8",
        "json" => "application/json",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "svg" => "image/svg+xml",
        "webp" => "image/webp",
        "ico" => "image/x-icon",
        _ => "application/octet-stream",
    }
}

fn module_web_path(path: &str) -> Result<PathBuf> {
    let rest = path
        .strip_prefix("/module-web/")
        .context("missing module web prefix")?;
    let (id, rel) = rest.split_once('/').unwrap_or((rest, "index.html"));
    module::validate_module_id(id)?;
    let rel = if rel.is_empty() { "index.html" } else { rel };
    ensure!(!rel.starts_with('/'), "invalid module web path");
    let rel_path = Path::new(rel);
    ensure!(
        !rel_path
            .components()
            .any(|c| matches!(c, std::path::Component::ParentDir)),
        "invalid module web path"
    );
    Ok(Path::new(defs::MODULE_DIR)
        .join(id)
        .join(defs::MODULE_WEB_DIR)
        .join(rel_path))
}

fn route_api(req: &HttpRequest, state: &Arc<Mutex<WebState>>) -> Result<Value> {
    let path = req.path.split('?').next().unwrap_or(&req.path);
    match (req.method.as_str(), path) {
        ("GET", "/api/v1/home") => Ok(handle_home(state)),
        ("GET", "/api/v1/status") => Ok(handle_status()),
        ("GET", "/api/v1/features") => Ok(handle_features()),
        ("GET", "/api/v1/apps") => Ok(handle_apps()),
        ("GET", "/api/v1/modules") => Ok(handle_modules()),
        ("POST", "/api/v1/modules/install") => handle_module_install(req),
        ("GET", "/api/v1/settings") => Ok(handle_settings()),
        ("PATCH", "/api/v1/settings") => handle_settings_patch(req),
        ("GET", "/api/v1/su/requests") => Ok(handle_su_requests(state)),
        _ => {
            if let Some(rest) = path.strip_prefix("/api/v1/apps/") {
                let Some(uid_text) = rest.strip_suffix("/profile") else {
                    bail!("unknown app endpoint");
                };
                let uid = uid_text.parse::<u32>().context("invalid uid")?;
                return match req.method.as_str() {
                    "GET" => handle_app_profile_get(req, uid),
                    "PUT" => handle_app_profile_put(req, uid),
                    _ => bail!("unknown app profile method"),
                };
            }
            if req.method == "PATCH"
                && let Some(name) = path.strip_prefix("/api/v1/features/")
            {
                return handle_feature_patch(req, name);
            }
            if req.method == "POST"
                && let Some(rest) = path.strip_prefix("/api/v1/modules/")
            {
                let mut parts = rest.split('/');
                let id = parts.next().context("missing module id")?;
                let action = parts.next().context("missing module action")?;
                return handle_module_action(action, id);
            }
            if req.method == "POST"
                && let Some(rest) = path.strip_prefix("/api/v1/su/requests/")
            {
                let Some(id) = rest.strip_suffix("/decision") else {
                    bail!("unknown su request endpoint");
                };
                let request_id = id.parse::<u64>().context("invalid request id")?;
                return handle_su_decision(req, state, request_id);
            }
            bail!("not found")
        }
    }
}

fn handle_connection(
    mut stream: TcpStream,
    token: &str,
    state: &Arc<Mutex<WebState>>,
) -> Result<()> {
    let req = parse_http_request(&mut stream)?;
    let path = req.path.split('?').next().unwrap_or(&req.path);

    let result = if path.starts_with("/api/") {
        if !is_authorized(&req, token) {
            write_json(
                &mut stream,
                "401 Unauthorized",
                &api_error("unauthorized", "unauthorized"),
            )
        } else if matches!(req.method.as_str(), "POST" | "PATCH" | "PUT" | "DELETE")
            && !origin_allowed(&req)
        {
            write_json(
                &mut stream,
                "403 Forbidden",
                &api_error("bad origin", "bad_origin"),
            )
        } else {
            match route_api(&req, state) {
                Ok(value) => write_json(&mut stream, "200 OK", &value),
                Err(err) => write_json(
                    &mut stream,
                    "400 Bad Request",
                    &api_error(&err.to_string(), "bad_request"),
                ),
            }
        }
    } else if req.method == "GET" && (path == "/" || path == "/index.html") {
        write_response(
            &mut stream,
            "200 OK",
            "text/html; charset=utf-8",
            INDEX_HTML.as_bytes(),
        )
    } else if req.method == "GET" && path.starts_with("/module-web/") {
        match module_web_path(path).and_then(|file| {
            let body = fs::read(&file).with_context(|| format!("read {}", file.display()))?;
            Ok((content_type_for(&file), body))
        }) {
            Ok((content_type, body)) => write_response(&mut stream, "200 OK", content_type, &body),
            Err(_) => write_response(
                &mut stream,
                "404 Not Found",
                "text/plain; charset=utf-8",
                b"not found\n",
            ),
        }
    } else {
        write_response(
            &mut stream,
            "404 Not Found",
            "text/plain; charset=utf-8",
            b"not found\n",
        )
    };

    if let Some(upload_path) = &req.upload_path {
        let _ = fs::remove_file(upload_path);
    }
    result
}

pub fn serve() -> Result<()> {
    let token = read_or_create_token()?;
    fs::write(PID_PATH, format!("{}\n", std::process::id()))?;
    let state = Arc::new(Mutex::new(WebState::default()));
    let reader_state = Arc::clone(&state);
    std::thread::spawn(move || su_request_reader(&reader_state));

    let listener = TcpListener::bind(LISTEN_ADDR).with_context(|| format!("bind {LISTEN_ADDR}"))?;
    log::info!("webadmin listening at http://{LISTEN_ADDR}");
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                if let Err(err) = handle_connection(stream, &token, &state) {
                    log::warn!("webadmin request failed: {err:#}");
                }
            }
            Err(err) => log::warn!("webadmin accept failed: {err}"),
        }
    }
    Ok(())
}

const INDEX_HTML: &str = r#"<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
  <meta name="color-scheme" content="light">
  <title>KernelSU Web Manager</title>
  <style>
    :root{
      color-scheme:light;
      --bg:#f5f7fb;
      --surface:#ffffff;
      --surface-2:#eef3fa;
      --ink:#17202a;
      --muted:#687589;
      --line:#dfe6f0;
      --accent:#18a058;
      --blue:#2563eb;
      --warn:#c47a00;
      --danger:#d92d20;
      --shadow:0 10px 28px rgba(18,32,54,.09);
      --radius:8px;
      font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Arial,sans-serif;
    }
    *{box-sizing:border-box}
    html,body{min-height:100%;margin:0;background:var(--bg);color:var(--ink);letter-spacing:0}
    body{
      background:
        radial-gradient(circle at top left,rgba(24,160,88,.16),transparent 30rem),
        radial-gradient(circle at 90% 10%,rgba(37,99,235,.13),transparent 26rem),
        linear-gradient(180deg,#fbfcff 0,#f5f7fb 48%,#eef3fa 100%);
    }
    button,input,select,textarea{font:inherit}
    button{border:0;border-radius:8px;background:var(--surface-2);color:var(--ink);min-height:38px;padding:0 13px;cursor:pointer}
    button:hover{filter:brightness(.98)}
    button.primary{background:var(--accent);color:white}
    button.blue{background:var(--blue);color:white}
    button.danger{background:#fff0ee;color:var(--danger)}
    button.ghost{background:transparent;border:1px solid var(--line)}
    button.icon{width:38px;padding:0;display:inline-grid;place-items:center}
    button:disabled,input:disabled,select:disabled{opacity:.55;cursor:not-allowed}
    input,select,textarea{width:100%;border:1px solid var(--line);border-radius:8px;background:#fff;color:var(--ink);padding:10px 12px;outline:none}
    textarea{min-height:112px;resize:vertical;font-family:ui-monospace,SFMono-Regular,Consolas,monospace}
    input:focus,select:focus,textarea:focus{border-color:#8dc7a7;box-shadow:0 0 0 3px rgba(24,160,88,.14)}
    .app{display:grid;grid-template-columns:248px minmax(0,1fr);min-height:100vh}
    aside{position:sticky;top:0;height:100vh;padding:22px 16px;border-right:1px solid var(--line);background:rgba(255,255,255,.72);backdrop-filter:blur(18px)}
    .brand{display:flex;align-items:center;gap:12px;padding:8px 8px 20px}
    .logo{width:42px;height:42px;border-radius:8px;background:linear-gradient(145deg,var(--accent),#6ee7b7);display:grid;place-items:center;color:#fff;font-weight:800;box-shadow:var(--shadow)}
    .brand b{display:block;font-size:18px}.brand span{display:block;color:var(--muted);font-size:12px;margin-top:2px}
    nav{display:grid;gap:8px}
    nav button{height:46px;display:grid;grid-template-columns:28px 1fr auto;align-items:center;text-align:left;background:transparent;color:var(--muted)}
    nav button.active{background:#e9f7ef;color:#0f7a40;font-weight:700}
    .badge{min-width:24px;height:24px;border-radius:999px;background:#eef3fa;color:var(--muted);display:inline-grid;place-items:center;font-size:12px;padding:0 7px}
    .badge.hot{background:#fff0ee;color:var(--danger)}
    main{min-width:0;padding:26px 28px 96px}
    .topbar{display:grid;grid-template-columns:minmax(0,1fr) auto;gap:16px;align-items:center;margin-bottom:22px}
    h1{margin:0;font-size:30px;line-height:1.1}
    .subtitle{color:var(--muted);margin-top:6px}
    .auth{display:flex;gap:8px;align-items:center;min-width:min(420px,42vw)}
    .auth input{height:40px}
    section{display:none}.show{display:block}
    .grid{display:grid;gap:14px}
    .cols-3{grid-template-columns:repeat(3,minmax(0,1fr))}
    .cols-2{grid-template-columns:repeat(2,minmax(0,1fr))}
    .panel,.card{background:rgba(255,255,255,.82);border:1px solid var(--line);border-radius:8px;box-shadow:var(--shadow)}
    .panel{padding:18px}.card{padding:15px}
    .hero{display:grid;grid-template-columns:minmax(0,1.3fr) minmax(260px,.7fr);gap:14px;align-items:stretch}
    .status-card{min-height:214px;color:white;background:linear-gradient(135deg,#159957,#155799);border:0;display:flex;flex-direction:column;justify-content:space-between}
    .status-card .kicker{opacity:.86}.status-card h2{margin:8px 0 0;font-size:36px;line-height:1}
    .chips{display:flex;flex-wrap:wrap;gap:8px;margin-top:18px}.chip{border-radius:999px;background:rgba(255,255,255,.18);padding:7px 10px;font-size:13px}
    .metric{display:flex;justify-content:space-between;align-items:center;gap:12px}.metric b{font-size:26px}.muted{color:var(--muted)}.small{font-size:12px}
    .toolbar{display:grid;grid-template-columns:minmax(180px,1fr) auto auto;gap:10px;align-items:center;margin-bottom:14px}
    .list{display:grid;gap:10px}
    .row{display:grid;grid-template-columns:auto minmax(0,1fr) auto;gap:12px;align-items:center;background:rgba(255,255,255,.78);border:1px solid var(--line);border-radius:8px;padding:12px}
    .avatar{width:42px;height:42px;border-radius:8px;background:#e9f7ef;color:#0f7a40;display:grid;place-items:center;font-weight:800}
    .title{font-weight:700;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.meta{color:var(--muted);font-size:13px;margin-top:3px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
    .actions{display:flex;gap:8px;flex-wrap:wrap;justify-content:flex-end}
    .switch{position:relative;display:inline-flex;align-items:center;gap:10px;cursor:pointer}
    .switch input{position:absolute;opacity:0;width:1px;height:1px}
    .track{width:46px;height:26px;border-radius:999px;background:#d7e0eb;position:relative;transition:.18s}
    .track::after{content:"";position:absolute;width:22px;height:22px;left:2px;top:2px;border-radius:50%;background:#fff;box-shadow:0 2px 6px rgba(0,0,0,.22);transition:.18s}
    .switch input:checked + .track{background:var(--accent)}.switch input:checked + .track::after{transform:translateX(20px)}
    .settings-grid{display:grid;gap:14px}
    .setting-group{background:rgba(255,255,255,.72);border:1px solid var(--line);border-radius:8px;padding:4px 16px}
    .setting-group-head{display:flex;justify-content:space-between;gap:12px;align-items:flex-start;padding:12px 0;border-bottom:1px solid var(--line)}
    .setting-group-head h3{margin:0;font-size:16px}.setting-group-head p{margin:4px 0 0;color:var(--muted);font-size:13px}
    .setting{display:grid;grid-template-columns:minmax(0,1fr) auto;gap:12px;align-items:center;padding:14px 0;border-bottom:1px solid var(--line)}
    .setting:last-child{border-bottom:0}
    .setting.unsupported{opacity:.62}
    .setting.saving{pointer-events:none;opacity:.72}
    .setting .status{display:inline-flex;align-items:center;margin-top:7px;border-radius:999px;background:#eef3fa;color:var(--muted);font-size:12px;padding:4px 8px}
    .setting.unsupported .status{background:#fff7e6;color:var(--warn)}
    .install{display:flex;gap:8px;align-items:center;flex-wrap:wrap}
    .empty{padding:28px;text-align:center;color:var(--muted);border:1px dashed var(--line);border-radius:8px;background:rgba(255,255,255,.5)}
    .toast{position:fixed;right:18px;bottom:18px;z-index:50;display:grid;gap:8px}
    .toast div{background:#17202a;color:#fff;padding:12px 14px;border-radius:8px;box-shadow:var(--shadow);max-width:min(430px,calc(100vw - 36px))}
    .toast div.error{background:#8f1d16}.toast div.success{background:#0f7a40}
    dialog{border:0;border-radius:8px;padding:0;width:min(760px,calc(100vw - 28px));box-shadow:0 28px 80px rgba(0,0,0,.28)}
    dialog::backdrop{background:rgba(14,23,38,.42);backdrop-filter:blur(4px)}
    .modal-head,.modal-foot{display:flex;justify-content:space-between;gap:12px;align-items:center;padding:16px 18px;border-bottom:1px solid var(--line)}
    .modal-foot{border-top:1px solid var(--line);border-bottom:0;justify-content:flex-end}
    .modal-body{padding:18px;max-height:min(72vh,720px);overflow:auto}
    .form-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:12px}.form-grid .wide{grid-column:1/-1}
    label span{display:block;font-size:12px;color:var(--muted);margin-bottom:6px}
    .mobile-tabs{display:none}
    @media(max-width:900px){
      .app{display:block}aside{display:none}main{padding:18px 14px 86px}.topbar{grid-template-columns:1fr}.auth{min-width:0}.hero,.cols-3,.cols-2{grid-template-columns:1fr}.toolbar{grid-template-columns:1fr 1fr}.toolbar input{grid-column:1/-1}
      .row{grid-template-columns:auto minmax(0,1fr)}.actions{grid-column:1/-1;justify-content:stretch}.actions button{flex:1}
      .form-grid{grid-template-columns:1fr}.mobile-tabs{position:fixed;z-index:40;display:grid;grid-template-columns:repeat(4,1fr);gap:6px;left:10px;right:10px;bottom:10px;background:rgba(255,255,255,.88);border:1px solid var(--line);border-radius:8px;padding:8px;backdrop-filter:blur(18px);box-shadow:var(--shadow)}
      .mobile-tabs button{font-size:12px;padding:0 6px}.mobile-tabs button.active{background:#e9f7ef;color:#0f7a40;font-weight:700}
    }
  </style>
</head>
<body>
  <div class="app">
    <aside>
      <div class="brand"><div class="logo">K</div><div><b>KernelSU</b><span>Web Manager</span></div></div>
      <nav id="sideTabs"></nav>
    </aside>
    <main>
      <div class="topbar">
        <div><h1 id="title">Home</h1><div id="subtitle" class="subtitle">Device and KernelSU status</div></div>
        <div class="auth">
          <input id="token" type="password" placeholder="Bearer token">
          <button id="saveToken" class="primary">Save</button>
          <button id="refresh" class="ghost icon" title="Refresh">R</button>
        </div>
      </div>

      <section id="home" class="show">
        <div class="hero">
          <div id="homeStatus" class="panel status-card"></div>
          <div class="grid">
            <div class="panel"><div class="metric"><span>Superuser</span><b id="countSu">0</b></div></div>
            <div class="panel"><div class="metric"><span>Modules</span><b id="countModules">0</b></div></div>
            <div class="panel"><div class="metric"><span>Apps</span><b id="countApps">0</b></div></div>
          </div>
        </div>
        <div class="grid cols-2" style="margin-top:14px">
          <div class="panel"><h3>Device</h3><div id="deviceInfo" class="grid"></div></div>
          <div class="panel"><h3>Security</h3><div id="securityInfo" class="grid"></div></div>
        </div>
      </section>

      <section id="superuser">
        <div class="toolbar">
          <input id="appSearch" placeholder="Search app or package">
          <select id="appFilter"><option value="all">All apps</option><option value="root">Root allowed</option><option value="custom">Custom profile</option><option value="umount">Will umount</option></select>
          <button id="loadRequests" class="ghost">Requests <span id="requestBadge" class="badge">0</span></button>
        </div>
        <div id="requests" class="list" style="margin-bottom:14px"></div>
        <div id="apps" class="list"></div>
      </section>

      <section id="module">
        <div class="toolbar">
          <input id="moduleSearch" placeholder="Search module">
          <div class="install"><input id="zipFile" type="file" accept=".zip,application/zip"><button id="installZip" class="blue">Install</button></div>
          <button id="reloadModules" class="ghost">Reload</button>
        </div>
        <div id="modules" class="list"></div>
      </section>

      <section id="settings">
        <div class="panel">
          <div id="settingsList"></div>
        </div>
      </section>
    </main>
  </div>
  <div id="mobileTabs" class="mobile-tabs"></div>
  <div id="toast" class="toast"></div>

  <dialog id="profileDialog">
    <div class="modal-head"><strong id="profileTitle">App profile</strong><button class="icon ghost" onclick="profileDialog.close()">X</button></div>
    <form id="profileForm">
      <div class="modal-body">
        <div class="form-grid">
          <label class="wide"><span>Package</span><input name="name" readonly></label>
          <label><span>Current UID</span><input name="currentUid" readonly></label>
          <label><span>Namespace</span><select name="namespace"><option value="0">Inherited</option><option value="1">Global</option><option value="2">Individual</option></select></label>
          <label class="wide switch"><input name="allowSu" type="checkbox"><span class="track"></span><strong>Allow root access</strong></label>
          <label class="wide switch"><input name="rootUseDefault" type="checkbox"><span class="track"></span><strong>Use default root profile</strong></label>
          <label><span>Root UID</span><input name="uid" type="number"></label>
          <label><span>Root GID</span><input name="gid" type="number"></label>
          <label><span>Groups, comma separated</span><input name="groups"></label>
          <label><span>Capabilities, comma separated</span><input name="capabilities"></label>
          <label class="wide"><span>SELinux context</span><input name="context"></label>
          <label class="wide"><span>Root template</span><input name="rootTemplate"></label>
          <label class="wide switch"><input name="nonRootUseDefault" type="checkbox"><span class="track"></span><strong>Use default non-root profile</strong></label>
          <label class="wide switch"><input name="umountModules" type="checkbox"><span class="track"></span><strong>Unmount modules for this app</strong></label>
          <label><span>Flags</span><input name="flags" type="number"></label>
          <label class="wide"><span>SEPolicy rules</span><textarea name="rules" spellcheck="false"></textarea></label>
        </div>
      </div>
      <div class="modal-foot"><button type="button" class="ghost" onclick="profileDialog.close()">Cancel</button><button class="primary">Save profile</button></div>
    </form>
  </dialog>

  <dialog id="confirmDialog">
    <div class="modal-head"><strong id="confirmTitle">Confirm</strong></div>
    <div class="modal-body"><p id="confirmText"></p></div>
    <div class="modal-foot"><button id="confirmCancel" class="ghost">Cancel</button><button id="confirmOk" class="danger">Continue</button></div>
  </dialog>

  <script>
    const $ = (id) => document.getElementById(id);
    const tabs = [
      ['home','H','Home','Device and KernelSU status'],
      ['superuser','S','Superuser','Apps, profiles, and pending SU requests'],
      ['module','M','Module','Installed modules and ZIP install'],
      ['settings','T','Settings','KernelSU feature controls']
    ];
      const state = {home:null, apps:[], modules:[], settings:null, profile:null, savingSetting:null};
    let activeTab = localStorage.getItem('ksu.web.tab') || 'home';
    $('token').value = localStorage.getItem('ksu.web.token') || '';

    function esc(v){return String(v ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));}
    function initials(v){return (String(v || 'K').split(/[._-]/).filter(Boolean).slice(0,2).map(s=>s[0]).join('') || 'K').toUpperCase();}
    function csv(v){return String(v || '').split(',').map(s=>s.trim()).filter(Boolean).map(Number).filter(n=>Number.isFinite(n));}
    function toast(text,type=''){const el=document.createElement('div');el.textContent=text;if(type)el.className=type;$('toast').append(el);setTimeout(()=>el.remove(),4200);}
    function confirmAction(title,text){return new Promise(resolve=>{confirmTitle.textContent=title;confirmText.textContent=text;confirmDialog.showModal();confirmCancel.onclick=()=>{confirmDialog.close();resolve(false)};confirmOk.onclick=()=>{confirmDialog.close();resolve(true)}})}
    async function api(path,opt={}){
      const headers = opt.headers || {};
      if (!(opt.body instanceof File) && !(opt.body instanceof Blob) && opt.body && !headers['Content-Type']) headers['Content-Type']='application/json';
      headers.Authorization = 'Bearer ' + $('token').value.trim();
      const res = await fetch(path,{...opt,headers});
      const type = res.headers.get('content-type') || '';
      const data = type.includes('json') ? await res.json() : {};
      if(!res.ok) throw new Error(data.error || res.statusText);
      return data;
    }
    $('saveToken').onclick=()=>{localStorage.setItem('ksu.web.token',$('token').value.trim());toast('Token saved');refresh()};
    $('refresh').onclick=()=>refresh(true);

    function buildTabs(){
      const html = tabs.map(([id,icon,label])=>`<button data-tab="${id}"><span>${icon}</span><span>${label}</span><span id="badge-${id}" class="badge"></span></button>`).join('');
      $('sideTabs').innerHTML = html; $('mobileTabs').innerHTML = html;
      document.querySelectorAll('[data-tab]').forEach(btn=>btn.onclick=()=>setTab(btn.dataset.tab));
      setTab(activeTab,false);
    }
    function setTab(id,load=true){
      activeTab=id; localStorage.setItem('ksu.web.tab',id);
      document.querySelectorAll('section').forEach(s=>s.classList.toggle('show',s.id===id));
      document.querySelectorAll('[data-tab]').forEach(b=>b.classList.toggle('active',b.dataset.tab===id));
      const tab=tabs.find(t=>t[0]===id); $('title').textContent=tab[2]; $('subtitle').textContent=tab[3];
      if(load) refresh();
    }

    function kv(label,value){return `<div class="metric"><span>${esc(label)}</span><b class="small">${esc(value || 'unknown')}</b></div>`}
    async function loadHome(){
      try{
        state.home = await api('/api/v1/home');
        const h=state.home, s=h.status, c=h.counts;
        homeStatus.innerHTML = `<div><div class="kicker">KernelSU status</div><h2>${s.safeMode?'Safe mode':'Working'}</h2><div class="chips"><span class="chip">Kernel ${esc(s.kernelVersion)}</span><span class="chip">ksud ${esc(s.ksudVersionCode)}</span><span class="chip">${s.lkmMode?'LKM':'GKI'}</span><span class="chip">${s.lateLoad?'Late load':'Normal load'}</span></div></div><div class="small">UAPI ${esc(s.kernelUapiVersion)} / ${esc(s.managerUapiVersion)}</div>`;
        countSu.textContent=c.superusers; countModules.textContent=c.modules; countApps.textContent=c.apps;
        $('badge-superuser').textContent = c.pendingRequests || '';
        $('badge-superuser').classList.toggle('hot', (c.pendingRequests||0)>0);
        deviceInfo.innerHTML = kv('Model',`${h.device.manufacturer || ''} ${h.device.model || ''}`)+kv('Device',h.device.device)+kv('Android',`${h.device.android || ''} SDK ${h.device.sdk || ''}`)+kv('Fingerprint',h.device.fingerprint);
        securityInfo.innerHTML = kv('SELinux',h.security.selinux)+kv('Seccomp',h.security.seccomp)+kv('Safe mode',s.safeMode?'enabled':'off')+kv('Manager UID',s.manager?'detected':'unknown');
      }catch(e){toast(e.message,'error')}
    }

    function filteredApps(){
      const q=appSearch.value.toLowerCase(), f=appFilter.value;
      return state.apps.filter(a=>{
        const hay=[a.label,a.package,...(a.packages||[])].join(' ').toLowerCase();
        if(q && !hay.includes(q)) return false;
        if(f==='root') return a.allowSu;
        if(f==='custom') return a.hasCustomProfile;
        if(f==='umount') return a.uidShouldUmount;
        return true;
      });
    }
    async function loadApps(){
      try{ const data=await api('/api/v1/apps'); state.apps=data.apps||[]; renderApps(); }
      catch(e){toast(e.message,'error'); renderApps();}
      loadRequests();
    }
    function renderApps(){
      const list=filteredApps();
      $('badge-superuser').textContent=state.apps.filter(a=>a.allowSu).length || '';
      list.length ? appsEl(list) : $('apps').innerHTML='<div class="empty">No apps found.</div>';
    }
    function appsEl(items){
      $('apps').innerHTML = items.map(a=>`<div class="row"><div class="avatar">${esc(initials(a.label))}</div><div><div class="title">${esc(a.label)}</div><div class="meta">uid ${esc(a.uid)} - ${(a.packages||[]).map(esc).join(', ')}</div><div class="chips"><span class="chip">${a.allowSu?'Root allowed':'No root'}</span>${a.hasCustomProfile?'<span class="chip">Custom</span>':''}${a.uidShouldUmount?'<span class="chip">Umount</span>':''}</div></div><div class="actions"><button class="ghost" onclick="openProfile(${a.uid},decodeURIComponent('${encodeURIComponent(a.package||'')}'))">Profile</button></div></div>`).join('');
    }
    appSearch.oninput=renderApps; appFilter.onchange=renderApps; loadRequests.onclick=loadRequests;

    async function loadRequests(){
      try{
        const data=await api('/api/v1/su/requests'); const requests=data.requests||[];
        $('requestBadge').textContent=requests.length; $('badge-superuser').textContent=requests.length || state.apps.filter(a=>a.allowSu).length || '';
        $('badge-superuser').classList.toggle('hot',requests.length>0);
        $('requests').innerHTML=requests.map(r=>`<div class="row"><div class="avatar">SU</div><div><div class="title">${esc(r.comm || r.path)}</div><div class="meta">uid ${esc(r.uid)} - ${(r.packages||[]).map(esc).join(', ')}</div><div class="meta">${esc(r.argv || '')}</div></div><div class="actions"><button class="primary" onclick="decide(${r.request_id},true)">Allow</button><button class="ghost" onclick="decide(${r.request_id},true,true)">Allow and remember</button><button class="danger" onclick="decide(${r.request_id},false)">Deny</button></div></div>`).join('');
      }catch(e){toast(e.message,'error')}
    }
    async function decide(id,allow,remember=false){
      if(!await confirmAction('SU request', `${allow?'Allow':'Deny'} this request${remember?' and remember it':''}?`)) return;
      await api(`/api/v1/su/requests/${id}/decision`,{method:'POST',body:JSON.stringify({decision:allow?'allow':'deny',remember})});
      loadRequests(); loadApps();
    }

    async function openProfile(uid,pkg){
      try{
        const data=await api(`/api/v1/apps/${uid}/profile?package=${encodeURIComponent(pkg)}`);
        state.profile=data.profile; fillProfile(data.profile); profileDialog.showModal();
      }catch(e){toast(e.message,'error')}
    }
    function fillProfile(p){
      profileTitle.textContent = p.name;
      const f=profileForm.elements;
      for(const key of ['name','currentUid','uid','gid','context','namespace','rootTemplate','rules','flags']) f[key].value = p[key] ?? '';
      f.allowSu.checked=!!p.allowSu; f.rootUseDefault.checked=!!p.rootUseDefault; f.nonRootUseDefault.checked=!!p.nonRootUseDefault; f.umountModules.checked=!!p.umountModules;
      f.groups.value=(p.groups||[]).join(','); f.capabilities.value=(p.capabilities||[]).join(',');
    }
    profileForm.onsubmit=async(ev)=>{
      ev.preventDefault();
      if(!state.profile) return;
      if(!await confirmAction('Save app profile','This changes root or mount policy for the selected app. Continue?')) return;
      const f=profileForm.elements;
      const body={name:f.name.value,currentUid:Number(f.currentUid.value),allowSu:f.allowSu.checked,rootUseDefault:f.rootUseDefault.checked,rootTemplate:f.rootTemplate.value||null,uid:Number(f.uid.value||0),gid:Number(f.gid.value||0),groups:csv(f.groups.value),capabilities:csv(f.capabilities.value),context:f.context.value,namespace:Number(f.namespace.value),nonRootUseDefault:f.nonRootUseDefault.checked,umountModules:f.umountModules.checked,rules:f.rules.value,flags:Number(f.flags.value||0)};
      try{await api(`/api/v1/apps/${body.currentUid}/profile?package=${encodeURIComponent(body.name)}`,{method:'PUT',body:JSON.stringify(body)}); profileDialog.close(); toast('Profile saved','success'); loadApps();}
      catch(e){toast(e.message,'error')}
    };

    function filteredModules(){
      const q=moduleSearch.value.toLowerCase();
      return state.modules.filter(m=>!q || [m.id,m.name,m.author,m.description].join(' ').toLowerCase().includes(q));
    }
    async function loadModules(){
      try{const data=await api('/api/v1/modules'); state.modules=data.modules||[]; renderModules();}
      catch(e){toast(e.message,'error'); renderModules();}
    }
    function renderModules(){
      const list=filteredModules(); $('badge-module').textContent=state.modules.length || '';
      $('modules').innerHTML=list.length?list.map(m=>{
        const id=String(m.id||''), enabled=m.enabled==='true', removed=m.remove==='true', web=m.web==='true', action=m.action==='true';
        const safeId=esc(id), urlId=encodeURIComponent(id);
        return `<div class="row"><div class="avatar">M</div><div><div class="title">${esc(m.name||m.id)}</div><div class="meta">${esc(m.version||'')} ${m.author?'by '+esc(m.author):''}</div><div class="meta">${esc(m.description||'')}</div><div class="chips"><span class="chip">${enabled?'Enabled':'Disabled'}</span>${removed?'<span class="chip">Remove on reboot</span>':''}${m.update==='true'?'<span class="chip">Updated</span>':''}</div></div><div class="actions"><button class="ghost" onclick="moduleAction('${safeId}','${enabled?'disable':'enable'}')">${enabled?'Disable':'Enable'}</button>${removed?`<button class="ghost" onclick="moduleAction('${safeId}','restore')">Restore</button>`:`<button class="danger" onclick="moduleAction('${safeId}','uninstall')">Uninstall</button>`}${action?`<button class="blue" onclick="moduleAction('${safeId}','action')">Run</button>`:''}${web?`<button class="ghost" onclick="window.open('/module-web/${urlId}/','_blank')">WebUI</button>`:''}</div></div>`
      }).join(''):'<div class="empty">No modules found.</div>';
    }
    moduleSearch.oninput=renderModules; reloadModules.onclick=loadModules;
    async function moduleAction(id,action){
      const dangerous=['uninstall','action'].includes(action);
      if(dangerous && !await confirmAction('Module action', `${action} module ${id}?`)) return;
      try{await api(`/api/v1/modules/${encodeURIComponent(id)}/${action}`,{method:'POST',body:'{}'}); toast('Module updated','success'); loadModules(); loadHome();}
      catch(e){toast(e.message,'error')}
    }
    installZip.onclick=async()=>{
      const file=zipFile.files[0]; if(!file){toast('Choose a ZIP first');return}
      if(!await confirmAction('Install module',`Install ${file.name}?`)) return;
      try{await api('/api/v1/modules/install',{method:'POST',body:file,headers:{'Content-Type':'application/zip'}}); toast('Module installed','success'); zipFile.value=''; loadModules(); loadHome();}
      catch(e){toast(e.message,'error')}
    };

    const featureLabels={su_compat:'SU compatibility',kernel_umount:'Kernel umount',sulog:'SU log',adb_root:'ADB root',selinux_hide:'SELinux hide',web_su_prompt:'Web SU prompt'};
    async function loadSettings(){
      try{const data=await api('/api/v1/settings'); state.settings=data.settings; renderSettings();}
      catch(e){toast(e.message,'error'); renderSettings();}
    }
    function renderSettings(){
      const s=state.settings; if(!s){$('settingsList').innerHTML='<div class="empty">Settings unavailable.</div>';return}
      const features=s.features||[];
      const featureRows=features.map(f=>settingRow(featureLabels[f.name]||f.name,f.description,`feature:${f.name}`,!!f.enabled,!f.supported)).join('');
      const policyRows=settingRow('Default umount modules','Unmount modules for non-root apps unless overridden','defaultUmountModules',!!s.defaultUmountModules,false)+settingRow('Webadmin autostart','Start web manager after boot','webadminAutostart',!!s.webadminAutostart,false);
      $('settingsList').innerHTML=`<div class="settings-grid"><div class="setting-group"><div class="setting-group-head"><div><h3>Kernel features</h3><p>Runtime switches exposed by the active KernelSU kernel.</p></div><span class="badge">${features.filter(f=>f.enabled).length}/${features.length}</span></div>${featureRows||'<div class="empty">No kernel features reported.</div>'}</div><div class="setting-group"><div class="setting-group-head"><div><h3>Web and default policy</h3><p>Local web manager startup and default non-root mount behavior.</p></div></div>${policyRows}</div></div>`;
      $('settingsList').querySelectorAll('input[type=checkbox]').forEach(input=>input.onchange=()=>patchSetting(input.dataset.key,input.checked));
    }
    function settingRow(title,desc,key,checked,disabled){const saving=state.savingSetting===key;const status=disabled?'Unsupported':(saving?'Saving...':(checked?'Enabled':'Disabled'));return `<div class="setting ${disabled?'unsupported':''} ${saving?'saving':''}"><div><div class="title">${esc(title)}</div><div class="meta">${esc(desc||'')}</div><span class="status">${esc(status)}</span></div><label class="switch"><input data-key="${esc(key)}" type="checkbox" ${checked?'checked':''} ${(disabled||saving)?'disabled':''}><span class="track"></span></label></div>`}
    async function patchSetting(key,enabled){
      if(!await confirmAction('Change setting',`Set ${key.replace('feature:','')} to ${enabled?'on':'off'}?`)){loadSettings();return}
      const body = key.startsWith('feature:') ? {features:{[key.slice(8)]:enabled}} : {[key]:enabled};
      state.savingSetting=key; renderSettings();
      try{const data=await api('/api/v1/settings',{method:'PATCH',body:JSON.stringify(body)}); state.settings=data.settings; toast('Setting saved','success');}
      catch(e){toast(e.message,'error');}
      finally{state.savingSetting=null; loadSettings();}
    }

    function refresh(force=false){
      if(activeTab==='home') loadHome();
      if(activeTab==='superuser') loadApps();
      if(activeTab==='module') loadModules();
      if(activeTab==='settings') loadSettings();
    }
    buildTabs();
    refresh();
    setInterval(()=>{ if(activeTab==='superuser') loadRequests(); },3000);
  </script>
</body>
</html>
"#;

#[allow(dead_code)]
const _OLD_INDEX_HTML: &str = r#"<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
  <meta name="color-scheme" content="light dark">
  <title>KernelSU Web Admin</title>
  <style>
    :root{
      color-scheme:light dark;
      --bg:#07100d;
      --ink:#101418;
      --muted:#5e6b7d;
      --hairline:rgba(23,32,51,.08);
      --glass:rgba(255,255,255,.72);
      --glass-strong:rgba(255,255,255,.88);
      --fill:rgba(255,255,255,.46);
      --field:rgba(255,255,255,.58);
      --control:rgba(255,255,255,.88);
      --accent:#00c781;
      --accent-2:#2f7cff;
      --warn:#f59e0b;
      --danger:#ef4444;
      --violet:#7c3aed;
      --shadow:0 18px 50px rgba(0,0,0,.22);
      --radius:18px;
      font-family:-apple-system,BlinkMacSystemFont,"SF Pro Text","Segoe UI",Roboto,Arial,sans-serif;
    }
    @media(prefers-color-scheme:dark){
      :root{
        --bg:#07100d;
        --ink:#f7fbf8;
        --muted:#9fb2aa;
        --hairline:rgba(255,255,255,.14);
        --glass:rgba(12,22,18,.76);
        --glass-strong:rgba(16,28,24,.92);
        --fill:rgba(255,255,255,.075);
        --field:rgba(255,255,255,.11);
        --control:rgba(255,255,255,.10);
        --shadow:0 20px 58px rgba(0,0,0,.38);
      }
    }
    *{box-sizing:border-box}
    html{min-height:100%;background:var(--bg);overflow-x:hidden}
    body{
      min-height:100vh;
      margin:0;
      color:var(--ink);
      background:
        linear-gradient(135deg,rgba(0,199,129,.12),transparent 34%),
        linear-gradient(225deg,rgba(47,124,255,.14),transparent 38%),
        var(--bg);
      letter-spacing:0;
      overflow-x:hidden;
    }
    body::before{
      content:"";
      position:fixed;
      inset:0;
      pointer-events:none;
      background:
        linear-gradient(rgba(255,255,255,.045) 1px,transparent 1px),
        linear-gradient(90deg,rgba(255,255,255,.045) 1px,transparent 1px),
        linear-gradient(120deg,transparent 0 58%,rgba(0,199,129,.10) 58% 59%,transparent 59%),
        linear-gradient(60deg,transparent 0 44%,rgba(47,124,255,.12) 44% 45%,transparent 45%);
      background-size:44px 44px,44px 44px,100% 100%,100% 100%;
      opacity:.82;
    }
    body::after{
      content:"";
      position:fixed;
      inset:0;
      pointer-events:none;
      background:linear-gradient(180deg,rgba(7,16,13,.04),rgba(7,16,13,.72));
      opacity:.9;
    }
    button,input{font:inherit}
    button{
      min-height:38px;
      border:1px solid var(--hairline);
      border-radius:12px;
      color:var(--ink);
      background:var(--control);
      box-shadow:0 1px 0 rgba(255,255,255,.34) inset;
      cursor:pointer;
      transition:transform .16s ease,background .16s ease,border-color .16s ease,opacity .16s ease;
      -webkit-tap-highlight-color:transparent;
    }
    button:active{transform:scale(.97)}
    button:disabled{cursor:not-allowed;opacity:.52}
    input{
      width:100%;
      min-height:42px;
      border:1px solid var(--hairline);
      border-radius:12px;
      padding:10px 12px;
      color:var(--ink);
      background:var(--field);
      outline:none;
      box-shadow:0 1px 0 rgba(255,255,255,.4) inset;
    }
    input:focus{border-color:color-mix(in srgb,var(--accent),white 28%);box-shadow:0 0 0 4px color-mix(in srgb,var(--accent),transparent 78%)}
    .app{
      position:relative;
      z-index:1;
      display:grid;
      grid-template-columns:136px minmax(0,1fr);
      min-height:100vh;
    }
    .sidebar{
      display:grid;
      grid-template-rows:auto 1fr;
      gap:24px;
      position:sticky;
      top:0;
      height:100vh;
      padding:22px 12px;
      border-right:1px solid var(--hairline);
      background:rgba(6,15,12,.68);
      backdrop-filter:blur(14px) saturate(1.1);
      -webkit-backdrop-filter:blur(14px) saturate(1.1);
    }
    .brand{display:block;text-align:center}
    .eyebrow{margin:0 0 6px;color:var(--muted);font-size:12px;font-weight:700;text-transform:uppercase}
    h1{margin:0;font-size:25px;line-height:1.05;font-weight:760;letter-spacing:0}
    .auth-pill{
      display:inline-flex;
      gap:7px;
      align-items:center;
      min-height:28px;
      margin-top:12px;
      padding:5px 9px;
      border:1px solid var(--hairline);
      border-radius:999px;
      background:var(--fill);
      color:var(--muted);
      font-size:12px;
      font-weight:650;
    }
    .dot{width:8px;height:8px;border-radius:50%;background:var(--danger);box-shadow:0 0 0 3px color-mix(in srgb,var(--danger),transparent 82%)}
    .auth-pill.ready .dot{background:var(--accent-2);box-shadow:0 0 0 3px color-mix(in srgb,var(--accent-2),transparent 82%)}
    nav{display:grid;align-content:start;gap:12px}
    nav button{
      position:relative;
      display:flex;
      flex-direction:column;
      align-items:center;
      justify-content:center;
      width:78px;
      min-height:76px;
      margin:0 auto;
      padding:8px 6px;
      text-align:center;
      color:var(--muted);
      background:transparent;
      border-color:transparent;
      box-shadow:none;
    }
    nav button.active{
      color:var(--ink);
      background:linear-gradient(180deg,rgba(0,199,129,.22),rgba(47,124,255,.12));
      border-color:rgba(0,199,129,.32);
      box-shadow:0 12px 30px rgba(0,0,0,.22),0 1px 0 rgba(255,255,255,.16) inset;
    }
    .nav-glyph{
      display:grid;
      place-items:center;
      width:42px;
      height:42px;
      border-radius:14px;
      color:color-mix(in srgb,var(--ink),transparent 6%);
      background:rgba(255,255,255,.10);
      font-size:18px;
      font-weight:800;
    }
    nav button.active .nav-glyph{color:#06100d;background:var(--accent)}
    .nav-count{position:absolute;transform:translate(28px,-22px);min-width:18px;text-align:center;font-size:12px;font-weight:800;color:var(--muted)}
    .content{
      min-width:0;
      padding:76px clamp(20px,2vw,38px) 142px;
    }
    .topbar{
      position:sticky;
      top:0;
      z-index:3;
      display:flex;
      align-items:center;
      justify-content:space-between;
      gap:12px;
      min-height:58px;
      margin:-76px calc(clamp(20px,2vw,38px) * -1) 24px;
      padding:14px clamp(20px,2vw,38px);
      border-bottom:0;
      border-bottom:1px solid var(--hairline);
      background:rgba(7,16,13,.76);
      backdrop-filter:blur(18px) saturate(1.2);
      -webkit-backdrop-filter:blur(18px) saturate(1.2);
    }
    .topbar-title{font-size:28px;font-weight:850}
    .topbar-title::after{content:" / KernelSU";margin-left:8px;color:var(--accent);font-size:18px;font-weight:800}
    .top-actions{display:flex;gap:8px;align-items:center}
    .icon-button{display:grid;place-items:center;width:44px;height:44px;padding:0;border-radius:12px;font-weight:800}
    .primary{border-color:color-mix(in srgb,var(--accent),white 30%);background:linear-gradient(180deg,color-mix(in srgb,var(--accent),white 10%),var(--accent));color:#03100b}
    .ok{border-color:color-mix(in srgb,var(--accent-2),white 30%);background:linear-gradient(180deg,color-mix(in srgb,var(--accent-2),white 12%),var(--accent-2));color:white}
    .danger{border-color:color-mix(in srgb,var(--danger),white 26%);background:linear-gradient(180deg,color-mix(in srgb,var(--danger),white 10%),var(--danger));color:white}
    section{display:none;animation:lift .22s ease both}
    section.active{display:block}
    @keyframes lift{from{opacity:.65;transform:translateY(8px)}to{opacity:1;transform:none}}
    @media(prefers-reduced-motion:reduce){*,section{animation:none!important;transition:none!important}}
    .hero{
      display:grid;
      grid-template-columns:minmax(0,1fr) minmax(360px,.44fr);
      gap:18px;
      align-items:stretch;
      max-width:1840px;
      margin:0 auto 18px;
    }
    .panel,.item,.empty,.notice{
      border:1px solid var(--hairline);
      border-radius:var(--radius);
      background:var(--glass);
      box-shadow:var(--shadow),0 1px 0 rgba(255,255,255,.12) inset;
      backdrop-filter:blur(18px) saturate(1.2);
      -webkit-backdrop-filter:blur(18px) saturate(1.2);
      overflow:hidden;
    }
    .panel,.item{position:relative}
    .panel,.item,.slider-card,.wide-meter{min-width:0}
    .panel::before,.item::before,.empty::before,.notice::before{
      content:"";
      position:absolute;
      inset:0 0 auto 0;
      height:1px;
      background:rgba(255,255,255,.18);
    }
    .panel{padding:28px}
    .panel.hero-card{
      background:
        linear-gradient(135deg,rgba(0,199,129,.24),transparent 38%),
        linear-gradient(225deg,rgba(47,124,255,.18),transparent 44%),
        var(--glass-strong);
    }
    .headline{display:flex;justify-content:space-between;gap:14px;align-items:flex-start}
    h2{margin:0;font-size:26px;line-height:1.1;font-weight:850;letter-spacing:0;overflow-wrap:anywhere}
    h3{margin:0;font-size:19px;font-weight:820;letter-spacing:0}
    .muted{color:var(--muted)}
    .small{font-size:12px}
    .token-grid{
      display:grid;
      grid-template-columns:minmax(0,1fr) auto;
      gap:8px;
      margin-top:28px;
    }
    .stat-grid{
      display:grid;
      grid-template-columns:repeat(4,minmax(0,1fr));
      gap:14px;
      max-width:1840px;
      margin:18px auto 0;
    }
    .metric{
      min-height:118px;
      padding:18px 20px;
      border:1px solid var(--hairline);
      border-radius:16px;
      background:var(--fill);
    }
    .metric span{display:block;color:var(--muted);font-size:12px;font-weight:650}
    .metric b{display:block;margin-top:8px;font-size:18px;line-height:1.1;overflow-wrap:anywhere}
    .grid,.list{max-width:1840px;margin:0 auto}
    .grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:18px}
    .list{display:grid;gap:18px}
    .item{padding:22px}
    .item-head,.row{display:flex;align-items:center;justify-content:space-between;gap:10px}
    .row{justify-content:flex-start;flex-wrap:wrap}
    .title{font-weight:750;overflow-wrap:anywhere}
    .code{
      margin-top:8px;
      color:var(--muted);
      font-family:"SF Mono","Cascadia Mono","Roboto Mono",monospace;
      font-size:12px;
      line-height:1.45;
      overflow-wrap:anywhere;
    }
    .desc{margin-top:8px;color:var(--muted);line-height:1.45}
    .pill{
      display:inline-flex;
      align-items:center;
      gap:6px;
      min-height:26px;
      padding:5px 10px;
      border:1px solid var(--hairline);
      border-radius:999px;
      background:rgba(255,255,255,.08);
      color:var(--muted);
      font-size:12px;
      font-weight:700;
      white-space:nowrap;
    }
    .pill.good{color:color-mix(in srgb,var(--accent-2),var(--ink) 22%)}
    .pill.bad{color:color-mix(in srgb,var(--danger),var(--ink) 18%)}
    .switch{
      position:relative;
      width:112px;
      height:50px;
      border-radius:999px;
      padding:0;
      border-color:rgba(255,255,255,.12);
      background:linear-gradient(180deg,rgba(255,255,255,.16),rgba(0,0,0,.28));
      box-shadow:inset 0 3px 8px rgba(255,255,255,.10),inset 0 -10px 18px rgba(0,0,0,.28);
    }
    .switch::after{
      content:"";
      position:absolute;
      top:-2px;
      left:0;
      width:54px;
      height:54px;
      border-radius:50%;
      background:linear-gradient(180deg,#f9fffc,#aab7b1);
      box-shadow:0 8px 18px rgba(0,0,0,.38),inset 0 1px 0 rgba(255,255,255,.7);
      transition:left .2s ease,transform .2s ease;
    }
    .switch.on{
      background:linear-gradient(180deg,rgba(80,255,170,.78),rgba(0,199,129,.92) 50%,rgba(0,122,79,.94));
      box-shadow:inset 0 4px 9px rgba(255,255,255,.24),inset 0 -10px 18px rgba(0,0,0,.22),0 0 18px rgba(0,199,129,.20);
    }
    .switch.on::after{left:58px}
    .empty,.notice{
      padding:18px;
      color:var(--muted);
      line-height:1.5;
    }
    .notice.bad{color:color-mix(in srgb,var(--danger),var(--ink) 10%)}
    .module-actions,.su-actions{display:flex;gap:10px;flex-wrap:wrap;margin-top:18px}
    .module-actions button,.su-actions button{padding:9px 14px;border-radius:999px}
    .segment{
      display:flex;
      gap:10px;
      padding:14px;
      margin-top:22px;
      border-radius:999px;
      background:rgba(255,255,255,.055);
      overflow:auto;
      min-width:0;
      width:100%;
    }
    .seg{
      min-height:48px;
      min-width:0;
      padding:0 24px;
      border-radius:16px;
      color:var(--ink);
      background:rgba(255,255,255,.08);
      border-color:rgba(255,255,255,.10);
      font-weight:800;
      white-space:nowrap;
    }
    .seg.active{color:var(--accent);background:rgba(0,199,129,.16)}
    .bar{
      height:12px;
      border-radius:999px;
      background:rgba(255,255,255,.10);
      overflow:hidden;
      margin-top:10px;
    }
    .bar span{
      display:block;
      height:100%;
      width:var(--value,50%);
      border-radius:999px;
      background:linear-gradient(90deg,var(--accent),var(--accent-2));
    }
    .runtime-stack{display:grid;gap:12px;margin-top:18px}
    .runtime-row{
      display:flex;
      align-items:center;
      justify-content:space-between;
      gap:12px;
      padding:12px 14px;
      border:1px solid var(--hairline);
      border-radius:14px;
      background:var(--fill);
    }
    .runtime-row span{color:var(--muted);font-size:12px;font-weight:750;text-transform:uppercase}
    .runtime-row b{min-width:0;font-size:13px;overflow-wrap:anywhere;text-align:right}
    .status-ribbon{
      display:grid;
      grid-template-columns:repeat(3,minmax(0,1fr));
      gap:12px;
      margin-top:22px;
    }
    .ribbon-cell{
      min-height:84px;
      padding:14px;
      border:1px solid var(--hairline);
      border-radius:16px;
      background:rgba(255,255,255,.08);
    }
    .ribbon-cell span{display:block;color:var(--muted);font-size:12px;font-weight:750}
    .ribbon-cell b{display:block;margin-top:8px;font-size:22px}
    .control-stack{
      display:grid;
      gap:18px;
      max-width:1840px;
      margin:18px auto 0;
    }
    .slider-card{
      position:relative;
      min-height:188px;
      padding:24px;
      border:1px solid var(--hairline);
      border-radius:var(--radius);
      background:var(--glass);
      box-shadow:var(--shadow),0 1px 0 rgba(255,255,255,.12) inset;
      overflow:hidden;
      backdrop-filter:blur(18px) saturate(1.2);
      -webkit-backdrop-filter:blur(18px) saturate(1.2);
    }
    .slider-card::before{content:"";position:absolute;inset:0 0 auto;height:1px;background:rgba(255,255,255,.18)}
    .slider-head{display:flex;align-items:flex-start;justify-content:space-between;gap:18px}
    .value-badge{
      min-width:86px;
      padding:10px 12px;
      border:1px solid rgba(0,122,255,.45);
      border-radius:14px;
      color:var(--accent);
      background:rgba(0,122,255,.13);
      text-align:center;
      font-weight:850;
      box-shadow:0 0 20px rgba(0,122,255,.08) inset;
    }
    .value-badge small{display:block;color:var(--muted);font-size:12px;font-weight:700}
    .range{
      width:100%;
      margin:54px 0 28px;
      appearance:none;
      background:transparent;
    }
    .range::-webkit-slider-runnable-track{
      height:13px;
      border-radius:999px;
      background:linear-gradient(90deg,var(--accent-2) var(--range,50%),rgba(255,255,255,.22) var(--range,50%));
    }
    .range::-webkit-slider-thumb{
      appearance:none;
      width:34px;
      height:34px;
      margin-top:-11px;
      border:0;
      border-radius:50%;
      background:linear-gradient(180deg,#fff,#f2f2f2);
      box-shadow:0 10px 22px rgba(0,0,0,.38),inset 0 1px 0 rgba(255,255,255,.9);
    }
    .range-labels{display:flex;justify-content:space-between;color:var(--muted);font-weight:800}
    .wide-meter{
      min-height:238px;
      padding:24px;
      border:1px solid var(--hairline);
      border-radius:var(--radius);
      background:var(--glass);
      box-shadow:var(--shadow),0 1px 0 rgba(255,255,255,.12) inset;
      backdrop-filter:blur(18px) saturate(1.2);
      -webkit-backdrop-filter:blur(18px) saturate(1.2);
    }
    .meter-title{text-align:center;font-size:20px;font-weight:850;margin:8px 0 30px;color:var(--muted)}
    .health-grid{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:12px}
    .health-tile{padding:16px;border:1px solid var(--hairline);border-radius:16px;background:var(--fill)}
    .health-tile b{display:block;font-size:18px}
    .health-tile span{display:block;margin-top:6px;color:var(--muted);font-size:12px;font-weight:750}
    .bottom-tabs{
      position:fixed;
      z-index:5;
      left:14px;
      right:14px;
      bottom:calc(18px + env(safe-area-inset-bottom));
      display:grid;
      grid-template-columns:repeat(4,1fr);
      width:auto;
      max-width:620px;
      margin:0 auto;
      gap:4px;
      padding:8px;
      border:1px solid var(--hairline);
      border-radius:999px;
      background:rgba(29,29,31,.82);
      box-shadow:0 18px 42px rgba(0,0,0,.42),0 1px 0 rgba(255,255,255,.16) inset;
      backdrop-filter:blur(18px) saturate(1.25);
      -webkit-backdrop-filter:blur(18px) saturate(1.25);
    }
    .bottom-tabs button{
      display:grid;
      grid-template-rows:24px auto;
      place-items:center;
      min-width:0;
      min-height:64px;
      padding:7px 8px;
      border-radius:999px;
      color:var(--muted);
      background:transparent;
      border-color:transparent;
      box-shadow:none;
      font-size:12px;
      font-weight:760;
    }
    .bottom-tabs button::before{font-size:22px;line-height:1;color:inherit}
    .bottom-tabs button[data-tab="status"]::before{content:"▦"}
    .bottom-tabs button[data-tab="su"]::before{content:"✦"}
    .bottom-tabs button[data-tab="features"]::before{content:"▰"}
    .bottom-tabs button[data-tab="modules"]::before{content:"⚙"}
    .bottom-tabs button.active{color:var(--accent);background:rgba(255,255,255,.12)}
    .bottom-tabs button[data-tab="status"]::before{content:"S"}
    .bottom-tabs button[data-tab="su"]::before{content:"R"}
    .bottom-tabs button[data-tab="features"]::before{content:"F"}
    .bottom-tabs button[data-tab="modules"]::before{content:"M"}
    @media(min-width:861px){
      .bottom-tabs{display:none}
      .content{padding-bottom:48px}
    }
    @media(max-width:860px){
      .app{display:block}
      .sidebar{display:none}
      .content{padding:72px 14px 104px}
      .topbar{margin:-72px -14px 16px;padding:12px 20px}
      .topbar-title{font-size:28px}
      .hero{grid-template-columns:1fr}
      .stat-grid{grid-template-columns:repeat(2,minmax(0,1fr))}
      .grid{grid-template-columns:1fr}
      .status-ribbon,.health-grid{grid-template-columns:1fr}
      .bottom-tabs{bottom:calc(10px + env(safe-area-inset-bottom));padding:6px}
      .bottom-tabs button{min-height:54px;font-size:11px}
      .bottom-tabs button.active{color:white;background:rgba(0,122,255,.95)}
      h1{font-size:24px}
      h2{font-size:26px}
    }
    @media(max-width:520px){
      .top-actions .pill{display:none}
      .token-grid{grid-template-columns:1fr}
      .stat-grid{grid-template-columns:1fr}
      .headline,.item-head{align-items:flex-start;flex-direction:column}
      .switch{align-self:flex-start;width:92px;height:42px}
      .switch::after{width:46px;height:46px}
      .switch.on::after{left:48px}
      .segment{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:8px;padding:8px;border-radius:18px}
      .seg{padding:0 8px}
      .runtime-row{display:grid;grid-template-columns:1fr}
      .runtime-row b{text-align:left}
      .topbar-title::after{display:none}
      .bottom-tabs button{font-size:10px}
      h2{font-size:24px}
    }
  </style>
</head>
<body>
  <div class="app">
    <aside class="sidebar">
      <div class="brand">
        <p class="eyebrow">Local admin</p>
        <h1>KernelSU</h1>
        <div id="authState" class="auth-pill"><span class="dot"></span><span>Token missing</span></div>
      </div>
      <nav aria-label="Primary">
        <button type="button" data-tab="status" class="active"><span class="nav-glyph">S</span><span>Status</span><span id="navStatus" class="nav-count"></span></button>
        <button type="button" data-tab="su"><span class="nav-glyph">R</span><span>Requests</span><span id="navSu" class="nav-count">0</span></button>
        <button type="button" data-tab="features"><span class="nav-glyph">F</span><span>Features</span><span id="navFeatures" class="nav-count"></span></button>
        <button type="button" data-tab="modules"><span class="nav-glyph">M</span><span>Modules</span><span id="navModules" class="nav-count"></span></button>
      </nav>
    </aside>
    <main class="content">
      <div class="topbar">
        <div class="topbar-title" id="screenTitle">Status</div>
        <div class="top-actions">
          <span id="compactAuthState" class="pill bad">No token</span>
          <button id="refreshButton" class="icon-button" type="button" title="Refresh" aria-label="Refresh">Re</button>
        </div>
      </div>
      <section id="status" class="active">
        <div class="hero">
          <div class="panel hero-card">
            <div class="headline">
              <div>
                <p class="eyebrow">System guard</p>
                <h2>Root control, live and local</h2>
              </div>
              <button id="promptSwitch" class="switch" type="button" aria-label="Toggle web SU prompt"></button>
            </div>
            <div class="row" style="margin-top:16px">
              <span id="safeModePill" class="pill">Loading</span>
              <span id="promptPill" class="pill">Prompt sync</span>
            </div>
            <div class="segment" aria-label="Root mode">
              <button class="seg active" type="button">Guard</button>
              <button class="seg" type="button">Fast grant</button>
              <button class="seg" type="button">Audit</button>
            </div>
            <div class="token-grid">
              <input id="token" type="password" inputmode="text" autocomplete="off" spellcheck="false" placeholder="Bearer token">
              <button id="saveToken" class="primary" type="button">Save</button>
            </div>
          </div>
          <div class="panel">
            <h3>Runtime snapshot</h3>
            <div id="statusSummary" class="desc">Waiting for status.</div>
            <div id="runtimeDetails" class="runtime-stack"></div>
          </div>
        </div>
        <div id="statusOut"></div>
      </section>
      <section id="su"><div id="suOut" class="list"></div></section>
      <section id="features"><div id="featuresOut" class="grid"></div></section>
      <section id="modules"><div id="modulesOut" class="grid"></div></section>
    </main>
  </div>
  <nav class="bottom-tabs" aria-label="Primary mobile">
    <button type="button" data-tab="status" class="active">Status</button>
    <button type="button" data-tab="su">Requests</button>
    <button type="button" data-tab="features">Features</button>
    <button type="button" data-tab="modules">Modules</button>
  </nav>
  <script>
    let token = localStorage.getItem('ksu.web.token') || '';
    let webPromptEnabled = false;
    let webPromptSupported = false;
    let suPollMs = Number(localStorage.getItem('ksu.web.poll_ms') || '1000');
    let suPollTimer = 0;
    const $ = (id) => document.getElementById(id);
    const titles = {status:'Status',su:'Superuser Requests',features:'Features',modules:'Modules'};
    $('token').value = token;

    function setAuthState(){
      const ready = !!token;
      const label = ready ? 'Token loaded' : 'Token missing';
      $('authState').classList.toggle('ready', ready);
      $('authState').querySelector('span:last-child').textContent = label;
      $('compactAuthState').textContent = ready ? 'Authorized' : 'No token';
      $('compactAuthState').className = ready ? 'pill good' : 'pill bad';
    }

    function esc(value){
      return String(value ?? '').replace(/[&<>"]/g, (char) => ({
        '&':'&amp;',
        '<':'&lt;',
        '>':'&gt;',
        '"':'&quot;'
      }[char]));
    }

    function jsString(value){
      return String(value ?? '').replace(/\\/g, '\\\\').replace(/'/g, "\\'");
    }

    async function api(path, opts={}){
      opts.headers = Object.assign({'Authorization':'Bearer '+token}, opts.headers || {});
      if (opts.body && !opts.headers['Content-Type']) {
        opts.headers['Content-Type']='application/json';
      }
      const res = await fetch(path, opts);
      const data = await res.json().catch(() => ({}));
      if (!res.ok) {
        throw new Error(data.error || res.statusText);
      }
      return data;
    }

    function setTab(name){
      document.querySelectorAll('[data-tab],section').forEach((node) => node.classList.remove('active'));
      document.querySelectorAll(`[data-tab="${name}"]`).forEach((node) => node.classList.add('active'));
      $(name).classList.add('active');
      $('screenTitle').textContent = titles[name] || name;
      refresh();
    }

    document.querySelectorAll('[data-tab]').forEach((btn) => {
      btn.onclick = () => setTab(btn.dataset.tab);
    });

    $('saveToken').onclick = () => {
      token = $('token').value.trim();
      localStorage.setItem('ksu.web.token', token);
      setAuthState();
      refresh();
    };

    $('refreshButton').onclick = () => refresh();
    $('promptSwitch').onclick = () => toggleWebPrompt();

    function active(){
      return document.querySelector('section.active').id;
    }

    function notice(target, message, bad=false){
      $(target).innerHTML = `<div class="notice ${bad ? 'bad' : ''}">${esc(message)}</div>`;
    }

    function renderWebPromptState(){
      $('promptSwitch').classList.toggle('on', webPromptEnabled);
      $('promptSwitch').disabled = !webPromptSupported;
      $('promptPill').className = webPromptSupported ? (webPromptEnabled ? 'pill good' : 'pill') : 'pill bad';
      $('promptPill').textContent = webPromptSupported ? (webPromptEnabled ? 'Web prompt on' : 'Web prompt off') : 'Prompt unsupported';
    }

    async function syncFeatureState(){
      const data = await api('/api/v1/features');
      $('navFeatures').textContent = data.features.filter((f) => f.enabled).length;
      const prompt = data.features.find((f) => f.name === 'web_su_prompt');
      webPromptEnabled = !!(prompt && prompt.enabled);
      webPromptSupported = !!(prompt && prompt.supported);
      renderWebPromptState();
      return data;
    }

    async function loadStatus(){
      try {
        const s = await api('/api/v1/status');
        $('safeModePill').className = s.safe_mode ? 'pill bad' : 'pill good';
        $('safeModePill').textContent = s.safe_mode ? 'Safe mode' : 'Normal';
        $('statusSummary').innerHTML = `${esc(s.ksud_version_name)} / UAPI ${esc(s.kernel_uapi_version)}`;
        $('runtimeDetails').innerHTML = `<div class="runtime-row"><span>Kernel</span><b>${esc(s.kernel_version)}</b></div>
          <div class="runtime-row"><span>ksud code</span><b>${esc(s.ksud_version_code)}</b></div>
          <div class="runtime-row"><span>Flags</span><b>${esc('0x' + Number(s.kernel_flags || 0).toString(16))}</b></div>`;
        await syncFeatureState();
        $('statusOut').innerHTML = `<div class="stat-grid">
          <div class="metric"><span>Security state</span><b>${s.safe_mode ? 'Safe mode' : 'Normal'}</b><div class="bar" style="--value:${s.safe_mode ? 28 : 88}%"><span></span></div></div>
          <div class="metric"><span>Feature mask</span><b>${esc('0x' + Number(s.kernel_features || 0).toString(16))}</b><div class="bar" style="--value:84%"><span></span></div></div>
          <div class="metric"><span>Kernel flags</span><b>${esc('0x' + Number(s.kernel_flags || 0).toString(16))}</b><div class="bar" style="--value:48%"><span></span></div></div>
          <div class="metric"><span>Version code</span><b>${esc(s.ksud_version_code)}</b><div class="bar" style="--value:64%"><span></span></div></div>
        </div>
        <div class="control-stack">
          <div class="slider-card">
            <div class="slider-head">
              <div>
                <h3>Request refresh timing</h3>
                <div class="desc">Controls how often the local page checks for pending SU prompts.</div>
              </div>
              <div class="value-badge"><span id="pollValue">${(suPollMs / 1000).toFixed(1)} s</span><small>${suPollMs} ms</small></div>
            </div>
            <input id="pollSlider" class="range" type="range" min="300" max="5000" step="100" value="${suPollMs}">
            <div class="range-labels"><span>300 ms</span><span>Balanced</span><span>5.0 s</span></div>
          </div>
          <div class="wide-meter">
            <div class="meter-title">Control health</div>
            <div class="health-grid">
              <div class="health-tile"><b>${s.safe_mode ? 'Restricted' : 'Ready'}</b><span>Boot policy</span></div>
              <div class="health-tile"><b>${webPromptEnabled ? 'Prompting' : 'Quiet'}</b><span>SU prompt</span></div>
              <div class="health-tile"><b>Local</b><span>127.0.0.1:9700</span></div>
            </div>
          </div>
        </div>`;
        bindPollSlider();
      } catch(e) {
        $('safeModePill').className = 'pill bad';
        $('safeModePill').textContent = 'Offline';
        webPromptEnabled = false;
        webPromptSupported = false;
        renderWebPromptState();
        $('statusSummary').textContent = e.message;
        $('runtimeDetails').innerHTML = '';
        notice('statusOut', e.message, true);
      }
    }

    async function loadFeatures(){
      try {
        const data = await syncFeatureState();
        $('featuresOut').innerHTML = data.features.map((f) => {
          const safeName = esc(f.name);
          const jsName = jsString(f.name);
          const enabled = !!f.enabled;
          const supported = !!f.supported;
          return `<div class="item">
            <div class="item-head">
              <div>
                <div class="title">${safeName}</div>
                <div class="desc">${esc(f.description)}</div>
              </div>
              <button class="switch ${enabled ? 'on' : ''}" type="button" aria-label="${enabled ? 'Disable' : 'Enable'} ${safeName}" ${supported ? '' : 'disabled'} onclick="setFeature('${jsName}',${enabled ? 0 : 1})"></button>
            </div>
            <div class="row" style="margin-top:12px">
              <span class="pill ${supported ? (enabled ? 'good' : '') : 'bad'}">${supported ? (enabled ? 'Enabled' : 'Disabled') : 'Unsupported'}</span>
              <span class="pill">ID ${esc(f.id)}</span>
            </div>
          </div>`;
        }).join('');
      } catch(e) {
        notice('featuresOut', e.message, true);
      }
    }

    async function setFeature(name,value){
      await api('/api/v1/features/'+name,{method:'PATCH',body:JSON.stringify({value})});
      if (name === 'web_su_prompt') {
        webPromptEnabled = value !== 0;
        renderWebPromptState();
      }
      loadFeatures();
    }

    async function toggleWebPrompt(){
      if (!webPromptSupported) {
        await syncFeatureState();
      }
      if (!webPromptSupported) {
        return;
      }
      await setFeature('web_su_prompt', webPromptEnabled ? 0 : 1);
      if (active() === 'status') {
        await syncFeatureState();
      }
    }

    async function loadModules(){
      try {
        const data = await api('/api/v1/modules');
        $('navModules').textContent = data.modules.length;
        $('modulesOut').innerHTML = data.modules.length ? data.modules.map((m) => {
          const enabled = m.enabled === 'true' || m.enabled === true;
          const id = esc(m.id);
          const jsId = jsString(m.id);
          const moduleLoad = enabled ? 78 : 24;
          return `<div class="item">
            <div class="item-head">
              <div>
                <div class="title">${esc(m.name || m.id)}</div>
                <div class="code">${id} ${esc(m.version || '')}</div>
              </div>
              <span class="pill ${enabled ? 'good' : ''}">${enabled ? 'Enabled' : 'Disabled'}</span>
            </div>
            <div class="desc">${esc(m.description || '')}</div>
            <div class="bar" style="--value:${moduleLoad}%"><span></span></div>
            <div class="module-actions">
              <button type="button" onclick="moduleAction('${jsId}','${enabled ? 'disable' : 'enable'}')">${enabled ? 'Disable' : 'Enable'}</button>
              <button type="button" class="danger" onclick="moduleAction('${jsId}','uninstall')">Uninstall</button>
            </div>
          </div>`;
        }).join('') : '<div class="empty">No modules found.</div>';
      } catch(e) {
        notice('modulesOut', e.message, true);
      }
    }

    async function moduleAction(id,action){
      await api(`/api/v1/modules/${id}/${action}`,{method:'POST',body:'{}'});
      loadModules();
    }

    function requestTitle(r){
      return r.packages && r.packages.length ? r.packages[0] : (r.comm || r.uid);
    }

    async function loadSu(){
      try {
        const data = await api('/api/v1/su/requests');
        $('navSu').textContent = data.requests.length;
        $('suOut').innerHTML = data.requests.length ? data.requests.map((r) => `<div class="item">
          <div class="item-head">
            <div>
              <div class="title">${esc(requestTitle(r))}</div>
              <div class="code">uid ${esc(r.uid)} / pid ${esc(r.pid)} / euid ${esc(r.euid)}</div>
            </div>
            <span class="pill bad">Waiting</span>
          </div>
          <div class="desc">${esc(r.argv || r.path)}</div>
          <div class="su-actions">
            <button type="button" class="ok" onclick="decide(${r.request_id},true,false)">Allow once</button>
            <button type="button" class="ok" onclick="decide(${r.request_id},true,true)">Remember</button>
            <button type="button" class="danger" onclick="decide(${r.request_id},false,false)">Deny</button>
          </div>
        </div>`).join('') : '<div class="empty">No pending requests.</div>';
      } catch(e) {
        notice('suOut', e.message, true);
      }
    }

    function bindPollSlider(){
      const slider = $('pollSlider');
      if (!slider) return;
      const apply = () => {
        suPollMs = Number(slider.value);
        localStorage.setItem('ksu.web.poll_ms', String(suPollMs));
        slider.style.setProperty('--range', `${((suPollMs - 300) / 4700) * 100}%`);
        const value = $('pollValue');
        if (value) value.textContent = `${(suPollMs / 1000).toFixed(1)} s`;
        const badge = value && value.parentElement;
        if (badge) badge.querySelector('small').textContent = `${suPollMs} ms`;
      };
      slider.oninput = apply;
      apply();
    }

    async function decide(id,allow,remember){
      await api(`/api/v1/su/requests/${id}/decision`,{
        method:'POST',
        body:JSON.stringify({decision:allow ? 'allow' : 'deny',remember})
      });
      loadSu();
    }

    function refresh(){
      const screen = active();
      if (screen === 'status') loadStatus();
      if (screen === 'features') loadFeatures();
      if (screen === 'modules') loadModules();
      if (screen === 'su') loadSu();
    }

    setAuthState();
    async function pollSuLoop(){
      if (active() === 'su') {
        await loadSu();
      }
      suPollTimer = setTimeout(pollSuLoop, suPollMs);
    }
    pollSuLoop();
    refresh();
  </script>
</body>
</html>
"#;
