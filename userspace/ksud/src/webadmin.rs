use anyhow::{Context, Result, bail};
use serde_json::{Value, json};
use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::fd::{FromRawFd, OwnedFd};
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::{defs, ksucalls, module, utils};

const LISTEN_ADDR: &str = "127.0.0.1:9700";
const TOKEN_PATH: &str = concat!("/data/adb/ksu/", "webadmin.token");
const AUTOSTART_PATH: &str = concat!("/data/adb/ksu/", "webadmin.autostart");
const PID_PATH: &str = concat!("/data/adb/ksu/", "webadmin.pid");
const READ_BUF_SIZE: usize = 8192;
const EVENT_HEADER_SIZE: usize = 24;
const DROPPED_RECORD_TYPE: u16 = 0xffff;

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
    if content_len > 2 * 1024 * 1024 {
        bail!("request body too large");
    }

    let mut body = buf[header_end..].to_vec();
    while body.len() < content_len {
        let n = stream.read(&mut tmp)?;
        if n == 0 {
            bail!("connection closed before body");
        }
        body.extend_from_slice(&tmp[..n]);
    }
    body.truncate(content_len);

    Ok(HttpRequest {
        method,
        path,
        headers,
        body,
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
        .map(|(name, id, description)| {
            let (value, supported) = ksucalls::get_feature(*id).unwrap_or((0, false));
            json!({
                "name": name,
                "id": id,
                "description": description,
                "value": value,
                "enabled": value != 0,
                "supported": supported,
            })
        })
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
        _ => bail!("unknown module action"),
    }
    Ok(json!({ "ok": true, "id": id, "action": action }))
}

fn route_api(req: &HttpRequest, state: &Arc<Mutex<WebState>>) -> Result<Value> {
    let path = req.path.split('?').next().unwrap_or(&req.path);
    match (req.method.as_str(), path) {
        ("GET", "/api/v1/status") => Ok(handle_status()),
        ("GET", "/api/v1/features") => Ok(handle_features()),
        ("GET", "/api/v1/modules") => Ok(handle_modules()),
        ("GET", "/api/v1/su/requests") => Ok(handle_su_requests(state)),
        _ => {
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

    if path.starts_with("/api/") {
        if !is_authorized(&req, token) {
            return write_json(
                &mut stream,
                "401 Unauthorized",
                &json!({ "error": "unauthorized" }),
            );
        }
        if matches!(req.method.as_str(), "POST" | "PATCH" | "PUT" | "DELETE")
            && !origin_allowed(&req)
        {
            return write_json(
                &mut stream,
                "403 Forbidden",
                &json!({ "error": "bad origin" }),
            );
        }
        match route_api(&req, state) {
            Ok(value) => write_json(&mut stream, "200 OK", &value),
            Err(err) => write_json(
                &mut stream,
                "400 Bad Request",
                &json!({ "error": err.to_string() }),
            ),
        }
    } else if req.method == "GET" && (path == "/" || path == "/index.html") {
        write_response(
            &mut stream,
            "200 OK",
            "text/html; charset=utf-8",
            INDEX_HTML.as_bytes(),
        )
    } else {
        write_response(
            &mut stream,
            "404 Not Found",
            "text/plain; charset=utf-8",
            b"not found\n",
        )
    }
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
  <meta name="color-scheme" content="light dark">
  <title>KernelSU Web Admin</title>
  <style>
    :root{
      color-scheme:light dark;
      --bg:#f2f2f7;
      --ink:#101418;
      --muted:#5e6b7d;
      --hairline:rgba(23,32,51,.08);
      --glass:rgba(255,255,255,.30);
      --glass-strong:rgba(255,255,255,.72);
      --fill:rgba(255,255,255,.34);
      --field:rgba(255,255,255,.58);
      --control:rgba(255,255,255,.88);
      --accent:#007aff;
      --accent-2:#34c759;
      --warn:#ff9f0a;
      --danger:#ff3b30;
      --purple:#8b5cf6;
      --shadow:0 22px 70px rgba(0,0,0,.22);
      --radius:24px;
      font-family:-apple-system,BlinkMacSystemFont,"SF Pro Text","Segoe UI",Roboto,Arial,sans-serif;
    }
    @media(prefers-color-scheme:dark){
      :root{
        --bg:#000;
        --ink:#f5f8ff;
        --muted:#b9c4d3;
        --hairline:rgba(255,255,255,.14);
        --glass:rgba(18,22,30,.42);
        --glass-strong:rgba(13,18,27,.78);
        --fill:rgba(255,255,255,.08);
        --field:rgba(255,255,255,.11);
        --control:rgba(255,255,255,.10);
        --shadow:0 22px 70px rgba(0,0,0,.48);
      }
    }
    *{box-sizing:border-box}
    html{min-height:100%;background:var(--bg)}
    body{
      min-height:100vh;
      margin:0;
      color:var(--ink);
      background:var(--bg);
      letter-spacing:0;
    }
    body::before{
      content:"";
      position:fixed;
      inset:0;
      pointer-events:none;
      background:
        radial-gradient(circle at 42% 12%,rgba(0,122,255,.18),transparent 18rem),
        radial-gradient(circle at 90% 4%,rgba(139,92,246,.18),transparent 16rem),
        radial-gradient(ellipse at 48% 45%,rgba(255,255,255,.09),transparent 25rem),
        repeating-linear-gradient(120deg,transparent 0 86px,rgba(255,255,255,.035) 87px 89px,transparent 90px 176px),
        repeating-linear-gradient(62deg,transparent 0 132px,rgba(255,255,255,.028) 133px 135px,transparent 136px 252px),
        linear-gradient(180deg,rgba(9,15,26,.70),rgba(0,0,0,.92));
      opacity:.95;
    }
    body::after{
      content:"";
      position:fixed;
      inset:58px 0 0 0;
      pointer-events:none;
      background:
        radial-gradient(ellipse at 54% 22%,rgba(255,255,255,.08),transparent 20rem),
        conic-gradient(from 35deg at 52% 34%,transparent,rgba(255,255,255,.055),transparent 26%,rgba(0,122,255,.08),transparent 46%);
      filter:blur(.2px);
      opacity:.55;
    }
    button,input{font:inherit}
    button{
      min-height:38px;
      border:1px solid var(--hairline);
      border-radius:16px;
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
      border-radius:16px;
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
      display:block;
      min-height:100vh;
    }
    .sidebar{
      display:none;
      position:sticky;
      top:0;
      height:100vh;
      padding:92px 10px 18px;
      border-right:0;
      background:rgba(0,0,0,.16);
      backdrop-filter:blur(14px) saturate(1.1);
      -webkit-backdrop-filter:blur(14px) saturate(1.1);
    }
    .brand{display:none}
    .eyebrow{margin:0 0 6px;color:var(--muted);font-size:12px;font-weight:700;text-transform:uppercase}
    h1{margin:0;font-size:28px;line-height:1.05;font-weight:760;letter-spacing:0}
    .auth-pill{
      display:inline-flex;
      gap:7px;
      align-items:center;
      min-height:28px;
      margin-top:14px;
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
    nav{display:grid;gap:18px}
    nav button{
      position:relative;
      display:flex;
      flex-direction:column;
      align-items:center;
      justify-content:center;
      width:78px;
      min-height:82px;
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
      background:rgba(139,92,246,.28);
      border-color:rgba(255,255,255,.08);
      box-shadow:0 10px 30px rgba(0,0,0,.18),0 1px 0 rgba(255,255,255,.16) inset;
    }
    .nav-glyph{
      display:grid;
      place-items:center;
      width:42px;
      height:42px;
      border-radius:18px;
      color:color-mix(in srgb,var(--ink),transparent 6%);
      background:rgba(255,255,255,.10);
      font-size:18px;
      font-weight:800;
    }
    nav button.active .nav-glyph{color:white;background:rgba(139,92,246,.52)}
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
      background:rgba(0,0,0,.44);
      backdrop-filter:blur(18px) saturate(1.2);
      -webkit-backdrop-filter:blur(18px) saturate(1.2);
    }
    .topbar-title{font-size:28px;font-weight:850}
    .topbar-title::after{content:" KernelSU";margin-left:8px;color:var(--accent);font-size:18px;font-weight:800}
    .top-actions{display:flex;gap:8px;align-items:center}
    .icon-button{display:grid;place-items:center;width:44px;height:44px;padding:0;border-radius:16px;font-weight:800}
    .primary{border-color:color-mix(in srgb,var(--accent),white 30%);background:linear-gradient(180deg,color-mix(in srgb,var(--accent),white 12%),var(--accent));color:white}
    .ok{border-color:color-mix(in srgb,var(--accent-2),white 30%);background:linear-gradient(180deg,color-mix(in srgb,var(--accent-2),white 12%),var(--accent-2));color:white}
    .danger{border-color:color-mix(in srgb,var(--danger),white 26%);background:linear-gradient(180deg,color-mix(in srgb,var(--danger),white 10%),var(--danger));color:white}
    section{display:none;animation:lift .22s ease both}
    section.active{display:block}
    @keyframes lift{from{opacity:.65;transform:translateY(8px)}to{opacity:1;transform:none}}
    @media(prefers-reduced-motion:reduce){*,section{animation:none!important;transition:none!important}}
    .hero{
      display:grid;
      grid-template-columns:minmax(0,1fr) minmax(420px,.55fr);
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
    .panel::before,.item::before,.empty::before,.notice::before{
      content:"";
      position:absolute;
      inset:0 0 auto 0;
      height:1px;
      background:rgba(255,255,255,.18);
    }
    .panel{padding:28px}
    .headline{display:flex;justify-content:space-between;gap:14px;align-items:flex-start}
    h2{margin:0;font-size:26px;line-height:1.1;font-weight:850;letter-spacing:0}
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
      border-radius:22px;
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
      background:
        radial-gradient(circle at 50% 18%,rgba(255,255,255,.88),rgba(255,255,255,.22) 34%,transparent 38%),
        linear-gradient(180deg,#f5f5f5,#9fa5ad);
      box-shadow:0 8px 18px rgba(0,0,0,.38),inset 0 1px 0 rgba(255,255,255,.7);
      transition:left .2s ease,transform .2s ease;
    }
    .switch.on{
      background:
        linear-gradient(180deg,rgba(118,255,151,.78),rgba(14,188,76,.92) 50%,rgba(10,132,50,.94));
      box-shadow:inset 0 4px 9px rgba(255,255,255,.24),inset 0 -10px 18px rgba(0,0,0,.22),0 0 18px rgba(52,199,89,.20);
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
    }
    .seg{
      min-height:48px;
      padding:0 24px;
      border-radius:16px;
      color:var(--ink);
      background:rgba(255,255,255,.08);
      border-color:rgba(255,255,255,.10);
      font-weight:800;
      white-space:nowrap;
    }
    .seg.active{color:var(--accent);background:rgba(0,122,255,.22)}
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
      background:linear-gradient(90deg,rgba(0,122,255,.58),var(--accent));
    }
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
      width:92px;
      height:54px;
      margin-top:-21px;
      border:0;
      border-radius:22px;
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
    .core-row{display:grid;grid-template-columns:repeat(8,minmax(0,1fr));gap:12px}
    .core{display:grid;gap:10px;text-align:center;color:var(--muted);font-weight:800}
    .core .bar{height:10px;margin:0}
    .bottom-tabs{
      position:fixed;
      z-index:5;
      left:50%;
      right:auto;
      bottom:calc(18px + env(safe-area-inset-bottom));
      display:grid;
      grid-template-columns:repeat(4,1fr);
      width:min(620px,calc(100vw - 28px));
      transform:translateX(-50%);
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
    @media(max-width:860px){
      .app{display:block}
      .sidebar{display:none}
      .content{padding:72px 14px 104px}
      .topbar{margin:-72px -14px 16px;padding:12px 20px}
      .hero{grid-template-columns:1fr}
      .stat-grid{grid-template-columns:repeat(2,minmax(0,1fr))}
      .grid{grid-template-columns:1fr}
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
      .switch{align-self:flex-end}
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
          <button id="refreshButton" class="icon-button" type="button" title="Refresh" aria-label="Refresh">R</button>
        </div>
      </div>
      <section id="status" class="active">
        <div class="hero">
          <div class="panel">
            <div class="headline">
              <div>
                <p class="eyebrow">System</p>
                <h2>Root control surface</h2>
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
            <h3>Runtime</h3>
            <div id="statusSummary" class="desc">Waiting for status.</div>
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
        $('statusOut').innerHTML = `<div class="stat-grid">
          <div class="metric"><span>Kernel</span><b>${esc(s.kernel_version)}</b><div class="bar" style="--value:72%"><span></span></div></div>
          <div class="metric"><span>Features</span><b>${esc('0x' + Number(s.kernel_features || 0).toString(16))}</b><div class="bar" style="--value:84%"><span></span></div></div>
          <div class="metric"><span>Flags</span><b>${esc('0x' + Number(s.kernel_flags || 0).toString(16))}</b><div class="bar" style="--value:42%"><span></span></div></div>
          <div class="metric"><span>ksud</span><b>${esc(s.ksud_version_code)}</b><div class="bar" style="--value:64%"><span></span></div></div>
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
            <div class="meter-title">KernelSU</div>
            <div class="core-row">
              ${[62,54,48,71,82,67,39,44].map((v,i)=>`<div class="core"><div class="bar" style="--value:${v}%"><span></span></div><b>${i < 4 ? '970' : '768'}MHz</b><small>Core ${i}</small></div>`).join('')}
            </div>
          </div>
        </div>`;
        bindPollSlider();
        await syncFeatureState();
      } catch(e) {
        $('safeModePill').className = 'pill bad';
        $('safeModePill').textContent = 'Offline';
        webPromptEnabled = false;
        webPromptSupported = false;
        renderWebPromptState();
        $('statusSummary').textContent = e.message;
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
