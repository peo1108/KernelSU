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
        bail!("failed to stop webadmin: {}", std::io::Error::last_os_error());
    }
    let _ = fs::remove_file(PID_PATH);
    println!("webadmin stopped");
    Ok(())
}

pub fn status() -> Result<()> {
    let token_exists = Path::new(TOKEN_PATH).exists();
    let autostart = Path::new(AUTOSTART_PATH).exists();
    let listening = is_running();
    println!("listen: {LISTEN_ADDR}");
    println!("running: {listening}");
    println!("token: {token_exists}");
    println!("autostart: {autostart}");
    Ok(())
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

fn write_response(stream: &mut TcpStream, status: &str, content_type: &str, body: &[u8]) -> Result<()> {
    let header = format!(
        "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(header.as_bytes())?;
    stream.write_all(body)?;
    Ok(())
}

fn write_json(stream: &mut TcpStream, status: &str, value: Value) -> Result<()> {
    let body = serde_json::to_vec(&value)?;
    write_response(stream, status, "application/json", &body)
}

fn origin_allowed(req: &HttpRequest) -> bool {
    req.headers.get("origin").is_none_or(|origin| {
        origin == "http://127.0.0.1:9700" || origin == "http://localhost:9700"
    })
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

fn feature_names() -> [(&'static str, u32, &'static str); 6] {
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
    Some(u16::from_le_bytes(bytes.get(off..off + 2)?.try_into().ok()?))
}

fn read_u32_le(bytes: &[u8], off: usize) -> Option<u32> {
    Some(u32::from_le_bytes(bytes.get(off..off + 4)?.try_into().ok()?))
}

fn read_u64_le(bytes: &[u8], off: usize) -> Option<u64> {
    Some(u64::from_le_bytes(bytes.get(off..off + 8)?.try_into().ok()?))
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
    let pid = read_u32_le(payload, 32)?;
    let tgid = read_u32_le(payload, 36)?;
    let ppid = read_u32_le(payload, 40)?;
    let comm = string_from_nul(payload.get(44..60)?);
    let path = string_from_nul(payload.get(60..188)?);
    let argv = string_from_nul(payload.get(188..444)?);
    let packages = packages.get(&uid).cloned().unwrap_or_default();

    Some(SuRequest {
        request_id,
        deadline_ms,
        uid,
        euid,
        pid,
        tgid,
        ppid,
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

fn su_request_reader(state: Arc<Mutex<WebState>>) {
    let fd = match ksucalls::get_su_request_fd() {
        Ok(fd) => fd,
        Err(err) => {
            log::warn!("webadmin: failed to open su request fd: {err}");
            return;
        }
    };
    let _owned_fd = unsafe { OwnedFd::from_raw_fd(fd) };
    let mut packages = package_index();
    let mut buf = [0u8; READ_BUF_SIZE];

    loop {
        let read_len = unsafe { libc::read(fd, buf.as_mut_ptr().cast::<libc::c_void>(), buf.len()) };
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
                packages = package_index();
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

fn handle_su_decision(req: &HttpRequest, state: &Arc<Mutex<WebState>>, request_id: u64) -> Result<Value> {
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
    let remember = body.get("remember").and_then(Value::as_bool).unwrap_or(false);
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

fn handle_connection(mut stream: TcpStream, token: &str, state: &Arc<Mutex<WebState>>) -> Result<()> {
    let req = parse_http_request(&mut stream)?;
    let path = req.path.split('?').next().unwrap_or(&req.path);

    if path.starts_with("/api/") {
        if !is_authorized(&req, token) {
            return write_json(&mut stream, "401 Unauthorized", json!({ "error": "unauthorized" }));
        }
        if matches!(req.method.as_str(), "POST" | "PATCH" | "PUT" | "DELETE") && !origin_allowed(&req) {
            return write_json(&mut stream, "403 Forbidden", json!({ "error": "bad origin" }));
        }
        match route_api(&req, state) {
            Ok(value) => write_json(&mut stream, "200 OK", value),
            Err(err) => write_json(&mut stream, "400 Bad Request", json!({ "error": err.to_string() })),
        }
    } else if req.method == "GET" && (path == "/" || path == "/index.html") {
        write_response(&mut stream, "200 OK", "text/html; charset=utf-8", INDEX_HTML.as_bytes())
    } else {
        write_response(&mut stream, "404 Not Found", "text/plain; charset=utf-8", b"not found\n")
    }
}

pub fn serve() -> Result<()> {
    let token = read_or_create_token()?;
    fs::write(PID_PATH, format!("{}\n", std::process::id()))?;
    let state = Arc::new(Mutex::new(WebState::default()));
    let reader_state = Arc::clone(&state);
    std::thread::spawn(move || su_request_reader(reader_state));

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
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>KernelSU Web Admin</title>
  <style>
    :root{color-scheme:dark light;font-family:system-ui,Roboto,Arial,sans-serif}
    body{margin:0;background:#101418;color:#e8eef2}
    header{display:flex;gap:12px;align-items:center;padding:14px 18px;border-bottom:1px solid #2a343d;background:#151b21}
    h1{font-size:18px;margin:0}
    main{display:grid;grid-template-columns:220px 1fr;min-height:calc(100vh - 54px)}
    nav{border-right:1px solid #2a343d;padding:12px;background:#11171d}
    button,input{font:inherit}
    nav button{display:block;width:100%;margin:0 0 8px;padding:9px;border:1px solid #33414b;background:#18212a;color:#e8eef2;text-align:left;border-radius:6px}
    nav button.active{background:#245b7a;border-color:#3f9bcc}
    section{padding:18px;display:none}
    section.active{display:block}
    .row{display:flex;gap:10px;align-items:center;flex-wrap:wrap;margin:8px 0}
    .item{border:1px solid #2d3942;border-radius:8px;padding:12px;margin:10px 0;background:#151c23}
    .muted{color:#9fb0bc}
    .danger{background:#61252b}
    .ok{background:#1d5134}
    .toolbar{display:flex;gap:8px;align-items:center}
    input{padding:8px;border-radius:6px;border:1px solid #46545f;background:#0d1216;color:#e8eef2;min-width:260px}
    .small{font-size:12px}
    @media(max-width:720px){main{grid-template-columns:1fr}nav{border-right:0;border-bottom:1px solid #2a343d}.toolbar{flex-direction:column;align-items:stretch}input{min-width:0;width:100%}}
  </style>
</head>
<body>
  <header><h1>KernelSU Web Admin</h1><span id="authState" class="muted small"></span></header>
  <main>
    <nav>
      <button data-tab="status" class="active">Status</button>
      <button data-tab="su">Superuser</button>
      <button data-tab="features">Features</button>
      <button data-tab="modules">Modules</button>
    </nav>
    <div>
      <section id="status" class="active">
        <div class="toolbar"><input id="token" placeholder="Bearer token"><button id="saveToken">Save token</button></div>
        <div id="statusOut"></div>
      </section>
      <section id="su"><div id="suOut"></div></section>
      <section id="features"><div id="featuresOut"></div></section>
      <section id="modules"><div id="modulesOut"></div></section>
    </div>
  </main>
  <script>
    let token = localStorage.getItem('ksu.web.token') || '';
    const $ = (id) => document.getElementById(id);
    $('token').value = token;
    function setAuthState(){ $('authState').textContent = token ? 'token loaded' : 'token missing'; }
    setAuthState();
    document.querySelectorAll('nav button').forEach(btn => btn.onclick = () => {
      document.querySelectorAll('nav button,section').forEach(x => x.classList.remove('active'));
      btn.classList.add('active'); $(btn.dataset.tab).classList.add('active'); refresh();
    });
    $('saveToken').onclick = () => { token = $('token').value.trim(); localStorage.setItem('ksu.web.token', token); setAuthState(); refresh(); };
    async function api(path, opts={}){
      opts.headers = Object.assign({'Authorization':'Bearer '+token}, opts.headers || {});
      if (opts.body && !opts.headers['Content-Type']) opts.headers['Content-Type']='application/json';
      const res = await fetch(path, opts);
      const data = await res.json().catch(() => ({}));
      if (!res.ok) throw new Error(data.error || res.statusText);
      return data;
    }
    function esc(s){return String(s ?? '').replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));}
    async function loadStatus(){
      try { const s = await api('/api/v1/status'); $('statusOut').innerHTML = '<div class=item><pre>'+esc(JSON.stringify(s,null,2))+'</pre></div>'; }
      catch(e){ $('statusOut').innerHTML = '<div class=item>'+esc(e.message)+'</div>'; }
    }
    async function loadFeatures(){
      try {
        const data = await api('/api/v1/features');
        $('featuresOut').innerHTML = data.features.map(f => `<div class=item><b>${esc(f.name)}</b><div class=muted>${esc(f.description)}</div><div class=row><span>${f.supported ? (f.enabled ? 'enabled' : 'disabled') : 'unsupported'}</span><button onclick="setFeature('${f.name}',${f.enabled?0:1})">${f.enabled?'Disable':'Enable'}</button></div></div>`).join('');
      } catch(e){ $('featuresOut').innerHTML = '<div class=item>'+esc(e.message)+'</div>'; }
    }
    async function setFeature(name,value){ await api('/api/v1/features/'+name,{method:'PATCH',body:JSON.stringify({value})}); loadFeatures(); }
    async function loadModules(){
      try {
        const data = await api('/api/v1/modules');
        $('modulesOut').innerHTML = data.modules.map(m => `<div class=item><b>${esc(m.name || m.id)}</b><div class=muted>${esc(m.id)} ${esc(m.version || '')}</div><div>${esc(m.description || '')}</div><div class=row><button onclick="moduleAction('${m.id}','${m.enabled==='true'?'disable':'enable'}')">${m.enabled==='true'?'Disable':'Enable'}</button><button class=danger onclick="moduleAction('${m.id}','uninstall')">Uninstall</button></div></div>`).join('');
      } catch(e){ $('modulesOut').innerHTML = '<div class=item>'+esc(e.message)+'</div>'; }
    }
    async function moduleAction(id,action){ await api(`/api/v1/modules/${id}/${action}`,{method:'POST',body:'{}'}); loadModules(); }
    async function loadSu(){
      try {
        const data = await api('/api/v1/su/requests');
        $('suOut').innerHTML = data.requests.length ? data.requests.map(r => `<div class=item><b>${esc(r.packages[0] || r.comm || r.uid)}</b><div class=muted>uid ${r.uid} pid ${r.pid}</div><div>${esc(r.argv || r.path)}</div><div class=row><button class=ok onclick="decide(${r.request_id},true,false)">Allow once</button><button class=ok onclick="decide(${r.request_id},true,true)">Allow & remember</button><button class=danger onclick="decide(${r.request_id},false,false)">Deny</button></div></div>`).join('') : '<div class=item>No pending requests</div>';
      } catch(e){ $('suOut').innerHTML = '<div class=item>'+esc(e.message)+'</div>'; }
    }
    async function decide(id,allow,remember){ await api(`/api/v1/su/requests/${id}/decision`,{method:'POST',body:JSON.stringify({decision:allow?'allow':'deny',remember})}); loadSu(); }
    function active(){ return document.querySelector('section.active').id; }
    function refresh(){ const a=active(); if(a==='status')loadStatus(); if(a==='features')loadFeatures(); if(a==='modules')loadModules(); if(a==='su')loadSu(); }
    setInterval(()=>{ if(active()==='su') loadSu(); }, 1000);
    refresh();
  </script>
</body>
</html>
"#;
