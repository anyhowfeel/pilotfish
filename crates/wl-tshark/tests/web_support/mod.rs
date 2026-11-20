//! Loopback traffic generation for the web integration tests. Every helper returns `None`
//! when a needed tool (python3, curl, openssl, dumpcap) is missing or capture is not permitted,
//! so the tests skip instead of failing on bare machines.

use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const PY_SERVER: &str = r#"
import sys, http.server
class H(http.server.BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'
    def log_message(self, *a): pass
    def _send(self, code, body):
        b = body.encode()
        self.send_response(code)
        self.send_header('Content-Type', 'text/plain')
        self.send_header('Content-Length', str(len(b)))
        self.end_headers()
        self.wfile.write(b)
    def do_GET(self):
        if self.path.startswith('/missing'): self._send(404, 'nope')
        else: self._send(200, 'hello ' + self.path)
    def do_POST(self):
        n = int(self.headers.get('Content-Length', 0))
        self._send(200, 'got ' + self.rfile.read(n).decode())
http.server.ThreadingHTTPServer(('127.0.0.1', int(sys.argv[1])), H).serve_forever()
"#;

/// Kills the wrapped child on drop.
pub struct Guard(pub Child);

impl Drop for Guard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

pub fn have(tool: &str) -> bool {
    Command::new(tool)
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok()
}

pub fn free_port() -> Option<u16> {
    let l = TcpListener::bind("127.0.0.1:0").ok()?;
    l.local_addr().ok().map(|a| a.port())
}

pub fn wait_listening(port: u16) -> bool {
    let end = Instant::now() + Duration::from_secs(8);
    while Instant::now() < end {
        if TcpStream::connect(("127.0.0.1", port)).is_ok() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    false
}

pub fn spawn_quiet(cmd: &mut Command) -> Option<Guard> {
    cmd.stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .ok()
        .map(Guard)
}

pub fn python_server(port: u16) -> Option<Guard> {
    let g = spawn_quiet(Command::new("python3").args(["-c", PY_SERVER, &port.to_string()]))?;
    wait_listening(port).then_some(g)
}

/// Runs `traffic` while dumpcap records `filter` on loopback into `dest`.
pub fn capture(filter: &str, dest: &Path, traffic: impl FnOnce()) -> Option<()> {
    let mut dumpcap = spawn_quiet(
        Command::new("dumpcap")
            .args(["-q", "-i", "lo", "-f", filter, "-w"])
            .arg(dest),
    )?;
    std::thread::sleep(Duration::from_millis(800));
    if matches!(dumpcap.0.try_wait(), Ok(Some(_))) {
        return None;
    }
    traffic();
    std::thread::sleep(Duration::from_millis(500));
    // SIGINT lets dumpcap flush its last block; a plain kill would lose packets.
    let pid = dumpcap.0.id().to_string();
    let _ = Command::new("kill").args(["-INT", &pid]).status();
    let _ = dumpcap.0.wait();
    std::fs::metadata(dest)
        .ok()
        .filter(|m| m.len() > 0)
        .map(|_| ())
}

pub fn curl(args: &[&str], keylog: Option<&Path>) {
    let mut c = Command::new("curl");
    c.args([
        "-s",
        "-k",
        "--http1.1",
        "--max-time",
        "5",
        "-o",
        "/dev/null",
    ]);
    if let Some(k) = keylog {
        c.env("SSLKEYLOGFILE", k);
    }
    let _ = c
        .args(args)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
}

/// HTTP scenario: GET, POST, 404 on separate connections, then 3 keep-alive requests on one.
pub fn http_scenario(dest: &Path) -> Option<u16> {
    if !(have("python3") && have("curl") && have("dumpcap")) {
        return None;
    }
    let port = free_port()?;
    let _srv = python_server(port)?;
    let url = |p: &str| format!("http://127.0.0.1:{port}{p}");
    capture(&format!("tcp port {port}"), dest, || {
        curl(&[&url("/ok")], None);
        curl(&["-d", "a=1&b=2", &url("/submit")], None);
        curl(&[&url("/missing")], None);
        // One curl process with several URLs reuses the connection (keep-alive).
        let (a, b, c) = (url("/ka1"), url("/ka2"), url("/ka3"));
        curl(&[&a, &b, &c], None);
    })?;
    Some(port)
}

pub struct TlsRun {
    pub tls12_port: u16,
    pub tls13_port: u16,
    pub keylog: PathBuf,
}

/// TLS scenario: two `openssl s_server` instances (1.2 and 1.3) hit by curl with SNI names.
pub fn tls_scenario(dir: &Path, dest: &Path) -> Option<TlsRun> {
    if !(have("openssl") && have("curl") && have("dumpcap")) {
        return None;
    }
    let (key, cert) = (dir.join("k.pem"), dir.join("c.pem"));
    let ok = Command::new("openssl")
        .args([
            "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2",
        ])
        .args([
            "-subj",
            "/CN=wirelens.test",
            "-addext",
            "subjectAltName=DNS:wirelens.test",
        ])
        .arg("-keyout")
        .arg(&key)
        .arg("-out")
        .arg(&cert)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .ok()?
        .success();
    if !ok {
        return None;
    }
    let (p12, p13) = (free_port()?, free_port()?);
    let server = |port: u16, extra: &[&str]| {
        let mut c = Command::new("openssl");
        c.args(["s_server", "-www", "-accept", &port.to_string()])
            .arg("-cert")
            .arg(&cert)
            .arg("-key")
            .arg(&key)
            .args(extra);
        let g = spawn_quiet(&mut c)?;
        wait_listening(port).then_some(g)
    };
    let (_s12, _s13) = (server(p12, &["-tls1_2"])?, server(p13, &[])?);
    let keylog = dir.join("keys.log");
    capture(&format!("tcp port {p12} or tcp port {p13}"), dest, || {
        let u12 = format!("https://tls12.wirelens.test:{p12}/");
        let u13 = format!("https://tls13.wirelens.test:{p13}/");
        let r12 = format!("tls12.wirelens.test:{p12}:127.0.0.1");
        let r13 = format!("tls13.wirelens.test:{p13}:127.0.0.1");
        curl(&["--resolve", &r12, "--tlsv1.2", &u12], Some(&keylog));
        curl(&["--resolve", &r13, &u13], Some(&keylog));
    })?;
    Some(TlsRun {
        tls12_port: p12,
        tls13_port: p13,
        keylog,
    })
}
