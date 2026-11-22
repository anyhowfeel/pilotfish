//! `tls_sessions`: a handshake pass (SNI / version / cipher / ALPN / cert) and a light
//! byte-counting pass run concurrently, then merged per connection.

use std::collections::HashMap;
use std::ops::ControlFlow;
use std::path::Path;
use std::thread;

use wl_model::{CaptureError, TlsSession};

use crate::cert_scan;
use crate::process::Tools;
use crate::tls_merge::{CERT_FIELD, FIELDS, Merger, StreamKey, stream_key};
use crate::tsv_pass::{Pass, columns, run_pass};

const HANDSHAKE_FILTER: &str =
    "tls.handshake.type==1 || tls.handshake.type==2 || tls.handshake.type==11";

fn handshakes(tools: &Tools, file: &Path, opts: &[String]) -> Result<Merger, CaptureError> {
    let mut fields = FIELDS.to_vec();
    fields.push(CERT_FIELD);
    let pass = Pass {
        file,
        filter: HANDSHAKE_FILTER,
        fields: &fields,
        opts,
    };
    let mut merger = Merger::default();
    run_pass(tools, &pass, |l| {
        merger.push_line(l);
        ControlFlow::Continue(())
    })?;
    Ok(merger)
}

/// Frame bytes per TCP/QUIC flow. TCP reassembly is switched off: only sizes matter here, and
/// skipping reassembly + application dissection is what makes this pass cheap.
fn flow_bytes(
    tools: &Tools,
    file: &Path,
    opts: &[String],
) -> Result<HashMap<StreamKey, u64>, CaptureError> {
    let mut all = opts.to_vec();
    all.extend(["-o".into(), "tcp.desegment_tcp_streams:FALSE".into()]);
    let pass = Pass {
        file,
        filter: "tcp.len>0 || quic",
        fields: &["tcp.stream", "udp.stream", "frame.len"],
        opts: &all,
    };
    let mut bytes: HashMap<StreamKey, u64> = HashMap::new();
    run_pass(tools, &pass, |line| {
        let f: [&str; 3] = columns(line);
        if let (Some(k), Ok(n)) = (stream_key(f[0], f[1]), f[2].trim().parse::<u64>()) {
            *bytes.entry(k).or_default() += n;
        }
        ControlFlow::Continue(())
    })?;
    Ok(bytes)
}

pub fn tls_sessions(
    tools: &Tools,
    file: &Path,
    opts: &[String],
) -> Result<Vec<TlsSession>, CaptureError> {
    let (hs, bytes, certs) = thread::scope(|s| {
        let b = s.spawn(|| flow_bytes(tools, file, opts));
        let c = s.spawn(|| cert_scan::chains(tools, file, opts));
        let h = handshakes(tools, file, opts);
        let panicked = || CaptureError::Other("scan thread panicked".into());
        (
            h,
            b.join().unwrap_or_else(|_| Err(panicked())),
            c.join().unwrap_or_else(|_| Err(panicked())),
        )
    });
    let merger = hs?;
    // Byte totals and chains are decoration: a failed extra pass must not hide the sessions.
    let mut sessions = merger.finish(&bytes.unwrap_or_default());
    let mut certs = certs.unwrap_or_default();
    for s in &mut sessions {
        s.certs = s.stream.and_then(|n| certs.remove(&n)).unwrap_or_default();
    }
    Ok(sessions)
}
