//! What each background analysis reports back, built from the results of its tshark calls.
//! A failed call is carried as a failure instead of an empty result, so a page never reads "found
//! nothing" for an analysis that did not run.

use std::thread::ScopedJoinHandle;

use wl_model::{
    Analysis, BehaviorData, CaptureError, Channel, Credential, DnsQuery, ExpertReport,
    HttpExchange, ProtocolHierarchy, SecurityData, TlsSession,
};
use wl_panels::features::NameBook;

use super::Msg;

type Scan<T> = Result<T, CaptureError>;

pub(super) fn insights(expert: Scan<ExpertReport>, hierarchy: Scan<ProtocolHierarchy>) -> Msg {
    Msg::Insights(Analysis::from(expert), Analysis::from(hierarchy))
}

/// Channels and DNS make up the behavior data. TLS and HTTP only feed the name suggestions, so
/// their failure costs names and not the analysis.
pub(super) fn behavior(
    channels: Scan<Vec<Channel>>,
    dns: Scan<Vec<DnsQuery>>,
    tls: Scan<Vec<TlsSession>>,
    http: Scan<Vec<HttpExchange>>,
) -> Msg {
    let names = NameBook::build(
        dns.as_deref().unwrap_or_default(),
        tls.as_deref().unwrap_or_default(),
        http.as_deref().unwrap_or_default(),
    );
    let data = channels.and_then(|channels| dns.map(|dns| BehaviorData { channels, dns }));
    Msg::Behavior(Analysis::from(data), names)
}

/// `tls` is `Ok(vec![])` when no threat list needs the sessions.
pub(super) fn security(credentials: Scan<Vec<Credential>>, tls: Scan<Vec<TlsSession>>) -> Msg {
    let data = credentials.and_then(|credentials| tls.map(|tls| SecurityData { credentials, tls }));
    Msg::Security(Analysis::from(data))
}

/// A scan thread that panicked counts as a failed scan.
pub(super) fn join<T>(handle: ScopedJoinHandle<'_, Scan<T>>) -> Scan<T> {
    handle
        .join()
        .unwrap_or_else(|_| Err(CaptureError::Other("the scan stopped unexpectedly".into())))
}

#[cfg(test)]
#[path = "features_hub_jobs_tests.rs"]
mod tests;
