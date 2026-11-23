//! Where a background analysis stands, so a page can tell "not run", "running", "failed" and
//! "found nothing" apart.

use crate::{BehaviorData, CaptureError, ExpertReport, ProtocolHierarchy, SecurityData};

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum Analysis<T> {
    /// Nothing asked for it yet, for example while a live capture runs.
    #[default]
    Idle,
    Pending,
    Ready(T),
    Failed(String),
}

impl<T> Analysis<T> {
    pub fn ready(&self) -> Option<&T> {
        match self {
            Analysis::Ready(data) => Some(data),
            _ => None,
        }
    }

    pub fn failure(&self) -> Option<&str> {
        match self {
            Analysis::Failed(reason) => Some(reason),
            _ => None,
        }
    }

    pub fn is_pending(&self) -> bool {
        matches!(self, Analysis::Pending)
    }
}

impl<T> From<Result<T, CaptureError>> for Analysis<T> {
    fn from(result: Result<T, CaptureError>) -> Self {
        match result {
            Ok(data) => Analysis::Ready(data),
            Err(e) => Analysis::Failed(e.to_string()),
        }
    }
}

/// The analyses whose results make up the findings of a capture.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct Analyses {
    pub expert: Analysis<ExpertReport>,
    pub hierarchy: Analysis<ProtocolHierarchy>,
    pub behavior: Analysis<BehaviorData>,
    pub security: Analysis<SecurityData>,
}

impl Analyses {
    /// Marks every analysis as running; the caller starts them.
    pub fn start(&mut self) {
        self.expert = Analysis::Pending;
        self.hierarchy = Analysis::Pending;
        self.behavior = Analysis::Pending;
        self.security = Analysis::Pending;
    }

    /// The analysis could not even start: every one still waiting fails with `reason`.
    pub fn fail_pending(&mut self, reason: &str) {
        fn fail<T>(slot: &mut Analysis<T>, reason: &str) {
            if slot.is_pending() {
                *slot = Analysis::Failed(reason.to_owned());
            }
        }
        fail(&mut self.expert, reason);
        fail(&mut self.hierarchy, reason);
        fail(&mut self.behavior, reason);
        fail(&mut self.security, reason);
    }

    /// `(what, reason)` of each analysis that failed.
    pub fn failures(&self) -> Vec<(&'static str, &str)> {
        [
            ("Expert info", self.expert.failure()),
            ("Protocol hierarchy", self.hierarchy.failure()),
            ("Behavior checks", self.behavior.failure()),
            ("Credential scan", self.security.failure()),
        ]
        .into_iter()
        .filter_map(|(what, reason)| reason.map(|r| (what, r)))
        .collect()
    }

    pub fn any_pending(&self) -> bool {
        self.expert.is_pending()
            || self.hierarchy.is_pending()
            || self.behavior.is_pending()
            || self.security.is_pending()
    }

    pub fn any_idle(&self) -> bool {
        [
            matches!(self.expert, Analysis::Idle),
            matches!(self.hierarchy, Analysis::Idle),
            matches!(self.behavior, Analysis::Idle),
            matches!(self.security, Analysis::Idle),
        ]
        .contains(&true)
    }

    /// True when every analysis finished and none failed: only then can "nothing found" be said.
    pub fn complete(&self) -> bool {
        self.expert.ready().is_some()
            && self.hierarchy.ready().is_some()
            && self.behavior.ready().is_some()
            && self.security.ready().is_some()
    }
}

#[cfg(test)]
#[path = "analysis_state_tests.rs"]
mod tests;
