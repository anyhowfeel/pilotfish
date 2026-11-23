//! Insights side of the features hub: findings, the credential / TLS scan and threat lists.
use std::path::PathBuf;
use std::sync::Arc;

use eframe::egui;
use wl_model::{CaptureBackend, HealthInsight, StatsSnapshot, ThreatIntel};
use wl_panels::features::health::HEALTHY_TITLE;
use wl_panels::features::{InsightContext, InsightsAction, synthesize_insights};
use wl_panels::insights::InsightRules;

use super::{FeaturesHub, jobs};

impl FeaturesHub {
    /// New threat lists: match the capture against them again.
    pub fn set_intel(
        &mut self,
        intel: Arc<ThreatIntel>,
        file: Option<PathBuf>,
        ctx: &egui::Context,
    ) {
        self.intel = intel;
        if let Some(file) = file {
            self.spawn_security(&Arc::new(file), ctx);
        }
    }

    /// Cleartext credentials, plus the TLS sessions when threat lists could match them.
    pub(super) fn spawn_security(&self, file: &Arc<PathBuf>, ctx: &egui::Context) {
        let intel = self.intel.clone();
        self.spawn_job(file, ctx, move |b, f| {
            std::thread::scope(|s| {
                let tls = s.spawn(|| {
                    if intel.has_tls_indicators() {
                        b.tls_sessions(f)
                    } else {
                        Ok(Vec::new())
                    }
                });
                jobs::security(b.credentials(f), jobs::join(tls))
            })
        });
    }

    /// Findings for the exported reports. An analysis that did not finish says nothing, so the
    /// all-clear card is written only when every analysis ran: a file must not claim that a
    /// capture is healthy on the strength of a check that failed or never started.
    pub(crate) fn insights_for(&self, stats: &StatsSnapshot) -> Vec<HealthInsight> {
        if self.wireshark.is_missing() {
            return Vec::new();
        }
        let rules = InsightRules {
            reveal_secrets: false,
            ..self.rules.clone()
        };
        let mut all = synthesize_insights(
            self.analyses.expert.ready(),
            self.analyses.hierarchy.ready(),
            self.analyses.behavior.ready(),
            stats,
            &self.context(&rules),
        );
        if !self.analyses.complete() {
            all.retain(|i| i.title != HEALTHY_TITLE);
        }
        all
    }

    fn context<'a>(&'a self, rules: &'a InsightRules) -> InsightContext<'a> {
        InsightContext {
            security: self.analyses.security.ready(),
            intel: &self.intel,
            rules,
            wireshark: self.wireshark,
        }
    }

    pub fn insights_ui(&mut self, ui: &mut egui::Ui, stats: &StatsSnapshot) -> Vec<InsightsAction> {
        let cx = InsightContext {
            security: self.analyses.security.ready(),
            intel: &self.intel,
            rules: &self.rules,
            wireshark: self.wireshark,
        };
        self.insights.ui(ui, stats, &self.analyses, &cx)
    }
}
