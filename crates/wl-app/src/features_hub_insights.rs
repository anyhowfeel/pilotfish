//! Insights side of the features hub: findings, the credential / TLS scan and threat lists.
use std::path::PathBuf;
use std::sync::Arc;

use eframe::egui;
use wl_model::{CaptureBackend, HealthInsight, SecurityData, StatsSnapshot, ThreatIntel};
use wl_panels::features::{InsightContext, InsightsAction, synthesize_insights};
use wl_panels::insights::InsightRules;

use super::{FeaturesHub, Msg};

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
            let (credentials, tls) = std::thread::scope(|s| {
                let t = s.spawn(|| {
                    if intel.has_tls_indicators() {
                        b.tls_sessions(f).unwrap_or_default()
                    } else {
                        Vec::new()
                    }
                });
                (
                    b.credentials(f).unwrap_or_default(),
                    t.join().unwrap_or_default(),
                )
            });
            Msg::Security(SecurityData { credentials, tls })
        });
    }

    pub(crate) fn insights_for(&self, stats: &StatsSnapshot) -> Vec<HealthInsight> {
        let rules = InsightRules {
            reveal_secrets: false,
            ..self.rules.clone()
        };
        synthesize_insights(
            self.expert.as_ref(),
            self.phs.as_ref(),
            self.behavior.as_ref(),
            stats,
            &self.context(&rules),
        )
    }

    fn context<'a>(&'a self, rules: &'a InsightRules) -> InsightContext<'a> {
        InsightContext {
            security: self.security.as_ref(),
            intel: &self.intel,
            rules,
        }
    }

    pub fn insights_ui(&mut self, ui: &mut egui::Ui, stats: &StatsSnapshot) -> Vec<InsightsAction> {
        let cx = InsightContext {
            security: self.security.as_ref(),
            intel: &self.intel,
            rules: &self.rules,
        };
        self.insights.ui(
            ui,
            stats,
            self.expert.as_ref(),
            self.phs.as_ref(),
            self.behavior.as_ref(),
            &cx,
        )
    }
}
