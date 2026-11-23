use wl_kit::egui::{Context, RawInput};

use super::*;

fn with_ui(f: impl FnOnce(&mut Ui)) {
    let ctx = Context::default();
    let mut f = Some(f);
    ctx.run_ui(RawInput::default(), |ui| {
        if let Some(f) = f.take() {
            f(ui);
        }
    })
    .drop_without_applying_deltas();
}

#[test]
fn only_a_ready_analysis_gives_its_result() {
    with_ui(|ui| {
        assert_eq!(
            ready_or_explain(ui, "Expert info", &Analysis::Ready(7)),
            Some(&7)
        );
        for not_ready in [
            Analysis::Idle,
            Analysis::Pending,
            Analysis::Failed("boom".into()),
        ] {
            assert_eq!(ready_or_explain::<u8>(ui, "Expert info", &not_ready), None);
        }
    });
}

#[test]
fn a_failure_reason_that_ends_with_a_period_is_not_doubled() {
    with_ui(|ui| {
        let failed: Analysis<u8> = Analysis::Failed("tshark exited with status 2.".into());
        assert_eq!(ready_or_explain(ui, "Expert info", &failed), None);
    });
}
