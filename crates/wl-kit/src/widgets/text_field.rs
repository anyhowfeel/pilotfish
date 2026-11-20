//! Single-line text input with the text centred vertically (egui's default is top-aligned, which
//! looks low/high inside the 28 pt tall field). The one constructor every input should use.
use eframe::egui::{Align2, TextBuffer, TextEdit};

pub fn text_field(text: &mut dyn TextBuffer) -> TextEdit<'_> {
    TextEdit::singleline(text).align(Align2::LEFT_CENTER)
}
