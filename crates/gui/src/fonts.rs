//! Font installation — egui's bundled fonts have no CJK glyphs, so every
//! Chinese label would render as tofu boxes.  We load a system font at startup
//! and register it as the fallback for both the proportional and monospace
//! families.

use eframe::egui::{self, FontData, FontDefinitions, FontFamily};
use std::sync::Arc;

/// Candidate fonts in preference order.
///
/// All are stock Windows files.  `msyh.ttc` (Microsoft YaHei) is the best
/// match for the rest of the UI; the others are progressively older fallbacks
/// so the app still renders on a stripped-down install.
const CANDIDATES: &[&str] = &[
    r"C:\Windows\Fonts\msyh.ttc",
    r"C:\Windows\Fonts\msyhbd.ttc",
    r"C:\Windows\Fonts\Deng.ttf",
    r"C:\Windows\Fonts\simhei.ttf",
    r"C:\Windows\Fonts\simsun.ttc",
];

/// Load the first available CJK font and install it as a fallback.
///
/// Returns the path that was used, or `None` when no font could be read (in
/// which case the UI shows boxes for Chinese text but remains functional).
pub fn install_cjk(ctx: &egui::Context) -> Option<String> {
    let (path, bytes) = CANDIDATES.iter().find_map(|p| {
        std::fs::read(p).ok().map(|b| ((*p).to_string(), b))
    })?;

    let mut fonts = FontDefinitions::default();

    // Register under a private name so we can append it to both families.
    fonts
        .font_data
        .insert("cjk".to_owned(), Arc::new(FontData::from_owned(bytes)));

    // Append (not prepend): latin text keeps the crisper bundled face, and
    // only the glyphs the bundled face lacks fall through to the CJK font.
    for family in [FontFamily::Proportional, FontFamily::Monospace] {
        fonts
            .families
            .entry(family)
            .or_default()
            .push("cjk".to_owned());
    }

    ctx.set_fonts(fonts);
    Some(path)
}
