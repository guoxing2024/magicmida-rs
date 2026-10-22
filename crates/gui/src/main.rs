//! Magicmida-RS graphical front-end.
//!
//! Drives `mida-cli.exe` as a child process and renders the run as a phase
//! rail, a live metric panel, an IAT trace progress bar, and a colour-coded
//! log.  The pipeline itself is untouched — see `parse.rs` for why the process
//! boundary matters.

mod fonts;
mod job;
mod parse;
mod theme;
mod ui;

use std::path::PathBuf;

fn main() -> eframe::Result<()> {
    // Optional positional argument: an EXE to pre-fill and start immediately.
    // Makes the GUI usable as a shell/drag-target handler without extra code.
    //
    //   mida-gui.exe TARGET.exe            -> pre-fill, wait for the user
    //   mida-gui.exe TARGET.exe --auto     -> pre-fill and start immediately
    //   mida-gui.exe TARGET.exe --auto -v  -> ...with verbose logging
    let args: Vec<String> = std::env::args().skip(1).collect();
    let auto = args.iter().any(|a| a == "--auto");
    let verbose = args.iter().any(|a| a == "-v" || a == "--verbose");
    let preset = args
        .iter()
        .find(|a| !a.starts_with('-'))
        .map(PathBuf::from);
    let options = eframe::NativeOptions {
        viewport: eframe::egui::ViewportBuilder::default()
            .with_inner_size([1180.0, 780.0])
            .with_min_inner_size([900.0, 600.0])
            .with_title("Magicmida-RS · Themida 脱壳"),
        ..Default::default()
    };

    eframe::run_native(
        "Magicmida-RS",
        options,
        Box::new(|cc| {
            // Order matters: fonts first, then the theme, so the theme's
            // text styles resolve against a font set that has CJK coverage.
            let cjk = fonts::install_cjk(&cc.egui_ctx);
            theme::install(&cc.egui_ctx);
            Ok(Box::new(ui::App::new(cli_path(), cjk, preset, auto, verbose)))
        }),
    )
}

/// Resolve the CLI once at startup so the UI can report a clear error instead
/// of failing at the moment the user clicks 开始.
fn cli_path() -> Option<PathBuf> {
    job::find_cli()
}
