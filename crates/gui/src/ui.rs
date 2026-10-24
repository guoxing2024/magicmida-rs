//! The application window.
//!
//! Layout: a fixed left rail (target selection, run control, status) and a main
//! canvas showing either a drop target or the live run (phase rail, metric
//! grid, trace progress, log).

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use eframe::egui::{
    self, Align, Color32, CornerRadius, Layout, Margin, RichText, ScrollArea, Sense, Stroke,
    StrokeKind, Ui, Vec2,
};

use mida_run::Job;
use mida_run::{Level, LogLine, Metrics, Phase, RunState, TargetKind};
use crate::theme;

const RAIL_W: f32 = 300.0;

pub struct App {
    cli: Option<PathBuf>,
    cjk_ok: bool,
    input: String,
    output: String,
    verbose: bool,
    job: Option<Job>,
    last: Option<Arc<Mutex<RunState>>>,
    status: Status,
    log_filter: String,
    show_debug: bool,
    auto_scroll: bool,
    elapsed: f32,
    /// Target kind of the file currently in `input`.
    ///
    /// Tracked separately from `RunState.kind` because the rail has to show the
    /// right labels *before* a run starts — the file picker is the first place
    /// a user learns that DLLs are supported at all.
    kind: TargetKind,
    /// Whether the one-shot "fit the window to the monitor" pass has run.
    ///
    /// The preferred size in `main.rs` is a guess.  On a 1600x900 desktop a
    /// 1060x660 window plus its frame is comfortable, but on a smaller or
    /// heavily scaled screen the same numbers overflow.  Rather than pick a
    /// number that is wrong somewhere, the first frame measures the actual
    /// monitor and shrinks the viewport to fit if needed.  Doing it once keeps
    /// the user free to resize afterwards.
    fitted: bool,
}

#[derive(Clone)]
enum Status {
    Idle,
    Running,
    Ok(String),
    Failed(String),
}

impl App {
    pub fn new(
        cli: Option<PathBuf>,
        cjk_font: Option<String>,
        preset: Option<PathBuf>,
        auto_start: bool,
        verbose: bool,
    ) -> Self {
        let mut app = Self {
            cli,
            cjk_ok: cjk_font.is_some(),
            input: String::new(),
            output: String::new(),
            verbose,
            job: None,
            last: None,
            status: Status::Idle,
            log_filter: String::new(),
            show_debug: false,
            auto_scroll: true,
            elapsed: 0.0,
            kind: TargetKind::Exe,
            fitted: false,
        };
        if let Some(p) = preset {
            if p.is_file() {
                app.pick_input(p);
                if auto_start {
                    app.start();
                }
            }
        }
        app
    }

    fn running(&self) -> bool {
        self.job.is_some()
    }

    fn view(&self) -> Option<Arc<Mutex<RunState>>> {
        self.job
            .as_ref()
            .map(|j| j.state.clone())
            .or_else(|| self.last.clone())
    }

    fn pick_input(&mut self, p: PathBuf) {
        self.kind = TargetKind::of_path(&p);
        self.output = default_output(&p).display().to_string();
        self.input = p.display().to_string();
    }

    fn start(&mut self) {
        let Some(cli) = self.cli.clone() else {
            self.status = Status::Failed("找不到 mida-cli.exe".into());
            return;
        };
        let input = PathBuf::from(self.input.trim());
        if !input.is_file() {
            self.status = Status::Failed(format!("输入不存在：{}", short_name(&input)));
            return;
        }
        // Re-derive from the path actually being unpacked: the user may have
        // typed it rather than picked it, and the rail label has to agree with
        // what the CLI will do.
        self.kind = TargetKind::of_path(&input);
        let output = if self.output.trim().is_empty() {
            default_output(&input)
        } else {
            PathBuf::from(self.output.trim())
        };

        match Job::spawn(&cli, &input, &output, self.verbose) {
            Ok(job) => {
                self.status = Status::Running;
                self.elapsed = 0.0;
                self.job = Some(job);
                self.last = None;
            }
            Err(e) => self.status = Status::Failed(format!("启动失败：{e}")),
        }
    }

    fn cancel(&mut self) {
        if let Some(j) = &mut self.job {
            j.cancel();
        }
    }

    fn finish(&mut self, code: i32) {
        let Some(job) = self.job.take() else { return };
        let st = job.state.clone();
        let secs = job.started_at.elapsed().as_secs_f32();

        // `Done.` is logged to stderr while the final `[GOOD] Unpacked:` line may
        // race on stdout, so the parser flag alone is not authoritative.  Trust
        // the exit code, and corroborate with a product on disk.
        let (parsed_ok, product, kind) = st
            .lock()
            .map(|s| {
                (
                    s.finished == Some(true),
                    s.output_path
                        .as_ref()
                        .map(|p| Path::new(p).is_file())
                        .unwrap_or(false),
                    s.kind,
                )
            })
            .unwrap_or((false, false, TargetKind::Exe));

        let ok = code == 0 && (parsed_ok || product);
        self.status = match (ok, kind) {
            // An EXE product is accepted by launching it: still alive after a
            // few seconds means the dump is usable.
            (true, TargetKind::Exe) => Status::Ok(format!("完成 · {secs:.1}s")),
            // A DLL product is *not* accepted by its existence.  The failure
            // this project spent a whole round on was a DLL that loaded, had
            // resolvable exports, and still answered "0.0" because the shell
            // had not finished writing `.bss` when the dump was taken.  So the
            // GUI says what is actually known and points at the gate that
            // proves the rest.
            (true, TargetKind::Dll) => Status::Ok(format!(
                "产物已写出 · {secs:.1}s · 行为需 gate 验证"
            )),
            (false, _) => Status::Failed(format!("失败 · 退出码 {code} · {secs:.1}s")),
        };
        self.last = Some(st);
    }
}

impl eframe::App for App {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.fit_to_screen(ctx);

        if let Some(job) = &mut self.job {
            let (dirty, exit) = job.pump();
            if dirty {
                ctx.request_repaint();
            }
            if let Some(code) = exit {
                self.finish(code);
                ctx.request_repaint();
            } else {
                self.elapsed = job.started_at.elapsed().as_secs_f32();
                ctx.request_repaint_after(std::time::Duration::from_millis(100));
            }
        }

        // Accept EXE and DLL files dragged anywhere onto the window.
        let dropped = ctx.input(|i| {
            i.raw
                .dropped_files
                .iter()
                .filter_map(|f| f.path.clone())
                .find(|p| is_supported(p))
        });
        if let Some(p) = dropped {
            if !self.running() {
                self.pick_input(p);
            }
        }

        self.title_bar(ctx);
        self.rail(ctx);

        egui::CentralPanel::default()
            .frame(
                egui::Frame::NONE
                    .fill(theme::BG)
                    .inner_margin(Margin::symmetric(14, 12)),
            )
            .show(ctx, |ui| {
                let snap = self
                    .view()
                    .and_then(|s| s.lock().ok().map(|g| Snapshot::from(&*g)));
                match snap {
                    Some(s) => self.canvas_run(ui, &s),
                    None => self.canvas_empty(ui),
                }
            });
    }
}

impl App {
    /// Shrink the window to fit the monitor, once, on the first frame.
    ///
    /// `main.rs` asks for 1060x660, which is a guess.  The actual usable area
    /// depends on the monitor and the DPI scale, and on a small or scaled
    /// desktop that guess pushes the window off screen — the symptom being a
    /// log panel and the 开始 button that cannot be reached at all.
    ///
    /// This runs before any panel is laid out, so the very first frame is
    /// already correct; there is no visible resize on startup in the normal
    /// case because the target size only changes when it has to.
    fn fit_to_screen(&mut self, ctx: &egui::Context) {
        if self.fitted {
            return;
        }
        self.fitted = true;

        // `available_rect` is the viewport minus the title bar / taskbar, in
        // points.  Reading it needs a screen rect first, so use the monitor
        // size egui reports for the current viewport.
        let Some(screen) = ctx.input(|i| i.viewport().monitor_size) else {
            return;
        };
        if screen.x <= 0.0 || screen.y <= 0.0 {
            return;
        }

        // Leave room for the OS window frame and the taskbar.  These margins are
        // deliberately generous: a window that is slightly smaller than the
        // screen is a mild waste of space, a window that is larger is unusable.
        let max_w = (screen.x - 48.0).max(720.0);
        let max_h = (screen.y - 96.0).max(480.0);

        let cur = ctx.input(|i| i.viewport().inner_rect.map(|r| r.size()));
        let Some(cur) = cur else { return };

        if cur.x > max_w || cur.y > max_h {
            let target = Vec2::new(cur.x.min(max_w), cur.y.min(max_h));
            ctx.send_viewport_cmd(egui::ViewportCommand::InnerSize(target));
        }
    }
}

/// Rendering snapshot — cloned so the lock is released immediately.
struct Snapshot {
    phase: Option<Phase>,
    kind: TargetKind,
    metrics: Metrics,
    finished: Option<bool>,
    error: Option<String>,
    output_path: Option<String>,
    lines: Vec<LogLine>,
}

impl From<&RunState> for Snapshot {
    fn from(s: &RunState) -> Self {
        Self {
            phase: s.phase,
            kind: s.kind,
            metrics: s.metrics.clone(),
            finished: s.finished,
            error: s.error.clone(),
            output_path: s.output_path.clone(),
            lines: s.lines.clone(),
        }
    }
}

// ---------------------------------------------------------------------------
// Title bar
// ---------------------------------------------------------------------------

impl App {
    fn title_bar(&mut self, ctx: &egui::Context) {
        egui::TopBottomPanel::top("title")
            .exact_height(46.0)
            .frame(
                egui::Frame::NONE
                    .fill(theme::PANEL)
                    .inner_margin(Margin::symmetric(14, 0)),
            )
            .show(ctx, |ui| {
                ui.horizontal_centered(|ui| {
                    ui.label(RichText::new("Magicmida").size(17.0).strong().color(theme::ACCENT));
                    ui.label(RichText::new("RS").size(17.0).strong().color(theme::TEXT));
                    ui.add_space(10.0);
                    pill(ui, "Themida v3 · x64", theme::MUTED);
                    ui.add_space(5.0);
                    // The kind of the file in the picker, not of the last run:
                    // the badge has to answer "what will happen if I press 开始".
                    pill(ui, self.kind.label(), theme::ACCENT);

                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        if self.running() {
                            ui.add(egui::Spinner::new().size(13.0).color(theme::ACCENT));
                            ui.label(
                                RichText::new(format!("{:.1}s", self.elapsed))
                                    .size(12.0)
                                    .font(theme::mono(12.0))
                                    .color(theme::MUTED),
                            );
                        }
                    });
                });
            });
    }
}

// ---------------------------------------------------------------------------
// Left rail
// ---------------------------------------------------------------------------

impl App {
    fn rail(&mut self, ctx: &egui::Context) {
        egui::SidePanel::left("rail")
            .exact_width(RAIL_W)
            .resizable(false)
            .frame(
                egui::Frame::NONE
                    .fill(theme::PANEL)
                    .inner_margin(Margin::symmetric(14, 12)),
            )
            .show(ctx, |ui| {
                ui.add_space(2.0);
                section(ui, "目标");
                ui.add_space(6.0);

                let busy = self.running();
                ui.add_enabled(
                    !busy,
                    egui::TextEdit::singleline(&mut self.input)
                        .desired_width(f32::INFINITY)
                        .hint_text("受 Themida 保护的 .exe / .dll")
                        .font(theme::mono(12.5)),
                );
                ui.add_space(6.0);
                ui.horizontal(|ui| {
                    if ui
                        .add_enabled(!busy, egui::Button::new("浏览…").min_size(Vec2::new(0.0, 26.0)))
                        .clicked()
                    {
                        if let Some(p) = rfd::FileDialog::new()
                            .add_filter("可执行文件 / 动态库", &["exe", "dll"])
                            .pick_file()
                        {
                            self.pick_input(p);
                        }
                    }
                    if ui
                        .add_enabled(
                            !busy && !self.input.is_empty(),
                            egui::Button::new("清除").min_size(Vec2::new(0.0, 26.0)),
                        )
                        .clicked()
                    {
                        self.input.clear();
                        self.output.clear();
                    }
                });

                ui.add_space(12.0);
                section(ui, "输出");
                ui.add_space(6.0);
                ui.add_enabled(
                    !busy,
                    egui::TextEdit::singleline(&mut self.output)
                        .desired_width(f32::INFINITY)
                        .hint_text(if self.kind == TargetKind::Dll {
                            "<输入名>U.dll"
                        } else {
                            "<输入名>U.exe"
                        })
                        .font(theme::mono(12.5)),
                );
                ui.add_space(6.0);
                if ui
                    .add_enabled(!busy, egui::Button::new("另存为…").min_size(Vec2::new(0.0, 26.0)))
                    .clicked()
                {
                    // Match the extension to the target: a DLL dumped to `.exe`
                    // still loads, but the name would mislead every later tool.
                    let (filter_name, filter_ext, default_name) = match self.kind {
                        TargetKind::Dll => ("动态库", "dll", "unpacked.dll"),
                        TargetKind::Exe => ("可执行文件", "exe", "unpacked.exe"),
                    };
                    if let Some(p) = rfd::FileDialog::new()
                        .add_filter(filter_name, &[filter_ext])
                        .set_file_name(default_name)
                        .save_file()
                    {
                        self.output = p.display().to_string();
                    }
                }

                ui.add_space(12.0);
                section(ui, "选项");
                ui.add_space(4.0);
                ui.checkbox(&mut self.verbose, "详细日志");
                hint(ui, "记录每个调试事件，排查用");

                ui.add_space(16.0);
                let can = self.cli.is_some() && !self.input.trim().is_empty();
                if busy {
                    if big_button(ui, "取消", theme::FATAL).clicked() {
                        self.cancel();
                    }
                } else if big_button_enabled(ui, "开始脱壳", can, theme::ACCENT).clicked() {
                    self.start();
                }

                if self.cli.is_none() {
                    ui.add_space(6.0);
                    hint(ui, "未找到 mida-cli.exe，请先 cargo build --release");
                }

                ui.add_space(10.0);
                match &self.status {
                    Status::Idle => {}
                    Status::Running => status_box(ui, theme::ACCENT, "运行中…"),
                    Status::Ok(t) => status_box(ui, theme::GOOD, t),
                    Status::Failed(t) => status_box(ui, theme::FATAL, t),
                }

                ui.with_layout(Layout::bottom_up(Align::Min), |ui| {
                    ui.add_space(2.0);
                    hint(ui, "支持 EXE 与 DLL（Themida v3 · x64）");
                    ui.add_space(2.0);
                    if !self.cjk_ok {
                        hint(ui, "未找到中文字体，部分文字可能显示为方块");
                    }
                });
            });
    }
}

// ---------------------------------------------------------------------------
// Canvas — empty state
// ---------------------------------------------------------------------------

impl App {
    fn canvas_empty(&mut self, ui: &mut Ui) {
        let avail = ui.available_rect_before_wrap();
        ui.allocate_ui_with_layout(avail.size(), Layout::top_down(Align::Center), |ui| {
            ui.add_space((avail.height() * 0.12).max(24.0));

            let size = Vec2::new(avail.width().min(520.0), 132.0);
            let (rect, resp) = ui.allocate_exact_size(size, Sense::hover());
            let hot = resp.hovered();
            let stroke_col = if hot { theme::ACCENT } else { theme::BORDER };
            ui.painter().rect_stroke(
                rect,
                CornerRadius::same(12),
                Stroke::new(1.5_f32, stroke_col),
                StrokeKind::Inside,
            );

            ui.scope_builder(egui::UiBuilder::new().max_rect(rect.shrink(18.0)), |ui| {
                ui.vertical_centered(|ui| {
                    ui.add_space(28.0);
                    ui.label(
                        RichText::new("把 EXE 或 DLL 拖到这里")
                            .size(17.0)
                            .color(if hot { theme::ACCENT } else { theme::TEXT }),
                    );
                    ui.add_space(6.0);
                    ui.label(
                        RichText::new("或使用左侧「浏览…」选择文件")
                            .size(12.0)
                            .color(theme::MUTED),
                    );
                });
            });

            // Give the drop target room before the capability strip; the
            // previous spacing let the strip collide with the dashed box.
            ui.add_space(30.0);
            ui.vertical_centered(|ui| {
                ui.label(RichText::new("已验证能力").size(10.5).color(theme::MUTED));
                ui.add_space(8.0);
                ui.horizontal(|ui| {
                    let total = 3.0 * 146.0 + 2.0 * 8.0;
                    ui.add_space(((ui.available_width() - total) / 2.0).max(0.0));
                    cap(ui, "Themida v3 · x64 EXE", "实测通过", theme::GOOD);
                    ui.add_space(8.0);
                    cap(ui, "Themida v3 · x64 DLL", "实测通过", theme::GOOD);
                    ui.add_space(8.0);
                    cap(ui, "x86 / v1 / v2", "无样本", theme::DIM);
                });
            });
        });
    }

    fn canvas_run(&mut self, ui: &mut Ui, snap: &Snapshot) {
        self.phase_rail(ui, snap);
        ui.add_space(10.0);
        self.metric_grid(ui, snap);
        ui.add_space(8.0);
        self.trace_strip(ui, snap);
        ui.add_space(8.0);
        self.log_panel(ui, snap);
    }

    fn phase_rail(&mut self, ui: &mut Ui, snap: &Snapshot) {
        let current = snap.phase;
        card_frame().show(ui, |ui| {
            ui.horizontal(|ui| {
                for (i, p) in Phase::ALL.iter().enumerate() {
                    let state = match current {
                        Some(c) if c == *p => ChipState::Active,
                        Some(c) if c > *p => ChipState::Done,
                        _ => ChipState::Pending,
                    };
                    if i > 0 {
                        let done = current.is_some_and(|c| c >= *p);
                        let (r, _) = ui.allocate_exact_size(Vec2::new(12.0, 2.0), Sense::hover());
                        ui.painter().line_segment(
                            [r.left_center(), r.right_center()],
                            Stroke::new(2.0_f32, if done { theme::GOOD } else { theme::BORDER }),
                        );
                    }
                    phase_chip(ui, *p, state);
                }
            });
        });
    }

    fn metric_grid(&mut self, ui: &mut Ui, snap: &Snapshot) {
        let m = &snap.metrics;

        ui.columns(4, |c| {
            metric(
                &mut c[0],
                "打包器",
                m.themida_version.clone().unwrap_or_else(|| "—".into()),
                theme::ACCENT,
            );
            metric(&mut c[1], "目标类型", snap.kind.label().to_string(), theme::ACCENT);
            metric(&mut c[2], "OEP", hex(m.oep), theme::TEXT);
            metric(
                &mut c[3],
                "IAT 槽位",
                m.iat_slots.map(|v| v.to_string()).unwrap_or_else(|| "—".into()),
                theme::TEXT,
            );
        });
        ui.add_space(6.0);
        ui.columns(4, |c| {
            metric(
                &mut c[0],
                "导入模块",
                m.module_count.map(|v| v.to_string()).unwrap_or_else(|| "—".into()),
                if m.module_count.is_some() { theme::GOOD } else { theme::TEXT },
            );
            metric(
                &mut c[1],
                "已解析",
                m.resolved.map(|v| v.to_string()).unwrap_or_else(|| "—".into()),
                theme::GOOD,
            );
            metric(
                &mut c[2],
                "失败槽",
                m.failed.map(|v| v.to_string()).unwrap_or_else(|| "—".into()),
                if m.failed.unwrap_or(0) > 0 { theme::WARN } else { theme::TEXT },
            );
            metric(
                &mut c[3],
                "数据槽",
                m.not_import.map(|v| v.to_string()).unwrap_or_else(|| "—".into()),
                theme::MUTED,
            );
        });
        ui.add_space(6.0);
        ui.columns(4, |c| {
            metric(
                &mut c[0],
                "地址重锚",
                m.fixed_addresses.map(|v| v.to_string()).unwrap_or_else(|| "—".into()),
                theme::TEXT,
            );
            metric(
                &mut c[1],
                "重定位",
                m.relocations.map(|v| v.to_string()).unwrap_or_else(|| "—".into()),
                theme::TEXT,
            );
            metric(
                &mut c[2],
                "产物",
                m.output_size.map(human_size).unwrap_or_else(|| "—".into()),
                theme::TEXT,
            );
            metric(
                &mut c[3],
                "验收方式",
                snap.kind.acceptance().to_string(),
                theme::MUTED,
            );
        });
    }

    fn trace_strip(&mut self, ui: &mut Ui, snap: &Snapshot) {
        let m = &snap.metrics;
        card_frame().show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.label(RichText::new("IAT 追踪").size(12.0).color(theme::MUTED));
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    ui.label(
                        RichText::new(m.trace_label())
                            .size(12.5)
                            .font(theme::mono(12.5))
                            .color(if m.trace_done { theme::GOOD } else { theme::TEXT }),
                    );
                });
            });
            ui.add_space(8.0);

            let bar_w = ui.available_width();
            let (rect, _) = ui.allocate_exact_size(Vec2::new(bar_w, 6.0), Sense::hover());
            let track = egui::Rect::from_min_size(rect.min, Vec2::new(bar_w, 6.0));
            let p = ui.painter();
            p.rect_filled(track, CornerRadius::same(3), theme::SURFACE);
            if let Some(f) = m.trace_progress() {
                let filled = egui::Rect::from_min_size(
                    track.min,
                    Vec2::new((bar_w * f).max(2.0), 6.0),
                );
                p.rect_filled(
                    filled,
                    CornerRadius::same(3),
                    if m.trace_done { theme::GOOD } else { theme::ACCENT },
                );
            }
            // Live counters under the bar, so the strip is informative even
            // before the first slot reports in.
            ui.add_space(6.0);
            ui.horizontal(|ui| {
                counter(ui, "已解析", m.resolved, theme::GOOD);
                ui.add_space(14.0);
                counter(ui, "失败", m.failed, theme::WARN);
                ui.add_space(14.0);
                counter(ui, "数据槽", m.not_import, theme::MUTED);
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    if let Some(b) = m.iat_blocks {
                        ui.label(
                            RichText::new(format!("{b} 个碎片块"))
                                .size(11.0)
                                .color(theme::DIM),
                        );
                    }
                });
            });
        });
    }

    /// Write the raw log to a file next to the product, for bug reports.
    fn save_log(&mut self, snap: &Snapshot) {
        let path = rfd::FileDialog::new()
            .set_file_name("mida-gui.log")
            .add_filter("日志", &["log", "txt"])
            .save_file();
        let Some(path) = path else { return };
        let mut text = String::new();
        for l in &snap.lines {
            text.push_str(&format!("{} {:5} {}\n", l.time, level_tag(l.level), l.message));
        }
        self.status = match std::fs::write(&path, text) {
            Ok(()) => Status::Ok(format!("日志已保存：{}", short_name(&path))),
            Err(e) => Status::Failed(format!("保存失败：{e}")),
        };
    }

    fn log_panel(&mut self, ui: &mut Ui, snap: &Snapshot) {
        ui.horizontal(|ui| {
            ui.label(RichText::new("日志").size(12.0).color(theme::MUTED));
            ui.add_space(10.0);
            ui.add(
                egui::TextEdit::singleline(&mut self.log_filter)
                    .desired_width(170.0)
                    .hint_text("过滤…")
                    .font(theme::mono(12.0)),
            );
            ui.checkbox(&mut self.show_debug, "调试行");
            ui.checkbox(&mut self.auto_scroll, "自动滚动");
            if ui.button("保存日志").clicked() {
                self.save_log(snap);
            }

            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                if let Some(err) = &snap.error {
                    ui.label(RichText::new(shorten(err, 64)).size(12.0).color(theme::FATAL));
                } else if snap.finished == Some(true) {
                    if let Some(p) = &snap.output_path {
                        ui.label(
                            RichText::new(format!("→ {}", short_name(Path::new(p))))
                                .size(12.0)
                                .font(theme::mono(12.0))
                                .color(theme::GOOD),
                        );
                    }
                }
            });
        });
        ui.add_space(6.0);

        let h = ui.available_height().max(120.0);
        egui::Frame::NONE
            .fill(theme::PANEL)
            .inner_margin(Margin::symmetric(9, 8))
            .corner_radius(CornerRadius::same(8))
            .stroke(Stroke::new(1.0_f32, theme::BORDER))
            .show(ui, |ui| {
                ui.set_min_height((h - 20.0).max(80.0));
                let needle = self.log_filter.to_lowercase();
                ScrollArea::vertical()
                    .auto_shrink([false, false])
                    .stick_to_bottom(self.auto_scroll)
                    .show(ui, |ui| {
                        // Truncate rather than extend: `Extend` lets a long
                        // line push the scroll area wider than the panel, which
                        // clipped text at the window edge.
                        ui.style_mut().wrap_mode = Some(egui::TextWrapMode::Truncate);
                        for line in &snap.lines {
                            if !self.show_debug && line.level == Level::Debug {
                                continue;
                            }
                            if !needle.is_empty()
                                && !line.message.to_lowercase().contains(&needle)
                            {
                                continue;
                            }
                            log_row(ui, line);
                        }
                    });
            });
    }
}

// ---------------------------------------------------------------------------
// Widgets
// ---------------------------------------------------------------------------

fn card_frame() -> egui::Frame {
    egui::Frame::NONE
        .fill(theme::PANEL)
        .inner_margin(Margin::symmetric(12, 9))
        .corner_radius(CornerRadius::same(8))
        .stroke(Stroke::new(1.0_f32, theme::BORDER))
}

fn section(ui: &mut Ui, text: &str) {
    ui.label(RichText::new(text).size(11.0).strong().color(theme::MUTED));
}

fn hint(ui: &mut Ui, text: &str) {
    ui.label(RichText::new(text).size(11.0).color(theme::DIM));
}

fn pill(ui: &mut Ui, text: &str, color: Color32) {
    egui::Frame::NONE
        .fill(theme::SURFACE)
        .inner_margin(Margin::symmetric(9, 3))
        .corner_radius(CornerRadius::same(20))
        .show(ui, |ui| {
            ui.label(RichText::new(text).size(11.0).color(color));
        });
}

fn big_button(ui: &mut Ui, text: &str, color: Color32) -> egui::Response {
    big_button_enabled(ui, text, true, color)
}

fn big_button_enabled(ui: &mut Ui, text: &str, enabled: bool, color: Color32) -> egui::Response {
    let (rect, resp) = ui.allocate_exact_size(
        Vec2::new(ui.available_width(), 40.0),
        if enabled { Sense::click() } else { Sense::hover() },
    );
    let hovered = enabled && resp.hovered();
    let fill = if !enabled {
        theme::SURFACE
    } else if hovered {
        lighten(color, 0.12)
    } else {
        color
    };
    let text_col = if enabled { theme::BG } else { theme::DIM };

    ui.painter().rect_filled(rect, CornerRadius::same(8), fill);
    ui.painter().text(
        rect.center(),
        egui::Align2::CENTER_CENTER,
        text,
        theme::heading(15.0),
        text_col,
    );
    if hovered {
        ui.ctx().set_cursor_icon(egui::CursorIcon::PointingHand);
    }
    resp
}

fn counter(ui: &mut Ui, label: &str, value: Option<u64>, color: Color32) {
    ui.label(RichText::new(label).size(11.0).color(theme::MUTED));
    ui.label(
        RichText::new(value.map(|v| v.to_string()).unwrap_or_else(|| "—".into()))
            .size(12.0)
            .font(theme::mono(12.0))
            .color(if value.is_some() { color } else { theme::DIM }),
    );
}

fn status_box(ui: &mut Ui, color: Color32, text: &str) {
    egui::Frame::NONE
        .fill(theme::SURFACE)
        .inner_margin(Margin::symmetric(10, 8))
        .corner_radius(CornerRadius::same(6))
        .stroke(Stroke::new(1.0_f32, color.gamma_multiply(0.35)))
        .show(ui, |ui| {
            ui.label(RichText::new(text).size(12.0).color(color));
        });
}

enum ChipState {
    Pending,
    Active,
    Done,
}

fn phase_chip(ui: &mut Ui, p: Phase, state: ChipState) {
    let (fg, bg) = match state {
        ChipState::Active => (theme::BG, theme::ACCENT),
        ChipState::Done => (theme::GOOD, theme::SURFACE),
        ChipState::Pending => (theme::MUTED, theme::SURFACE),
    };
    egui::Frame::NONE
        .fill(bg)
        .inner_margin(Margin::symmetric(11, 5))
        .corner_radius(CornerRadius::same(20))
        .show(ui, |ui| {
            ui.label(RichText::new(p.label()).size(12.0).color(fg));
        });
}

fn metric(ui: &mut Ui, label: &str, value: String, color: Color32) {
    egui::Frame::NONE
        .fill(theme::PANEL)
        .inner_margin(Margin::symmetric(11, 8))
        .corner_radius(CornerRadius::same(7))
        .stroke(Stroke::new(1.0_f32, theme::BORDER))
        .show(ui, |ui| {
            ui.vertical(|ui| {
                ui.label(RichText::new(label).size(10.5).color(theme::MUTED));
                ui.add_space(2.0);
                ui.label(
                    RichText::new(value)
                        .size(15.0)
                        .font(theme::mono(15.0))
                        .color(color),
                );
            });
        });
}

fn cap(ui: &mut Ui, title: &str, note: &str, color: Color32) {
    egui::Frame::NONE
        .fill(theme::PANEL)
        .inner_margin(Margin::symmetric(10, 8))
        .corner_radius(CornerRadius::same(7))
        .stroke(Stroke::new(1.0_f32, theme::BORDER))
        .show(ui, |ui| {
            ui.set_width(146.0);
            ui.vertical(|ui| {
                ui.label(RichText::new(title).size(11.5).color(theme::TEXT));
                ui.add_space(2.0);
                ui.label(RichText::new(note).size(10.5).color(color));
            });
        });
}

fn log_row(ui: &mut Ui, line: &LogLine) {
    let color = theme::level_color(line.level);
    let dim = matches!(line.level, Level::Debug);

    // Draw the row manually instead of nesting layouts: a `horizontal` with
    // three children lets a long message push the row wider than the panel,
    // which is what clipped text at the window edge.
    let full_w = ui.available_width();
    let row_h = 16.0;
    let (rect, resp) = ui.allocate_exact_size(Vec2::new(full_w, row_h), Sense::hover());
    let painter = ui.painter();
    let font_small = theme::mono(11.0);
    let font_msg = theme::mono(12.0);

    let mut x = rect.left();
    let mid_y = rect.center().y;

    let stamp = if line.time.is_empty() { "--:--:--" } else { &line.time };
    painter.text(
        egui::pos2(x, mid_y),
        egui::Align2::LEFT_CENTER,
        stamp,
        font_small.clone(),
        theme::DIM,
    );
    x += 62.0;

    painter.text(
        egui::pos2(x, mid_y),
        egui::Align2::LEFT_CENTER,
        level_tag(line.level),
        font_small,
        if dim { theme::DIM } else { color },
    );
    x += 42.0;

    // Clip the message to what is left of the row.
    let msg_rect = egui::Rect::from_min_max(
        egui::pos2(x, rect.top()),
        egui::pos2(rect.right(), rect.bottom()),
    );
    painter.with_clip_rect(msg_rect).text(
        egui::pos2(x, mid_y),
        egui::Align2::LEFT_CENTER,
        &line.message,
        font_msg,
        color,
    );

    if resp.hovered() {
        // Show the full text on hover when it was clipped.
        resp.on_hover_text(&line.message);
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn level_tag(level: Level) -> &'static str {
    match level {
        Level::Good => "GOOD",
        Level::Warn => "WARN",
        Level::Fatal => "FAIL",
        Level::Debug => "DBUG",
        Level::Info => "INFO",
    }
}

fn lighten(c: Color32, amount: f32) -> Color32 {
    let f = |v: u8| ((v as f32) + (255.0 - v as f32) * amount).min(255.0) as u8;
    Color32::from_rgb(f(c.r()), f(c.g()), f(c.b()))
}

fn hex(v: Option<u64>) -> String {
    match v {
        Some(x) => format!("0x{x:x}"),
        None => "—".into(),
    }
}

fn human_size(n: u64) -> String {
    const KB: f64 = 1024.0;
    let f = n as f64;
    if f >= KB * KB {
        format!("{:.2} MB", f / (KB * KB))
    } else if f >= KB {
        format!("{:.1} KB", f / KB)
    } else {
        format!("{n} B")
    }
}

fn short_name(p: &Path) -> String {
    p.file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("?")
        .to_string()
}

fn shorten(s: &str, n: usize) -> String {
    if s.chars().count() <= n {
        s.to_string()
    } else {
        let head: String = s.chars().take(n).collect();
        format!("{head}…")
    }
}

fn default_output(input: &Path) -> PathBuf {
    let stem = input.file_stem().and_then(|s| s.to_str()).unwrap_or("unpacked");
    let ext = input.extension().and_then(|s| s.to_str()).unwrap_or("exe");
    let parent = input.parent().unwrap_or_else(|| Path::new("."));
    parent.join(format!("{stem}U.{ext}"))
}

/// Extensions the CLI accepts as unpack targets.
///
/// The pipeline dispatches on the PE header, not the extension, but the GUI
/// needs a cheap filter for drag-and-drop and the file picker.
fn is_supported(p: &Path) -> bool {
    p.extension()
        .and_then(|e| e.to_str())
        .is_some_and(|e| e.eq_ignore_ascii_case("exe") || e.eq_ignore_ascii_case("dll"))
}

