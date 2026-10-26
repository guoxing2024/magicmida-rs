//! Interactive guided mode — the entry point for first-time users.
//!
//! Running `mida-cli` with no arguments used to print an error and exit 1:
//! the worst possible welcome for the exact audience that needs one.  This
//! module replaces that with a three-step walkthrough — pick a file, see what
//! static analysis recognises, confirm one suggested command — and then runs
//! it through the ordinary [`crate::commands::run_command`] dispatch, so the
//! wizard can never diverge from what the same command line would have done.
//!
//! The detection gates and their **order** mirror `analyze.rs` exactly
//! (VMProtect → UPX → Themida): the wizard shows the same verdict the
//! explicit command would produce, not a third opinion.
//!
//! The prompts are in Chinese to match the GUI, which is the other
//! beginner-facing surface; the command lines themselves stay in the CLI's
//! English so copy-pasting one out of the wizard keeps working verbatim.

use std::io::{self, BufRead, IsTerminal, Write};
use std::path::{Path, PathBuf};

use anyhow::Context;
use mida_pe::PeHeader;

use crate::args::{Command, PackerChoice};
use crate::log;

/// What static recognition concluded about the picked file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// Themida sections (`.winlice` / `.boot` / `.themida` or the
    /// unnamed-exec-write shape) — the pipeline this project is built around.
    Themida,
    /// VMProtect with the mode label from its own detector.
    VmProtect(String),
    /// UPX — fully static, the cheapest path in the whole tool.
    Upx,
    /// A parseable PE that no gate recognises, or not a PE at all.
    NotPe(String),
}

/// The gate verdict for an already-parsed image — the pure, testable core of
/// [`detect_verdict`].  Gate order mirrors `analyze.rs`: VMProtect, then UPX,
/// then Themida's section markers.
pub fn verdict_of_pe(pe: &PeHeader, image: &[u8]) -> Verdict {
    if let Some(d) = mida_packers_vmprotect::detect(pe, image) {
        return Verdict::VmProtect(d.summary());
    }
    if mida_packers_upx::detect(pe, image).is_some() {
        return Verdict::Upx;
    }
    let themida: Vec<&str> = pe
        .sections
        .iter()
        .filter(|s| mida_packers_themida::is_themida_section(s))
        .map(|s| s.name.as_str())
        .collect();
    if !themida.is_empty() {
        return Verdict::Themida;
    }
    Verdict::NotPe("文件是 PE，但没有任何已识别的加壳特征".into())
}

/// Read `path` and run the recognition gates over it.
fn detect_verdict(path: &Path) -> Result<Verdict, anyhow::Error> {
    let image = std::fs::read(path)
        .with_context(|| format!("无法读取文件：{}", path.display()))?;
    let pe = PeHeader::from_bytes(&image)
        .with_context(|| format!("无法解析 PE 头：{}", path.display()))?;
    Ok(verdict_of_pe(&pe, &image))
}

/// What the wizard suggests doing, derived from the verdict alone.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    /// `/unpack --packer upx` — no process, no window, no desktop session.
    UnpackStatic,
    /// `/unpack` through the Themida pipeline — needs an interactive desktop.
    UnpackLive,
    /// `/analyze --extract` — look before touching anything experimental.
    AnalyzeExtract,
}

/// The verdict's one-line summary, the advice the wizard prints under it, and
/// the action behind the suggestion.
///
/// Pure so the wording and the action stay testable without any file on disk.
pub fn plan_for(verdict: &Verdict) -> (String, String, Action) {
    match verdict {
        Verdict::Upx => (
            "UPX 加壳".into(),
            "UPX 的整个原始镜像在文件里就能静态还原 —— 不创建进程、不弹窗口，\
             是最安全也最快的一条路。"
                .into(),
            Action::UnpackStatic,
        ),
        Verdict::Themida => (
            "Themida 加壳".into(),
            "需要在有桌面的环境里运行：工具会启动目标并注入反反调试，\
             目标自己的窗口会真实弹出，属正常现象，不要关闭它们。"
                .into(),
            Action::UnpackLive,
        ),
        Verdict::VmProtect(mode) => (
            format!("VMProtect 加壳（{mode}）"),
            "先跑一次静态分析看结构与证据；提取出的是载荷/解码结果。\
             VMProtect 的完整脱壳是实验性的，稳一点先看分析输出。"
                .into(),
            Action::AnalyzeExtract,
        ),
        Verdict::NotPe(reason) => (
            "无法识别".into(),
            reason.clone(),
            Action::AnalyzeExtract,
        ),
    }
}

/// Validate a user-typed path: non-empty, exists, is a file.
///
/// Returns the message to show when it fails, so the wizard's loop stays thin.
pub fn validate_path(raw: &str) -> Result<PathBuf, String> {
    let trimmed = raw.trim().trim_matches('"');
    if trimmed.is_empty() {
        return Err("路径为空，请输入 .exe 或 .dll 文件的完整路径".into());
    }
    let p = PathBuf::from(trimmed);
    if !p.exists() {
        return Err(format!("文件不存在：{}", p.display()));
    }
    if !p.is_file() {
        return Err(format!("这不是一个文件：{}", p.display()));
    }
    Ok(p)
}

/// `<stem>U.<ext>` — the same default the CLI and GUI use, so all three
/// surfaces agree on where the product lands.
pub fn default_output(input: &Path) -> PathBuf {
    let stem = input.file_stem().and_then(|s| s.to_str()).unwrap_or("unpacked");
    let ext = input.extension().and_then(|s| s.to_str()).unwrap_or("exe");
    match input.parent() {
        Some(parent) => parent.join(format!("{stem}U.{ext}")),
        None => PathBuf::from(format!("{stem}U.{ext}")),
    }
}

// ---------------------------------------------------------------------------
// Wizard
// ---------------------------------------------------------------------------

/// Run the guided mode.
///
/// `forced` is `true` when the user spelled `interactive`/`-i` explicitly.
/// An unforced invocation (bare `mida-cli`) with a non-terminal stdin — a
/// script, a service, an AI client spawning the binary headless — prints the
/// friendly help and exits 0 instead of blocking on a prompt nobody can
/// answer.  An explicit spelling always runs, so piped answers drive the
/// wizard end to end (this is also how the smoke test exercises it).
pub fn run(forced: bool) -> Result<(), anyhow::Error> {
    if !forced && !io::stdin().is_terminal() {
        crate::commands::print_help();
        return Ok(());
    }

    println!(
        "Magicmida-RS v{} · 引导模式",
        env!("CARGO_PKG_VERSION")
    );
    println!("逐项回答即可；直接回车采用 [默认值]。输入 q 退出。\n");

    // Once, up front: `set_global_default` fails on the second call and
    // `init_logging` would print a warning every loop iteration otherwise.
    log::init_logging(false);

    loop {
        // [1/3] the file, validated in a loop until it works or the user quits.
        let input = loop {
            let Some(raw) = prompt("[1/3] 文件路径（.exe / .dll）") else {
                return Ok(());
            };
            if raw.trim().eq_ignore_ascii_case("q") {
                println!("已退出。");
                return Ok(());
            }
            match validate_path(&raw) {
                Ok(p) => break p,
                Err(msg) => println!("  ✗ {msg}（重试，或输入 q 退出）\n"),
            }
        };

        // Verdict + advice, then the one suggested command.
        let verdict = match detect_verdict(&input) {
            Ok(v) => v,
            Err(e) => {
                println!("  ✗ {e:#}\n");
                continue;
            }
        };
        let (summary, advice, action) = plan_for(&verdict);
        println!("\n  识别结果：{summary}");
        println!("  {advice}");

        // [2/3] the paths the chosen action needs.
        let cmd = match action {
            Action::AnalyzeExtract => {
                let default_dir = default_output(&input)
                    .with_extension("")
                    .with_added_extension("payloads");
                let Some(dir) = prompt_default("[2/3] 载荷提取目录", &default_dir.display().to_string())
                else {
                    return Ok(());
                };
                let dir = if dir.trim().is_empty() { default_dir } else { PathBuf::from(dir.trim().trim_matches('"')) };
                Command::Analyze {
                    input: input.clone(),
                    extract_to: Some(dir),
                    verbose: false,
                }
            }
            Action::UnpackStatic | Action::UnpackLive => {
                let default_out = default_output(&input);
                let Some(out) = prompt_default("[2/3] 输出路径", &default_out.display().to_string())
                else {
                    return Ok(());
                };
                let out = if out.trim().is_empty() {
                    default_out
                } else {
                    PathBuf::from(out.trim().trim_matches('"'))
                };
                let packer = match action {
                    Action::UnpackStatic => PackerChoice::Upx,
                    _ => PackerChoice::Auto,
                };
                Command::Unpack {
                    input: input.clone(),
                    output: Some(out),
                    create_data_sections: false,
                    shrink: true,
                    verbose: false,
                    packer,
                }
            }
        };

        // [3/3] confirm, showing exactly what will run.
        println!("\n  将执行：{}", describe(&cmd));
        let Some(go) = confirm("[3/3] 确认执行", true) else {
            return Ok(());
        };
        if !go {
            println!("已取消，未执行任何操作。\n");
            continue;
        }

        println!();
        let started = std::time::Instant::now();
        match crate::commands::run_command(cmd) {
            Ok(()) => println!("\n✓ 完成（{:.1}s）。", started.elapsed().as_secs_f32()),
            Err(e) => println!("\n✗ 失败：{e:#}"),
        }

        let Some(again) = confirm("\n再处理一个文件", false) else {
            return Ok(());
        };
        if !again {
            println!("再见。");
            return Ok(());
        }
        println!();
    }
}

/// One-line description of the command the wizard is about to run, so the
/// confirmation step names the real thing (and so a user can copy it).
fn describe(cmd: &Command) -> String {
    match cmd {
        Command::Unpack { input, output, packer, .. } => {
            let packer = match packer {
                PackerChoice::Upx => " --packer upx".to_string(),
                PackerChoice::Auto => String::new(),
                other => format!(" --packer {}", format!("{other:?}").to_lowercase()),
            };
            format!(
                "mida-cli /unpack {}{packer} -o {}",
                input.display(),
                output.as_ref().map(|p| p.display().to_string()).unwrap_or_default()
            )
        }
        Command::Analyze { input, extract_to, .. } => {
            let extract = extract_to
                .as_ref()
                .map(|d| format!(" --extract {}", d.display()))
                .unwrap_or_default();
            format!("mida-cli /analyze {}{extract}", input.display())
        }
        other => format!("{other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Prompt helpers — all EOF-safe: `None` ends the wizard gracefully.
// ---------------------------------------------------------------------------

/// Read one line from stdin, `None` on EOF (piped input exhausted, or Ctrl+Z
/// on Windows).  The wizard treats `None` as "leave, nothing more to answer".
fn read_line() -> Option<String> {
    let mut buf = String::new();
    match io::stdin().lock().read_line(&mut buf) {
        Ok(0) => None,
        Ok(_) => Some(buf.trim_end_matches(['\n', '\r']).to_string()),
        Err(_) => None,
    }
}

/// Print a prompt and read the answer.
fn prompt(label: &str) -> Option<String> {
    print!("{label}\n> ");
    let _ = io::stdout().flush();
    read_line()
}

/// Print a prompt with a `[default]` and read the answer; an empty answer
/// means "use the default" (returned as `Some(String::new())`).
fn prompt_default(label: &str, default: &str) -> Option<String> {
    print!("{label} [{default}]\n> ");
    let _ = io::stdout().flush();
    read_line()
}

/// Yes/no prompt; empty accepts the default.
fn confirm(label: &str, default_yes: bool) -> Option<bool> {
    let hint = if default_yes { "Y/n" } else { "y/N" };
    loop {
        let Some(raw) = prompt_default(label, hint) else {
            return None;
        };
        return match raw.trim() {
            "" => Some(default_yes),
            s if s.eq_ignore_ascii_case("y") || s.eq_ignore_ascii_case("yes") => Some(true),
            s if s.eq_ignore_ascii_case("n") || s.eq_ignore_ascii_case("no") => Some(false),
            _ => {
                println!("  请回答 y 或 n。");
                continue;
            }
        };
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use mida_pe::{
        ImageDataDirectory, ImageDosHeader, ImageFileHeader, ImageNtHeaders, ImageOptionalHeader,
        ImageSectionHeader,
    };

    /// A minimal PE32+ header carrying `sections`, hand-written field by field
    /// (same shape as the packer crates' fixtures).
    fn pe_with(sections: Vec<mida_pe::PeSection>) -> PeHeader {
        let n = sections.len() as u16;
        PeHeader {
            dos_header: ImageDosHeader { e_magic: 0x5a4d, e_lfanew: 0x80 },
            nt_headers: ImageNtHeaders {
                signature: 0x0000_4550,
                file_header: ImageFileHeader {
                    machine: 0x8664,
                    number_of_sections: n,
                    time_date_stamp: 0,
                    size_of_optional_header: 0xf0,
                    characteristics: 0x22,
                },
                optional_header: ImageOptionalHeader {
                    magic: 0x20b,
                    major_linker_version: 14,
                    minor_linker_version: 44,
                    size_of_code: 0,
                    size_of_initialized_data: 0,
                    size_of_uninitialized_data: 0,
                    address_of_entry_point: 0,
                    base_of_code: 0,
                    base_of_data: None,
                    image_base: 0x1_4000_0000,
                    section_alignment: 0x1000,
                    file_alignment: 0x200,
                    major_operating_system_version: 6,
                    minor_operating_system_version: 0,
                    major_image_version: 0,
                    minor_image_version: 0,
                    major_subsystem_version: 6,
                    minor_subsystem_version: 0,
                    win32_version_value: 0,
                    size_of_image: 0,
                    size_of_headers: 0x400,
                    check_sum: 0,
                    subsystem: 2,
                    dll_characteristics: 0x8160,
                    size_of_stack_reserve: 0,
                    size_of_stack_commit: 0,
                    size_of_heap_reserve: 0,
                    size_of_heap_commit: 0,
                    loader_flags: 0,
                    number_of_rva_and_sizes: 16,
                    data_directory: [ImageDataDirectory::default(); 16],
                },
            },
            sections,
            image_base: 0x1_4000_0000,
            entry_point: 0,
            is_64bit: true,
            file_alignment: 0x200,
            section_alignment: 0x1000,
        }
    }

    fn sec(name: &str, chars: u32) -> mida_pe::PeSection {
        mida_pe::PeSection {
            header: ImageSectionHeader {
                name: [0; 8],
                virtual_size: 0x1000,
                virtual_address: 0x1000,
                size_of_raw_data: 0x200,
                pointer_to_raw_data: 0x400,
                pointer_to_relocations: 0,
                pointer_to_linenumbers: 0,
                number_of_relocations: 0,
                number_of_linenumbers: 0,
                characteristics: chars,
            },
            name: name.to_string(),
            virtual_address: 0x1000,
            virtual_size: 0x1000,
            raw_offset: 0x400,
            raw_size: 0x200,
            characteristics: chars,
            extra_data: None,
        }
    }

    #[test]
    fn a_boot_section_is_recognised_as_themida() {
        let pe = pe_with(vec![
            sec(".text", 0x6000_0020),
            sec(".boot", 0xe000_00e0),
        ]);
        let image = vec![0u8; 0x1000];
        assert_eq!(verdict_of_pe(&pe, &image), Verdict::Themida);
    }

    #[test]
    fn a_plain_pe_has_no_verdict() {
        let pe = pe_with(vec![sec(".text", 0x6000_0020)]);
        let image = vec![0u8; 0x1000];
        let Verdict::NotPe(_) = verdict_of_pe(&pe, &image) else {
            panic!("a plain PE must not be called Themida/VMProtect/UPX");
        };
    }

    #[test]
    fn upx_magic_without_upx_sections_is_not_upx() {
        // The detection requires both the header and the named sections; a
        // bare magic in an image with normal sections must not win the gate.
        let pe = pe_with(vec![sec(".text", 0x6000_0020)]);
        let mut image = vec![0u8; 0x1000];
        image[0x10..0x14].copy_from_slice(b"UPX!");
        let Verdict::NotPe(_) = verdict_of_pe(&pe, &image) else {
            panic!("a stray UPX! must not produce Verdict::Upx");
        };
    }

    #[test]
    fn plans_carry_the_right_advice_and_action() {
        let (summary, advice, action) = plan_for(&Verdict::Upx);
        assert_eq!(action, Action::UnpackStatic);
        assert!(summary.contains("UPX"));
        assert!(advice.contains("不创建进程"), "{advice}");

        let (summary, advice, action) = plan_for(&Verdict::Themida);
        assert_eq!(action, Action::UnpackLive);
        assert!(summary.contains("Themida"));
        assert!(advice.contains("桌面"), "{advice}");

        let (summary, _, action) = plan_for(&Verdict::VmProtect("min-protection".into()));
        assert_eq!(action, Action::AnalyzeExtract);
        assert!(summary.contains("min-protection"));
    }

    #[test]
    fn path_validation_rejects_empty_missing_and_directories() {
        assert!(validate_path("").is_err());
        assert!(validate_path("   ").is_err());
        assert!(validate_path("no-such-file-xyz-123.exe").unwrap_err().contains("不存在"));
        // A directory exists but is not a file.
        assert!(validate_path("src").unwrap_err().contains("不是一个文件"));
        // Quote-wrapped paths (from "Copy as path") are accepted.
        assert_eq!(
            validate_path("\"Cargo.toml\"").unwrap(),
            PathBuf::from("Cargo.toml")
        );
        assert!(validate_path("Cargo.toml").is_ok());
    }

    #[test]
    fn default_output_matches_the_cli_convention() {
        assert_eq!(
            default_output(Path::new("D:\\samples\\target.exe")),
            PathBuf::from("D:\\samples\\targetU.exe")
        );
        assert_eq!(
            default_output(Path::new("core.dll")),
            PathBuf::from("coreU.dll")
        );
    }

    #[test]
    fn describe_shows_a_copyable_command_line() {
        let cmd = Command::Unpack {
            input: PathBuf::from("t.exe"),
            output: Some(PathBuf::from("tU.exe")),
            create_data_sections: false,
            shrink: true,
            verbose: false,
            packer: PackerChoice::Upx,
        };
        assert_eq!(describe(&cmd), "mida-cli /unpack t.exe --packer upx -o tU.exe");

        let cmd = Command::Analyze {
            input: PathBuf::from("t.exe"),
            extract_to: Some(PathBuf::from("out")),
            verbose: false,
        };
        assert_eq!(describe(&cmd), "mida-cli /analyze t.exe --extract out");
    }
}
