"""One-shot: extract post-attach fast path from unpacker mod.rs."""
from pathlib import Path

mod_path = Path(r"crates/cli/src/unpacker/mod.rs")
lines = mod_path.read_text(encoding="utf-8").splitlines(True)

# Content inside `if post_attach_mode { ... }` (1-indexed 456..730)
body = lines[455:730]
dedented = []
for l in body:
    if l.startswith("        "):
        dedented.append(l[4:])
    else:
        dedented.append(l)

header = '''//! Post-attach fast path (no debug port): observe .text, freeze, dump.
//!
//! Extracted from `mod.rs` (P1 host thin split / unattended engineering).
//! Used when section 0 is plain `.text` and the target is not .NET — create
//! without DEBUG_ONLY_THIS_PROCESS, capture early snapshots, poll until
//! decrypted .text execution, then hand off to [`run_post_loop_phases`].
//!
//! Shared `ThemidaState` host remains; this is not an independent GTO pipeline.

use std::path::Path;

use anyhow::anyhow;
use windows::Win32::System::Threading::{ResumeThread, SuspendThread};

use crate::log::{self, LogType};
use mida_core::PluginCtx;
use mida_packers_themida::ThemidaState;
use mida_pe::{ContainerRestoreMode, DumpProfile, EarlySectionSnapshot, OepPolicy, PeHeader};

use super::early_snapshots::{
    log_snapshot_summary, merge_reinitializable_data_state, refresh_early_snapshots_after_loader,
    update_pre_text_snapshots,
};
use super::plugin_host::{enter_dump_phase, SelectedPacker};
use super::post_loop::run_post_loop_phases;
use super::session::ProcessSession;

/// Post-attach observation + freeze + post-loop dump.
///
/// Caller has already created the process, captured early snapshots, resumed
/// the main thread, and applied plugin session defaults.
pub(super) fn run_post_attach_path(
    dbg: &mut ProcessSession,
    state: &mut ThemidaState,
    pe: &mut PeHeader,
    packer: &mut SelectedPacker,
    plugin_ctx: &mut PluginCtx,
    early_section_snapshots: &mut Vec<EarlySectionSnapshot>,
    is_dotnet: bool,
    is_64bit: bool,
    do_data_sections: bool,
    shrink: bool,
    oep_policy: OepPolicy,
    container_restore: ContainerRestoreMode,
    profile: DumpProfile,
    pure_rebuild: bool,
    input: &Path,
    output_path: &Path,
) -> Result<(), anyhow::Error> {
'''

footer = "}\n"

out = Path(r"crates/cli/src/unpacker/post_attach.rs")
out.write_text(header + "".join(dedented) + footer, encoding="utf-8")
print("wrote", out, "lines", len(out.read_text(encoding="utf-8").splitlines()))

text = mod_path.read_text(encoding="utf-8")
if "mod post_attach;" not in text:
    text = text.replace("mod post_loop;\n", "mod post_loop;\nmod post_attach;\n")
if "run_post_attach_path" not in text.split("fn unpack")[0]:
    text = text.replace(
        "use post_loop::run_post_loop_phases;\n",
        "use post_attach::run_post_attach_path;\nuse post_loop::run_post_loop_phases;\n",
    )

new_lines = text.splitlines(True)
start = None
end = None
for i, l in enumerate(new_lines):
    if l.strip() == "// ---- post-attach fast path: no debug port, direct dump ----":
        start = i
        break
if start is None:
    raise SystemExit("start marker not found")

for i in range(start, len(new_lines)):
    if new_lines[i].strip() != "return Ok(());":
        continue
    # expect: return Ok; closing `}` of if; blank; main debug loop comment
    if i + 1 >= len(new_lines) or new_lines[i + 1].strip() != "}":
        continue
    window = "".join(new_lines[i + 1 : i + 6])
    if "main debug loop" in window:
        end = i + 2  # exclusive: drop through closing }
        break

if end is None:
    raise SystemExit("end of post-attach block not found")

print("replace lines", start + 1, "to", end)

replacement = '''    // ---- post-attach fast path: no debug port, direct dump ----
    // Observe the freely running primary thread, freeze it on its first
    // transfer into decrypted .text, then go straight to the dump phase.
    // Body: `post_attach::run_post_attach_path`.
    if post_attach_mode {
        return run_post_attach_path(
            &mut dbg,
            &mut state,
            &mut pe,
            &mut packer,
            &mut plugin_ctx,
            &mut early_section_snapshots,
            is_dotnet,
            is_64bit,
            do_data_sections,
            shrink,
            oep_policy,
            container_restore,
            profile,
            pure_rebuild,
            input,
            &output_path,
        );
    }

'''

joined = "".join(new_lines[:start] + [replacement] + new_lines[end:])
mod_path.write_text(joined, encoding="utf-8")
print("mod.rs lines", len(joined.splitlines()))
for i, l in enumerate(joined.splitlines()):
    if "SuspendThread" in l or "ResumeThread" in l:
        print(f"mod still uses thread API L{i+1}: {l.strip()[:80]}")
