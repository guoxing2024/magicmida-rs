@echo off
REM Stage and commit debugger context hardening only (no temp tools, no PE).
cd /d "D:\Claude project\magicmida-rs"
git add ^
  crates/core/src/windows_debugger.rs ^
  crates/cli/src/unpacker/av_handler.rs ^
  crates/cli/src/unpacker/generic.rs ^
  crates/cli/src/unpacker/session.rs ^
  crates/packers/themida/src/binaries.rs ^
  docs/PROJECT_AUDIT_AND_ROADMAP.md ^
  WORKER_HANDOFF.md
git --no-pager status -sb
git --no-pager diff --cached --stat
git commit -m "fix(core): Win11 SetThreadContext CONTROL|INTEGER for Themida live" -m "Prefer CONTEXT_CONTROL|INTEGER over CONTEXT_ALL/XSAVE for Get/SetThreadContext, with OpenThread GET|SET|SUSPEND and SuspendThread retry. Soft-fail virtualized OEP and control-path SetThreadContext in the unpacker so IAT tracing can continue. Generic poll section falls back when names are wiped. Update ScyllaHide InjectorCLIx64 trusted hash for local staging set." -m "Evidence: Origin live_20260723-132326 and resmoke1 StructuralPassBehaviorPending under vault." -m "Co-authored-by: openhands <openhands@all-hands.dev>"
git --no-pager log -1 --stat
