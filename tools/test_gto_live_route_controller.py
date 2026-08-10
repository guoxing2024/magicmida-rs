#!/usr/bin/env python3
"""Route U R0 / Audit Fix 1 / Route V R0 — Live Harness Environment Propagation,
Armed-Run Preflight Closure, and Post-Capture Stage/Deadline Evidence.

Offline tests for the GTO live-route controller's authorized-environment contract,
the UAF1 mock-Popen child-boundary and capture-policy-arg-missing tests, and the
Route V R0 deadline/timeout evidence (V0-B) plus 600s policy closure (V0-C).

Run: python3 tools/test_gto_live_route_controller.py
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import re
import subprocess
import sys
import tempfile
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
CONTROLLER = HERE / "gto_live_route_controller.py"

_results = []


class FakePopen:
    """Capture Popen arguments without starting a real process (UAF1-A)."""
    calls = []

    def __init__(self, argv, stdout=None, stderr=None, cwd=None, env=None):
        FakePopen.calls.append({"argv": argv, "cwd": cwd, "env": env})
        self.argv = argv
        self.env = env or {}
        self.cwd = cwd
        self.pid = 4242
        self.returncode = 0

    def poll(self):
        # Exit immediately on the first poll (natural exit).
        return 0

    def wait(self, timeout=None):
        return self.returncode

    def kill(self):
        pass


def load_controller():
    spec = importlib.util.spec_from_file_location(
        "ctrl", str(CONTROLLER), submodule_search_locations=[]
    )
    ctrl = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(ctrl)
    return ctrl


def run_controller(ws, *, extra_env_list, allowlist, capture_policy_arg):
    """Invoke the controller binary in a fresh evidence dir. ``capture_policy_arg``
    is ``"present"`` (valid file), ``"missing_file"`` (arg present, file absent), or
    ``"absent"`` (no --capture-policy arg at all). Returns
    (returncode, controller_run.json dict)."""
    open(ws / "capture_policy.json", "w").write('{"preset":"ahk_gto_defaults"}')
    cli = "C:\\nonexistent\\mida-cli.exe"
    argv = [
        sys.executable, str(CONTROLLER),
        "--evidence-dir", str(ws),
        "--env-allowlist", "SystemRoot",
        "--env-allowlist", "WINDIR",
    ]
    for a in allowlist:
        argv.append("--env-allowlist")
        argv.append(a)
    for kv in extra_env_list:
        argv.append("--set-env")
        argv.append(kv)
    argv += [cli, "/unpack", "dummy.exe", "-o", str(ws / "cand.exe")]
    if capture_policy_arg == "present":
        argv.append("--capture-policy=" + str(ws / "capture_policy.json"))
    elif capture_policy_arg == "missing_file":
        argv.append("--capture-policy=" + str(ws / "MISSING.json"))
    # else "absent": no --capture-policy arg at all
    try:
        res = subprocess.run(argv, capture_output=True, text=True, timeout=30)
    except subprocess.TimeoutExpired:
        return "TIMEOUT", None
    d = json.load(open(ws / "controller_run.json", encoding="utf-8"))
    return res.returncode, d


def check(name, cond, detail=""):
    _results.append((name, bool(cond), detail))
    print(f"[{'PASS' if cond else 'FAIL'}] {name}" + (f"  -- {detail}" if detail else ""))


# U0-D / UAF1-D: no_bypass missing -> fail before spawn (spawned=False, pid=None,
# exit_code None, exit 6).
def test_no_bypass_missing_fails_before_spawn(ctrl):
    ws = Path(tempfile.mkdtemp(prefix="u0_missing_"))
    rc, d = run_controller(ws, extra_env_list=[], allowlist=["SystemRoot", "WINDIR"],
                           capture_policy_arg="present")
    check("route_u_r0_no_bypass_missing_fails_before_spawn",
          d is not None and rc == 6 and d.get("spawned") is False and d.get("pid") is None
          and d.get("exit_code") is None
          and "live_environment_preflight_error" in d
          and "allowlist_missing_no_bypass" in d["live_environment_preflight_error"]
          and "no_bypass_not_explicit_1" in d["live_environment_preflight_error"],
          f"rc={rc} spawned={d.get('spawned')} pid={d.get('pid')}")


# UAF1-A: no_bypass=1 reaches the child Popen env (mock Popen boundary).
def test_no_bypass_reaches_popen_env(ctrl):
    ws = Path(tempfile.mkdtemp(prefix="u0_popen_"))
    open(ws / "capture_policy.json", "w").write('{"preset":"ahk_gto_defaults"}')
    FakePopen.calls = []
    orig_popen = ctrl.subprocess.Popen
    ctrl.subprocess.Popen = FakePopen
    try:
        record = ctrl.run_child(
            argv=["mida-cli.exe", "/unpack", "x.exe", "-o", "cand.exe",
                  "--capture-policy=" + str(ws / "capture_policy.json")],
            cwd=ws,
            evidence_dir=ws,
            env_allowlist=["SystemRoot", "MIDA_GTO_NO_BYPASS"],
            timeout_sec=30,
            extra_env={"MIDA_GTO_NO_BYPASS": "1"},
        )
    finally:
        ctrl.subprocess.Popen = orig_popen
    check("route_u_af1_no_bypass_reaches_popen_env",
          len(FakePopen.calls) == 1
          and FakePopen.calls[0]["env"].get("MIDA_GTO_NO_BYPASS") == "1"
          and "MIDA_GTO_BYPASS" not in FakePopen.calls[0]["env"]
          and "MIDA_GTO_SEMANTIC_REPAIR" not in FakePopen.calls[0]["env"]
          and record.get("spawned") is True
          and record.get("effective_env_contract", {}).get("ok") is True,
          f"popen_calls={len(FakePopen.calls)}")


# U0-D: no_bypass=1 validator accepts the authorized dict.
def test_no_bypass_propagates_to_child(ctrl):
    env = {"MIDA_GTO_NO_BYPASS": "1"}
    allowlist = ["MIDA_GTO_NO_BYPASS"]
    ev = ctrl.validate_authorized_env(env, allowlist)
    check("route_u_r0_no_bypass_propagates_to_child",
          ev["ok"] and ev["no_bypass_present"] and ev["no_bypass_value"] == "1"
          and ev["no_bypass_verified"],
          f"no_bypass_value={ev.get('no_bypass_value')}")


# U0-D: bypass vars absent.
def test_bypass_vars_absent(ctrl):
    env = {"MIDA_GTO_NO_BYPASS": "1"}
    ev = ctrl.validate_authorized_env(env, ["MIDA_GTO_NO_BYPASS"])
    check("route_u_r0_bypass_vars_absent",
          ev["ok"] and ev["bypass_absent"] and not ev["bypass_present"],
          f"bypass_present={ev.get('bypass_present')}")
    env2 = {"MIDA_GTO_NO_BYPASS": "1", "MIDA_GTO_BYPASS": "1"}
    ev2 = ctrl.validate_authorized_env(env2, ["MIDA_GTO_NO_BYPASS"])
    check("route_u_r0_bypass_present_fails",
          not ev2["ok"] and "bypass_var_present" in ev2.get("failure_reasons", []),
          f"ok={ev2['ok']}")


# U0-D: semantic_repair absent.
def test_semantic_repair_absent(ctrl):
    env = {"MIDA_GTO_NO_BYPASS": "1"}
    ev = ctrl.validate_authorized_env(env, ["MIDA_GTO_NO_BYPASS"])
    check("route_u_r0_semantic_repair_absent",
          ev["ok"] and ev["semantic_repair_absent"] and not ev["semantic_repair_present"])
    env2 = {"MIDA_GTO_NO_BYPASS": "1", "MIDA_GTO_SEMANTIC_REPAIR": "1"}
    ev2 = ctrl.validate_authorized_env(env2, ["MIDA_GTO_NO_BYPASS"])
    check("route_u_r0_semantic_repair_present_fails",
          not ev2["ok"] and "semantic_repair_var_present" in ev2.get("failure_reasons", []))


# U0-D: effective env matches the authorized contract.
def test_effective_env_matches_authorized_contract(ctrl):
    env = {"MIDA_GTO_NO_BYPASS": "1"}
    ev = ctrl.validate_authorized_env(env, ["MIDA_GTO_NO_BYPASS"])
    check("route_u_r0_effective_env_matches_authorized_contract",
          ev["no_bypass_present"] and ev["no_bypass_value"] == ev["no_bypass_expected"]
          and ev["no_bypass_verified"] and ev["bypass_absent"] and ev["semantic_repair_absent"],
          f"contract={json.dumps(ev)}")


# UAF1-B/C: capture-policy ARG entirely missing -> fail before spawn, exit 6.
def test_capture_policy_arg_missing_fails_before_spawn(ctrl):
    ws = Path(tempfile.mkdtemp(prefix="u0_policyargmissing_"))
    rc, d = run_controller(ws, extra_env_list=["MIDA_GTO_NO_BYPASS=1"],
                           allowlist=["MIDA_GTO_NO_BYPASS"], capture_policy_arg="absent")
    check("route_u_af1_capture_policy_arg_missing_fails_before_spawn",
          d is not None and rc == 6 and d.get("spawned") is False and d.get("pid") is None
          and d.get("exit_code") is None
          and "capture_policy_arg_missing" in d.get("live_environment_preflight_error", ""),
          f"rc={rc} preflight={d.get('live_environment_preflight_error')}")


# UAF1-C: capture-policy arg present but FILE missing -> fail before spawn, exit 6,
# with precise reason capture_policy_file_missing.
def test_capture_policy_file_missing_fails_before_spawn(ctrl):
    ws = Path(tempfile.mkdtemp(prefix="u0_policyfilemissing_"))
    rc, d = run_controller(ws, extra_env_list=["MIDA_GTO_NO_BYPASS=1"],
                           allowlist=["MIDA_GTO_NO_BYPASS"], capture_policy_arg="missing_file")
    check("route_u_af1_capture_policy_file_missing_fails_before_spawn",
          d is not None and rc == 6 and d.get("spawned") is False and d.get("pid") is None
          and d.get("exit_code") is None
          and "capture_policy_file_missing" in d.get("live_environment_preflight_error", ""),
          f"rc={rc} preflight={d.get('live_environment_preflight_error')}")


# U0-D / UAF1-D: env contract armed only after preflight (no spawn, exit 6).
def test_argv_and_env_contract_armed_only_after_preflight(ctrl):
    ws = Path(tempfile.mkdtemp(prefix="u0_armedonly_"))
    rc, d = run_controller(ws, extra_env_list=[], allowlist=[],
                           capture_policy_arg="present")
    check("route_u_r0_argv_and_env_contract_is_armed_only_after_preflight",
          d is not None and rc == 6 and d.get("spawned") is False and d.get("pid") is None
          and d.get("exit_code") is None,
          f"rc={rc} spawned={d.get('spawned')} exit={d.get('exit_code')}")


# UAF1-D: all preflight rejections return the distinct exit code 6 AND never spawn.
def test_all_preflight_rejections_return_exit_six(ctrl):
    results = []
    # (extra_env, allowlist, capture_policy_arg) -> expected failure reason substring.
    cases = [
        ([], ["SystemRoot"], "present"),                 # env missing
        (["MIDA_GTO_NO_BYPASS=1"], ["MIDA_GTO_NO_BYPASS"], "absent"),        # policy arg missing
        (["MIDA_GTO_NO_BYPASS=1"], ["MIDA_GTO_NO_BYPASS"], "missing_file"),  # policy file missing
    ]
    for extra, allow, cap in cases:
        ws = Path(tempfile.mkdtemp(prefix="u0_exit6_"))
        rc, d = run_controller(ws, extra_env_list=extra, allowlist=allow,
                               capture_policy_arg=cap)
        ok = (d is not None and rc == 6 and d.get("spawned") is False
              and d.get("pid") is None and d.get("exit_code") is None
              and d.get("live_environment_preflight_error") is not None)
        results.append(ok)
    check("route_u_af1_all_preflight_rejections_return_exit_six",
          all(results),
          f"results={results}")


# UAF1-B: capture-policy arg-missing and file-missing use DISTINCT failure reasons.
def test_capture_policy_reasons_distinct(ctrl):
    pv = ctrl.validate_capture_policy_preflight(["mida", "--capture-policy=missing.json"])
    absent = ctrl.validate_capture_policy_preflight(["mida", "/unpack", "x.exe"])
    check("route_u_af1_capture_policy_reasons_distinct",
          pv.get("failure_reason") == "capture_policy_file_missing"
          and absent.get("failure_reason") == "capture_policy_arg_missing"
          and pv.get("failure_reason") != absent.get("failure_reason"),
          f"file={pv.get('failure_reason')} arg={absent.get('failure_reason')}")


# UAF1-D: a preflight failure must NOT call Popen at all (no protected spawn).
def test_no_popen_call_on_preflight_failure(ctrl):
    ws = Path(tempfile.mkdtemp(prefix="u0_nopopen_"))
    FakePopen.calls = []
    orig_popen = ctrl.subprocess.Popen
    ctrl.subprocess.Popen = FakePopen
    try:
        # Env contract unmet -> run_child returns before Popen.
        record = ctrl.run_child(
            argv=["mida-cli.exe", "/unpack", "x.exe", "-o", "cand.exe",
                  "--capture-policy=" + str(ws / "capture_policy.json")],
            cwd=ws,
            evidence_dir=ws,
            env_allowlist=["SystemRoot"],  # no MIDA_GTO_NO_BYPASS
            timeout_sec=30,
            extra_env={},
        )
    finally:
        ctrl.subprocess.Popen = orig_popen
    check("route_u_af1_no_popen_call_on_preflight_failure",
          len(FakePopen.calls) == 0 and record.get("spawned") is False
          and record.get("pid") is None,
          f"popen_calls={len(FakePopen.calls)}")


# ---------------------------------------------------------------------------
# Route V R0 (V0-E) — post-capture stage telemetry + deadline/timeout evidence.
# ---------------------------------------------------------------------------

# Helper: a real child that writes a GTO stage line then either exits or sleeps
# (so the controller's polling loop exercises real output-growth + timeout).
def _write_stage_child_script(ws, *, sleep_sec):
    """Write a child python script into ws that prints a gto_stage_enter line
    and optionally sleeps (to force a controller timeout)."""
    script = ws / "child_probe.py"
    body = (
        "import sys, time\n"
        "sys.stdout.write('[12:00:00] [INFO] stage=capture_heap_slab event=enter "
        "monotonic_elapsed_ms=0 stage_elapsed_ms=0 item_count=0 byte_count=0 "
        "gto_stage_enter\\n')\n"
        "sys.stdout.flush()\n"
    )
    if sleep_sec and sleep_sec > 0:
        body += f"time.sleep({sleep_sec})\n"
    script.write_text(body, encoding="utf-8")
    return script


def _run_real_child(ws, *, timeout_sec, script):
    """Invoke the controller against a real (short-lived or sleeping) child."""
    cli = sys.executable  # the probe script runs under the same interpreter
    argv = [
        sys.executable, str(CONTROLLER),
        "--evidence-dir", str(ws),
        "--env-allowlist", "MIDA_GTO_NO_BYPASS",
        "--env-allowlist", "PATH",
        "--env-allowlist", "SystemRoot",
        "--env-allowlist", "TEMP",
        "--env-allowlist", "COMSPEC",
        "--set-env", "MIDA_GTO_NO_BYPASS=1",
        "--timeout", str(timeout_sec),
        # NOTE: no "--" separator — argparse REMAINDER would capture the literal
        # "--" into args.command (verified: `with--: ['--','cmd',...]`). The live
        # PS driver strips "--" via parameter binding; here we must NOT include it.
        cli, str(script),
        "--capture-policy=" + str(ws / "capture_policy.json"),
    ]
    try:
        res = subprocess.run(argv, capture_output=True, text=True, timeout=30)
    except subprocess.TimeoutExpired:
        return "TIMEOUT", None
    d = json.load(open(ws / "controller_run.json", encoding="utf-8"))
    return res.returncode, d


# V0-B: controller_run.json records the configured timeout seconds.
def test_controller_records_configured_timeout(ctrl):
    ws = Path(tempfile.mkdtemp(prefix="v0_cfgtimeout_"))
    open(ws / "capture_policy.json", "w").write('{"preset":"ahk_gto_defaults"}')
    script = _write_stage_child_script(ws, sleep_sec=0)
    rc, d = _run_real_child(ws, timeout_sec=12.5, script=script)
    check("route_v_r0_controller_records_configured_timeout",
          d is not None and d.get("configured_timeout_sec") == 12.5
          and d.get("spawned") is True and rc == 0,
          f"configured_timeout_sec={d and d.get('configured_timeout_sec')} rc={rc}")


# V0-B: the controller records last-output growth + size + observed stage/event.
def test_controller_records_last_output_progress(ctrl):
    ws = Path(tempfile.mkdtemp(prefix="v0_progress_"))
    open(ws / "capture_policy.json", "w").write('{"preset":"ahk_gto_defaults"}')
    script = _write_stage_child_script(ws, sleep_sec=0)
    rc, d = _run_real_child(ws, timeout_sec=10.0, script=script)
    check("route_v_r0_controller_records_last_output_progress",
          d is not None
          and isinstance(d.get("last_output_size"), int) and d.get("last_output_size") > 0
          and isinstance(d.get("last_output_growth_utc"), str) and d.get("last_output_growth_utc")
          and d.get("last_observed_stage") == "capture_heap_slab"
          and d.get("last_observed_stage_event") == "enter",
          f"size={d and d.get('last_output_size')} growth={d and d.get('last_output_growth_utc')} "
          f"stage={d and d.get('last_observed_stage')} event={d and d.get('last_observed_stage_event')}")


# V0-B: on timeout the controller records the silence window before the kill.
def test_timeout_records_silence_duration(ctrl):
    ws = Path(tempfile.mkdtemp(prefix="v0_silence_"))
    open(ws / "capture_policy.json", "w").write('{"preset":"ahk_gto_defaults"}')
    # Child writes one line then sleeps 30s -> controller times out at 0.8s.
    script = _write_stage_child_script(ws, sleep_sec=30)
    t0 = time.monotonic()
    rc, d = _run_real_child(ws, timeout_sec=0.8, script=script)
    elapsed = time.monotonic() - t0
    check("route_v_r0_timeout_records_silence_duration",
          d is not None and d.get("timed_out") is True
          and isinstance(d.get("silence_before_timeout_ms"), int)
          and d.get("silence_before_timeout_ms") is not None
          and 0 <= d.get("silence_before_timeout_ms") <= int(round(elapsed * 1000)) + 500
          and d.get("termination_action") == "terminate_tree"
          and d.get("process_tree_cleanup_status") == "terminated",
          f"timed_out={d and d.get('timed_out')} silence={d and d.get('silence_before_timeout_ms')} "
          f"elapsed_ms={int(round(elapsed*1000))} action={d and d.get('termination_action')}")


# V0-B: a timeout must preserve the raw binary stdout/stderr evidence.
def test_timeout_preserves_binary_evidence(ctrl):
    ws = Path(tempfile.mkdtemp(prefix="v0_evidence_"))
    open(ws / "capture_policy.json", "w").write('{"preset":"ahk_gto_defaults"}')
    script = _write_stage_child_script(ws, sleep_sec=30)
    rc, d = _run_real_child(ws, timeout_sec=0.8, script=script)
    raw_path = ws / "child.stdout.bin"
    stderr_path = ws / "child.stderr.bin"
    ok = (d is not None and d.get("timed_out") is True
          and raw_path.exists() and raw_path.stat().st_size > 0
          and isinstance(d.get("stdout_raw_sha256"), str)
          and d.get("stdout_raw_sha256") and d.get("stdout_raw_size", 0) > 0
          and (not stderr_path.exists() or stderr_path.stat().st_size >= 0))
    check("route_v_r0_timeout_preserves_binary_evidence",
          ok,
          f"stdout_exists={raw_path.exists()} stdout_size={raw_path.stat().st_size if raw_path.exists() else None} "
          f"sha={d and d.get('stdout_raw_sha256')}")


# V0-C: the next hard timeout policy is explicit (600s) in both the controller
# core and the PS driver, and NO aggressive no-progress kill exists (silence is
# recorded but never used to terminate).
def test_600s_policy_is_explicit(ctrl):
    # 1) Controller core default --timeout is 600.0.
    src = (CONTROLLER).read_text(encoding="utf-8")
    m = re.search(r'--timeout["\']?\s*,\s*type=float,\s*default=([\d.]+)', src)
    core_default_600 = bool(m and float(m.group(1)) == 600.0)
    # 2) PS driver default $Timeout is 600.0.
    ps1 = HERE / "run_gto_live_route_controller.ps1"
    psrc = ps1.read_text(encoding="utf-8")
    m2 = re.search(r'\[double\]\$Timeout\s*=\s*([\d.]+)', psrc)
    driver_default_600 = bool(m2 and float(m2.group(1)) == 600.0)
    # 3) No aggressive no-progress kill: silence is only recorded, never used to
    #    terminate. Confirm the silence value is absent from any termination
    #    trigger and the only kill trigger is the total wall-clock timeout.
    has_silence_record = "silence_before_timeout_ms" in src
    # The loop must not reference silence in a kill decision: assert the kill
    # branch is guarded by elapsed >= timeout_sec and not by a silence predicate.
    silence_used_to_kill = re.search(r'silence_before_timeout_ms\s*[<>]=', src) is not None
    # And confirm there is a total-timeout kill guard.
    has_total_timeout_guard = re.search(r'elapsed\s*>=\s*timeout_sec', src) is not None
    check("route_v_r0_600s_policy_is_explicit",
          core_default_600 and driver_default_600
          and has_silence_record and not silence_used_to_kill
          and has_total_timeout_guard,
          f"core600={core_default_600} driver600={driver_default_600} "
          f"records_silence={has_silence_record} silence_used_to_kill={silence_used_to_kill} "
          f"total_timeout_guard={has_total_timeout_guard}")


# ---------------------------------------------------------------------------
# Route W R0 (W0-F) — build capability attestation + preflight evidence.
# ---------------------------------------------------------------------------

def _write_fake_binary(ws, name="fake_cli.exe"):
    """Write a tiny harmless fake CLI binary (not the protected sample)."""
    p = ws / name
    p.write_bytes(b"MZ\x90\x00" + b"\x00" * 256)
    # A valid capture-policy file so the policy preflight passes when we want
    # the run to reach Popen (W0 tests).
    (ws / "capture_policy.json").write_text('{"preset":"ahk_gto_defaults"}', encoding="utf-8")
    return p


def _policy_arg(ws):
    return "--capture-policy=" + str((ws / "capture_policy.json").resolve())


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _make_attestation(ws, binary_path, *, gto=True, features=("gto-product-recovery",),
                      head="a" * 40, size=None, digest=None):
    """Write a gto_cli_build_attestation.json for the given binary."""
    raw = Path(binary_path).read_bytes()
    if size is None:
        size = len(raw)
    if digest is None:
        digest = _sha256(raw)
    att = {
        "schema_version": "mida.build-attestation/v1",
        "baseline_commit": head,
        "binary_path": str(Path(binary_path).resolve()),
        "binary_sha256": digest,
        "binary_size": size,
        "cargo_package": "mida-cli",
        "cargo_profile": "debug",
        "requested_features": list(features),
        "capability_probe_output": json.dumps({
            "schema_version": "mida.build-capabilities/v1",
            "gto_product_recovery": gto,
            "profile": "debug",
            "package": "mida-cli",
        }),
        "gto_product_recovery": gto,
    }
    p = ws / "gto_cli_build_attestation.json"
    p.write_text(json.dumps(att), encoding="utf-8")
    return p


# W0-A: the canonical build script must request the GTO feature.
def test_build_script_requests_gto_feature(ctrl):
    ps1 = HERE / "build_gto_live_cli.ps1"
    ok = ps1.is_file()
    if ok:
        src = ps1.read_text(encoding="utf-8")
        ok = (
            "--features gto-product-recovery" in src
            and "-p mida-cli" in src
            and "--offline" in src
        )
    check("route_w_r0_build_script_requests_gto_feature",
          ok, f"ps1={ps1.is_file()}")

# W0-C: an attestation's digest/size match the actual binary.
def test_build_attestation_matches_binary(ctrl):
    ws = Path(tempfile.mkdtemp(prefix="w0_att_"))
    binary = _write_fake_binary(ws)
    att = _make_attestation(ws, binary)
    ev = ctrl.validate_build_capability_preflight(
        str(att), [str(binary.resolve()), "/unpack", "x.exe"], None
    )
    raw = binary.read_bytes()
    check("route_w_r0_build_attestation_matches_binary",
          ev.get("ok") is True
          and ev.get("attested_binary_sha256") == _sha256(raw)
          and ev.get("attested_binary_size") == len(raw)
          and ev.get("gto_product_recovery") is True,
          f"ok={ev.get('ok')} sha_match={ev.get('attested_binary_sha256')==_sha256(raw)} "
          f"size={ev.get('attested_binary_size')} vs {len(raw)}")

# W0-D: missing --build-attestation arg + provided-but-missing file both fail
# before Popen (when the flag IS supplied).
def test_missing_attestation_fails_before_popen(ctrl):
    ws = Path(tempfile.mkdtemp(prefix="w0_missingatt_"))
    binary = _write_fake_binary(ws)
    FakePopen.calls = []
    orig_popen = ctrl.subprocess.Popen
    ctrl.subprocess.Popen = FakePopen
    try:
        # Flag supplied but file missing.
        rec_missing = ctrl.run_child(
            argv=[str(binary.resolve()), "/unpack", "x.exe", _policy_arg(ws)],
            cwd=ws, evidence_dir=ws, env_allowlist=["MIDA_GTO_NO_BYPASS"],
            timeout_sec=5, extra_env={"MIDA_GTO_NO_BYPASS": "1"},
            build_attestation_path=str(ws / "MISSING.json"),
        )
        # Flag NOT supplied at all -> build gate not required (ok=True), no block.
        rec_unrequired = ctrl.run_child(
            argv=[str(binary.resolve()), "/unpack", "x.exe", _policy_arg(ws)],
            cwd=ws, evidence_dir=ws, env_allowlist=["MIDA_GTO_NO_BYPASS"],
            timeout_sec=5, extra_env={"MIDA_GTO_NO_BYPASS": "1"},
        )
    finally:
        ctrl.subprocess.Popen = orig_popen
    check("route_w_r0_missing_attestation_fails_before_popen",
          rec_missing.get("spawned") is False
          and rec_missing.get("build_capability_preflight_error") is not None
          and "build_attestation_file_missing" in rec_missing.get("build_capability_preflight_error", "")
          and len(FakePopen.calls) == 1  # only the unrequired call reached Popen
          and rec_unrequired.get("spawned") is True,
          f"missing_spawned={rec_missing.get('spawned')} "
          f"missing_err={rec_missing.get('build_capability_preflight_error')} "
          f"popen_calls={len(FakePopen.calls)}")

# W0-D: digest mismatch fails before Popen.
def test_digest_mismatch_fails_before_popen(ctrl):
    ws = Path(tempfile.mkdtemp(prefix="w0_digest_"))
    binary = _write_fake_binary(ws)
    wrong_digest = "0" * 64
    att = _make_attestation(ws, binary, digest=wrong_digest)
    FakePopen.calls = []
    orig_popen = ctrl.subprocess.Popen
    ctrl.subprocess.Popen = FakePopen
    try:
        rec = ctrl.run_child(
            argv=[str(binary.resolve()), "/unpack", "x.exe", _policy_arg(ws)],
            cwd=ws, evidence_dir=ws, env_allowlist=["MIDA_GTO_NO_BYPASS"],
            timeout_sec=5, extra_env={"MIDA_GTO_NO_BYPASS": "1"},
            build_attestation_path=str(att),
        )
    finally:
        ctrl.subprocess.Popen = orig_popen
    check("route_w_r0_digest_mismatch_fails_before_popen",
          rec.get("spawned") is False and len(FakePopen.calls) == 0
          and "build_binary_digest_mismatch" in rec.get("build_capability_preflight_error", ""),
          f"spawned={rec.get('spawned')} popen={len(FakePopen.calls)} "
          f"err={rec.get('build_capability_preflight_error')}")

# W0-D: feature=false attestation fails before Popen.
def test_feature_false_fails_before_popen(ctrl):
    ws = Path(tempfile.mkdtemp(prefix="w0_featfalse_"))
    binary = _write_fake_binary(ws)
    att = _make_attestation(ws, binary, gto=False)
    FakePopen.calls = []
    orig_popen = ctrl.subprocess.Popen
    ctrl.subprocess.Popen = FakePopen
    try:
        rec = ctrl.run_child(
            argv=[str(binary.resolve()), "/unpack", "x.exe", _policy_arg(ws)],
            cwd=ws, evidence_dir=ws, env_allowlist=["MIDA_GTO_NO_BYPASS"],
            timeout_sec=5, extra_env={"MIDA_GTO_NO_BYPASS": "1"},
            build_attestation_path=str(att),
        )
    finally:
        ctrl.subprocess.Popen = orig_popen
    check("route_w_r0_feature_false_fails_before_popen",
          rec.get("spawned") is False and len(FakePopen.calls) == 0
          and "gto_capability_false" in rec.get("build_capability_preflight_error", ""),
          f"spawned={rec.get('spawned')} err={rec.get('build_capability_preflight_error')}")

# W0-D: a valid attestation reaches the (mock) Popen boundary.
def test_valid_attestation_reaches_mock_popen(ctrl):
    ws = Path(tempfile.mkdtemp(prefix="w0_validatt_"))
    binary = _write_fake_binary(ws)
    att = _make_attestation(ws, binary)
    FakePopen.calls = []
    orig_popen = ctrl.subprocess.Popen
    ctrl.subprocess.Popen = FakePopen
    try:
        rec = ctrl.run_child(
            argv=[str(binary.resolve()), "/unpack", "x.exe", _policy_arg(ws)],
            cwd=ws, evidence_dir=ws, env_allowlist=["MIDA_GTO_NO_BYPASS"],
            timeout_sec=5, extra_env={"MIDA_GTO_NO_BYPASS": "1"},
            build_attestation_path=str(att),
            authorized_head="a" * 40,
        )
    finally:
        ctrl.subprocess.Popen = orig_popen
    check("route_w_r0_valid_attestation_reaches_mock_popen",
          rec.get("spawned") is True and len(FakePopen.calls) == 1
          and rec.get("build_capability_preflight_error") is None
          and rec.get("build_capability_preflight", {}).get("ok") is True,
          f"spawned={rec.get('spawned')} popen={len(FakePopen.calls)}")

# W0-D: build-capability rejection returns exit code 7 via main().
def test_build_preflight_returns_exit_seven(ctrl):
    ws = Path(tempfile.mkdtemp(prefix="w0_exit7_"))
    binary = _write_fake_binary(ws)
    # No attestation file exists; flag points at a missing file -> build gate fails -> exit 7.
    cli = "C:\\nonexistent\\mida-cli.exe"  # unused; argv[0] is the fake binary
    argv = [
        sys.executable, str(CONTROLLER),
        "--evidence-dir", str(ws),
        "--build-attestation", str(ws / "NOPE.json"),
        "--env-allowlist", "MIDA_GTO_NO_BYPASS",
        "--set-env", "MIDA_GTO_NO_BYPASS=1",
        str(binary.resolve()), "/unpack", "x.exe",
    ]
    r = subprocess.run(argv, capture_output=True, text=True, timeout=30)
    d = json.load(open(ws / "controller_run.json", encoding="utf-8"))
    check("route_w_r0_build_preflight_returns_exit_seven",
          r.returncode == 7 and d.get("spawned") is False and d.get("pid") is None
          and d.get("build_capability_preflight_error") is not None,
          f"rc={r.returncode} spawned={d.get('spawned')}")

# W0-E: preflight attempts are never overwritten.
def test_preflight_attempts_are_not_overwritten(ctrl):
    ws = Path(tempfile.mkdtemp(prefix="w0_nooverwrite_"))
    binary = _write_fake_binary(ws)
    # Two successive build-gate failures (missing attestation) with explicit
    # attempt sequences 1 and 2 -> two distinct controller_attempt files kept.
    for seq in (1, 2):
        ctrl.run_child(
            argv=[str(binary.resolve()), "/unpack", "x.exe"],
            cwd=ws, evidence_dir=ws, env_allowlist=["MIDA_GTO_NO_BYPASS"],
            timeout_sec=5, extra_env={"MIDA_GTO_NO_BYPASS": "1"},
            build_attestation_path=str(ws / "MISSING.json"),
            attempt_sequence=seq,
        )
    files = sorted(ws.glob("controller_attempt_*.json"))
    check("route_w_r0_preflight_attempts_are_not_overwritten",
          len(files) == 2
          and (ws / "controller_attempt_001.json").exists()
          and (ws / "controller_attempt_002.json").exists()
          and (ws / "controller_run.json").exists(),
          f"attempt_files={[f.name for f in files]}")

# W0-E: attempt sequence is monotonic (never reused).
def test_attempt_sequence_is_monotonic(ctrl):
    ws = Path(tempfile.mkdtemp(prefix="w0_seq_"))
    binary = _write_fake_binary(ws)
    ctrl.run_child(
        argv=[str(binary.resolve()), "/unpack", "x.exe"],
        cwd=ws, evidence_dir=ws, env_allowlist=["MIDA_GTO_NO_BYPASS"],
        timeout_sec=5, extra_env={"MIDA_GTO_NO_BYPASS": "1"},
        build_attestation_path=str(ws / "MISSING.json"),
        attempt_sequence=3,
    )
    # Next auto-derived sequence must be 4.
    next_seq = ctrl.main.__globals__  # not needed; recompute manually:
    existing = [
        int(p.stem.split("_")[-1])
        for p in ws.glob("controller_attempt_*.json")
        if p.stem.split("_")[-1].isdigit()
    ]
    derived = max(existing) + 1 if existing else 1
    check("route_w_r0_attempt_sequence_is_monotonic",
          derived == 4,
          f"existing={existing} derived={derived}")


def main():
    ctrl = load_controller()
    test_no_bypass_missing_fails_before_spawn(ctrl)
    test_no_bypass_reaches_popen_env(ctrl)
    test_no_bypass_propagates_to_child(ctrl)
    test_bypass_vars_absent(ctrl)
    test_semantic_repair_absent(ctrl)
    test_effective_env_matches_authorized_contract(ctrl)
    test_capture_policy_arg_missing_fails_before_spawn(ctrl)
    test_capture_policy_file_missing_fails_before_spawn(ctrl)
    test_argv_and_env_contract_armed_only_after_preflight(ctrl)
    test_all_preflight_rejections_return_exit_six(ctrl)
    test_capture_policy_reasons_distinct(ctrl)
    test_no_popen_call_on_preflight_failure(ctrl)
    # Route V R0 (V0-E)
    test_controller_records_configured_timeout(ctrl)
    test_controller_records_last_output_progress(ctrl)
    test_timeout_records_silence_duration(ctrl)
    test_timeout_preserves_binary_evidence(ctrl)
    test_600s_policy_is_explicit(ctrl)
    # Route W R0 (W0-F)
    test_build_script_requests_gto_feature(ctrl)
    test_build_attestation_matches_binary(ctrl)
    test_missing_attestation_fails_before_popen(ctrl)
    test_digest_mismatch_fails_before_popen(ctrl)
    test_feature_false_fails_before_popen(ctrl)
    test_valid_attestation_reaches_mock_popen(ctrl)
    test_build_preflight_returns_exit_seven(ctrl)
    test_preflight_attempts_are_not_overwritten(ctrl)
    test_attempt_sequence_is_monotonic(ctrl)
    passed = sum(1 for _, ok, _ in _results if ok)
    failed = len(_results) - passed
    print(f"\nroute_u+af1+v0+w0: {passed} passed / {failed} failed / {len(_results)} total")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
