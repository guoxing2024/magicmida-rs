#!/usr/bin/env python3
"""Route U R0 / Audit Fix 1 — Live Harness Environment Propagation and Armed-Run Preflight Closure.

Offline tests for the GTO live-route controller's authorized-environment contract,
including the UAF1 mock-Popen child-boundary and capture-policy-arg-missing tests.

Run: python3 tools/test_gto_live_route_controller.py
"""

from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
import tempfile
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
    passed = sum(1 for _, ok, _ in _results if ok)
    failed = len(_results) - passed
    print(f"\nroute_u_r0+af1: {passed} passed / {failed} failed / {len(_results)} total")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
