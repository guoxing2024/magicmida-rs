#!/usr/bin/env python3
"""Binary-safe live-route subprocess controller for GTO.

Fixes the Route J R1 root cause: ``subprocess.run(..., text=True)`` with no
explicit encoding used Windows' default ``cp936`` (GBK) to decode the Rust CLI's
output, and a non-decodable byte killed the internal ``_readerthread`` (losing
stdout/stderr). This controller never decodes child output during execution; it
writes stdout/stderr directly to ``.bin`` files via ``wb`` file handles handed
to ``Popen``, then generates display ``.txt`` copies afterward.

Authoritative evidence: ``child.stdout.bin`` / ``child.stderr.bin`` (raw bytes).
Display copies: ``child.stdout.txt`` / ``child.stderr.txt`` (decode best-effort;
never treated as authoritative).

Every run atomically writes ``controller_run.json`` with lifecycle metadata.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

SCHEMA = "mida.live-route-controller/v1"

# Route U R0 (U0-A/U0-B/U0-C): the authorized GTO live-route environment contract.
# The child MUST run with MIDA_GTO_NO_BYPASS=1 (authoritative raw-capture path),
# and MUST NOT have any bypass / semantic-repair escape hatches. This contract is
# enforced BEFORE spawn (protected_spawn stays 0 on any violation) and recorded as
# effective-env evidence in controller_run.json. It can never rely on implicit
# parent-shell inheritance.
GTO_ENV_NO_BYPASS = "MIDA_GTO_NO_BYPASS"
GTO_ENV_BYPASS = "MIDA_GTO_BYPASS"
GTO_ENV_SEMANTIC_REPAIR = "MIDA_GTO_SEMANTIC_REPAIR"
GTO_ENV_CONTRACT_VALUE = "1"

# IMP-09-LIVE-PREP (P3): runtime-authority pass-through allowlist additions.
# The post-attach runtime loader (crates/cli/src/unpacker/runtime_loader.rs)
# resolves MIDA_RUNTIME_AUTHORITY (authority manifest PATH) and MIDA_RUNTIME_DLL
# (runtime artifact PATH) from the CHILD env; unset -> loader fails closed.
# These keys authorize PASS-THROUGH ONLY: build_env copies them into the child
# env when (and only when) they are both allowlisted and set on the parent;
# absence is RECORDED as the loader's fail-closed posture (never fabricated).
# MIDA_RUNTIME_AUTHORITY_DIGEST is a compile-time option_env! constant that no
# runtime code reads from the child env — it is allowlisted for symmetric
# documentation-level pass-through only.
GTO_ENV_RUNTIME_AUTHORITY = "MIDA_RUNTIME_AUTHORITY"
GTO_ENV_RUNTIME_AUTHORITY_DIGEST = "MIDA_RUNTIME_AUTHORITY_DIGEST"
GTO_ENV_RUNTIME_DLL = "MIDA_RUNTIME_DLL"
GTO_ENV_RUNTIME_AUTHORITY_VARS = (
    GTO_ENV_RUNTIME_AUTHORITY,
    GTO_ENV_RUNTIME_AUTHORITY_DIGEST,
    GTO_ENV_RUNTIME_DLL,
)


def find_capture_policy_path(argv: List[str]) -> Optional[str]:
    """Extract the ``--capture-policy=<path>`` value from the child argv, if any."""
    for a in argv:
        if a.startswith("--capture-policy="):
            return a[len("--capture-policy="):]
    return None


def validate_capture_policy_preflight(argv: List[str]) -> Dict[str, Any]:
    """U0-B / UAF1-B: verify the capture-policy file referenced by the child argv
    exists before spawn. The capture-policy is a MANDATORY input for an authorized
    live route: a missing ``--capture-policy`` ARGUMENT fails closed (ok=False,
    failure_reason=capture_policy_arg_missing) just like a present-but-missing FILE
    (failure_reason=capture_policy_file_missing). Returns an evidence dict with
    boolean ``ok``. Any violation must fail BEFORE the child starts
    (protected_spawn stays 0)."""
    path_str = find_capture_policy_path(argv)
    if path_str is None:
        return {
            "ok": False,
            "capture_policy_arg_present": False,
            "capture_policy_path": None,
            "capture_policy_exists": False,
            "failure_reason": "capture_policy_arg_missing",
        }
    p = Path(path_str)
    ok = p.is_file()
    return {
        "ok": ok,
        "capture_policy_arg_present": True,
        "capture_policy_path": str(p),
        "capture_policy_exists": ok,
        "failure_reason": "capture_policy_file_missing" if not ok else None,
    }


# Route W R0 (W0-D): build-capability preflight. The child argv[0] (the mida-cli
# binary) must be the exact binary attested by `gto_cli_build_attestation.json`
# produced by tools/build_gto_live_cli.ps1, AND that attestation must report
# gto_product_recovery=true. This closes the Route V R1 failure mode where a
# default-feature (GTO-disabled) binary was silently used. Fails BEFORE spawn
# (protected_spawn stays 0) with a precise reason and exit code 7.
def validate_build_capability_preflight(
    attestation_path: Optional[str], argv: List[str], authorized_head: Optional[str]
) -> Dict[str, Any]:
    """Verify the child binary is a GTO-capable, attested build.

    Returns an evidence dict with boolean ``ok``. Failure reasons are precise so
    the driver can distinguish configuration problems. Any violation must fail
    BEFORE Popen (protected_spawn stays 0, exit code 7).

    Route W R0 AF1 (WAF1-A/B): the build gate is MANDATORY, not opt-in. Both
    ``attestation_path`` and ``authorized_head`` must be provided; a missing
    attestation or a missing authorized HEAD fails closed so an operator can
    never forget the capability/baseline binding and still reach Popen.
    """
    if not attestation_path:
        return {
            "ok": False,
            "build_attestation_arg_present": False,
            "failure_reason": "build_attestation_arg_missing",
        }
    if not authorized_head:
        return {
            "ok": False,
            "build_attestation_arg_present": True,
            "failure_reason": "authorized_head_arg_missing",
        }
    att = Path(attestation_path)
    if not att.is_file():
        return {
            "ok": False,
            "build_attestation_arg_present": True,
            "build_attestation_exists": False,
            "build_attestation_path": str(att),
            "failure_reason": "build_attestation_file_missing",
        }
    try:
        # utf-8-sig transparently strips a leading UTF-8 BOM (PowerShell's
        # Set-Content -Encoding UTF8 writes one) so the attestation parses
        # regardless of how the build script encoded it.
        text = att.read_text(encoding="utf-8-sig")
        data = json.loads(text)
    except Exception as exc:
        return {
            "ok": False,
            "build_attestation_arg_present": True,
            "build_attestation_exists": True,
            "build_attestation_path": str(att),
            "failure_reason": "build_attestation_invalid_json",
            "failure_detail": f"{type(exc).__name__}: {exc}",
        }
    if not argv:
        return {
            "ok": False,
            "build_attestation_arg_present": True,
            "failure_reason": "child_argv_empty",
        }
    binary_path = argv[0]
    attested_path = str(data.get("binary_path", ""))
    # Normalize both to absolute, case-folded for comparison.
    if os.path.normcase(os.path.abspath(str(binary_path))) != os.path.normcase(
        os.path.abspath(attested_path)
    ):
        return {
            "ok": False,
            "build_attestation_arg_present": True,
            "build_attestation_exists": True,
            "failure_reason": "build_binary_path_mismatch",
            "attested_path": attested_path,
            "child_argv0": str(binary_path),
        }
    if not os.path.isfile(str(binary_path)):
        return {
            "ok": False,
            "build_attestation_arg_present": True,
            "build_attestation_exists": True,
            "failure_reason": "build_binary_file_missing",
            "binary_path": str(binary_path),
        }
    actual_sha = sha256_file(Path(str(binary_path)))
    attested_sha = str(data.get("binary_sha256", ""))
    if actual_sha != attested_sha:
        return {
            "ok": False,
            "build_attestation_arg_present": True,
            "build_attestation_exists": True,
            "failure_reason": "build_binary_digest_mismatch",
            "attested_sha256": attested_sha,
            "actual_sha256": actual_sha,
        }
    actual_size = os.path.getsize(str(binary_path))
    attested_size = data.get("binary_size")
    if attested_size != actual_size:
        return {
            "ok": False,
            "build_attestation_arg_present": True,
            "build_attestation_exists": True,
            "failure_reason": "build_binary_size_mismatch",
            "attested_size": attested_size,
            "actual_size": actual_size,
        }
    features = list(data.get("requested_features", []) or [])
    if "gto-product-recovery" not in features:
        return {
            "ok": False,
            "build_attestation_arg_present": True,
            "build_attestation_exists": True,
            "failure_reason": "gto_feature_not_requested",
            "requested_features": features,
        }
    if data.get("gto_product_recovery") is not True:
        return {
            "ok": False,
            "build_attestation_arg_present": True,
            "build_attestation_exists": True,
            "failure_reason": "gto_capability_false",
            "gto_product_recovery": data.get("gto_product_recovery"),
        }
    baseline = str(data.get("baseline_commit", ""))
    if not baseline or baseline != authorized_head:
        return {
            "ok": False,
            "build_attestation_arg_present": True,
            "build_attestation_exists": True,
            "failure_reason": "build_baseline_mismatch",
            "attested_baseline": baseline,
            "authorized_head": authorized_head,
        }
    return {
        "ok": True,
        "build_attestation_arg_present": True,
        "build_attestation_exists": True,
        "build_attestation_path": str(att),
        "attested_binary_path": attested_path,
        "attested_binary_sha256": attested_sha,
        "attested_binary_size": attested_size,
        "requested_features": features,
        "gto_product_recovery": True,
        "baseline_commit": baseline,
        "authorized_head": authorized_head,
        "schema_version": data.get("schema_version"),
    }


def validate_authorized_env(env: Dict[str, str], allowlist: List[str]) -> Dict[str, Any]:
    """Validate the effective child env against the authorized GTO live-route
    contract. Returns an evidence dict with a boolean ``ok``.

    U0-B: fails (ok=False) when the allowlist does not carry MIDA_GTO_NO_BYPASS,
    when the effective env does not explicitly set MIDA_GTO_NO_BYPASS=1, or when a
    bypass / semantic-repair escape hatch is present. The caller MUST NOT spawn when
    ``ok`` is False (protected_spawn stays 0).

    IMP-09-LIVE-PREP (P3): additionally RECORDS the runtime-authority
    pass-through posture under ``runtime_authority_pass_through`` (per-var
    ``in_allowlist`` / ``present_in_effective_env`` / ``path_exists``). This is
    recording-only evidence: it NEVER changes ``ok``, so observation-only runs
    without the runtime vars stay valid while an armed run's missing runtime
    authority is visible in the effective-env evidence instead of silently
    failing deep inside the loader.
    """
    allowlist_has_no_bypass = GTO_ENV_NO_BYPASS in allowlist
    no_bypass_value = env.get(GTO_ENV_NO_BYPASS)
    no_bypass_ok = no_bypass_value == GTO_ENV_CONTRACT_VALUE
    bypass_present = GTO_ENV_BYPASS in env
    semantic_repair_present = GTO_ENV_SEMANTIC_REPAIR in env
    # IMP-09-LIVE-PREP (P3): record-only runtime-authority pass-through posture.
    runtime_authority: Dict[str, Any] = {}
    for _var in GTO_ENV_RUNTIME_AUTHORITY_VARS:
        _entry: Dict[str, Any] = {
            "in_allowlist": _var in allowlist,
            "present_in_effective_env": _var in env,
        }
        if _var in env:
            _value = env[_var]
            if _var == GTO_ENV_RUNTIME_AUTHORITY_DIGEST:
                # Compile-time constant mirrored for evidence only; never a
                # runtime credential.
                _entry["recorded_as"] = "compile_time_option_env_mirror"
            else:
                _entry["path_exists"] = Path(_value).exists()
        runtime_authority[_var] = _entry
    ok = allowlist_has_no_bypass and no_bypass_ok and not bypass_present and not semantic_repair_present
    evidence = {
        "ok": ok,
        "allowlist_carries_no_bypass": allowlist_has_no_bypass,
        "no_bypass_present": GTO_ENV_NO_BYPASS in env,
        "no_bypass_value": no_bypass_value,
        "no_bypass_expected": GTO_ENV_CONTRACT_VALUE,
        "no_bypass_verified": no_bypass_ok,
        "bypass_present": bypass_present,
        "bypass_absent": not bypass_present,
        "semantic_repair_present": semantic_repair_present,
        "semantic_repair_absent": not semantic_repair_present,
        "runtime_authority_pass_through": runtime_authority,
        "runtime_authority_all_allowlisted": all(
            entry["in_allowlist"] for entry in runtime_authority.values()
        ),
    }
    if not ok:
        reasons = []
        if not allowlist_has_no_bypass:
            reasons.append("allowlist_missing_no_bypass")
        if not no_bypass_ok:
            reasons.append("no_bypass_not_explicit_1")
        if bypass_present:
            reasons.append("bypass_var_present")
        if semantic_repair_present:
            reasons.append("semantic_repair_var_present")
        evidence["failure_reasons"] = reasons
    return evidence


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def atomic_write_bytes(dest: Path, data: bytes) -> None:
    dest.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_path = tempfile.mkstemp(prefix=".ctrl-", suffix=".tmp", dir=str(dest.parent))
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp_path, dest)
    except BaseException:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise


def decode_display(raw: bytes, label: str) -> Dict[str, Any]:
    """Best-effort UTF-8 decode for the display copy. Never authoritative."""
    try:
        text = raw.decode("utf-8")
        return {"decode_status": "utf-8", "replacement_count": 0, "display_text": text}
    except UnicodeDecodeError as exc:
        text = raw.decode("utf-8", errors="replace")
        return {
            "decode_status": "utf-8_with_replacement",
            "replacement_count": 1,
            "display_text": text,
            "decode_error": f"{exc}",
        }


# Route V R0 (V0-B) / X0-E: match a GTO stage-telemetry log line and extract the
# stage name and event (enter|exit|error). The Rust CLI emits lines of the form:
#   [HH:MM:SS] [INFO] gto_stage_enter stage="capture_heap_slab" event="enter" ...
# where the `tracing` field formatter may interleave ANSI SGR escapes around the
# field names, the `=`, and the values, and the values are QUOTED.
#
# X0-E: strip ANSI escapes BEFORE field parsing, and accept both quoted and
# unquoted field values. This is recording-only evidence; a parse failure or a
# silent window must never be treated as an early-kill condition.
_STAGE_RE = re.compile(rb"gto_stage_(\w+)\b")

# After ANSI stripping: `stage="name"` or `stage=name`, and `event="e"` / `event=e`.
_ANSI_ESC_RE = re.compile(rb"\x1b\[[0-9;]*m")
_STAGE_FIELD_RE = re.compile(rb"\bstage=\"?([^\"\s]+)\"?\b")
_EVENT_FIELD_RE = re.compile(rb"\bevent=\"?([^\"\s]+)\"?\b")


def _strip_ansi(data: bytes) -> bytes:
    return _ANSI_ESC_RE.sub(b"", data)


def _sample_last_stage(stdout_raw_path: Path, stderr_raw_path: Path):
    """Best-effort: find the last GTO stage + event seen in the raw output tails.

    Returns ``(stage_name, event)`` or ``(None, None)`` if nothing parseable was
    found. This is evidence-only: it never influences success/failure decisions.
    X0-E: ANSI escapes are stripped first; quoted or unquoted field values are
    both accepted (e.g. stage="raw_slab_overlay" event="error").
    """
    tail = bytearray()
    for p in (stdout_raw_path, stderr_raw_path):
        try:
            if p.exists():
                size = p.stat().st_size
                if size:
                    with open(p, "rb") as fh:
                        fh.seek(max(0, size - 8192))
                        tail.extend(fh.read())
        except Exception:
            continue
    if not tail:
        return None, None
    clean = _strip_ansi(bytes(tail))
    last_stage = None
    last_event = None
    # Scan line-by-line for the marker, keeping the last match.
    for line in clean.splitlines():
        if _STAGE_RE.search(line) is None:
            continue
        m_stage = _STAGE_FIELD_RE.search(line)
        m_event = _EVENT_FIELD_RE.search(line)
        if m_stage is not None:
            try:
                last_stage = m_stage.group(1).decode("ascii")
            except Exception:
                pass
        if m_event is not None:
            try:
                last_event = m_event.group(1).decode("ascii")
            except Exception:
                pass
    return last_stage, last_event


def build_env(allowlist: List[str]) -> Dict[str, str]:
    """Build the child environment from an explicit allowlist only.

    Sensitive variables are never exported wholesale. Unknown allowlist keys
    that are absent from the parent env are skipped.
    """
    env = {}
    for key in allowlist:
        if key in os.environ:
            env[key] = os.environ[key]
    return env


def run_child(
    *,
    argv: List[str],
    cwd: Optional[Path],
    evidence_dir: Path,
    env_allowlist: List[str],
    timeout_sec: float,
    timeout_kill_tree: bool = True,
    extra_env: Optional[Dict[str, str]] = None,
    build_attestation_path: Optional[str] = None,
    authorized_head: Optional[str] = None,
    attempt_sequence: int = 1,
) -> Dict[str, Any]:
    """Run ``argv`` as a child, capturing stdout/stderr as raw bytes.

    Returns a structured record. Never raises on child failure (exit != 0);
    sets ``controller_error`` on controller-side faults.
    """
    evidence_dir = Path(evidence_dir)
    evidence_dir.mkdir(parents=True, exist_ok=True)
    started = utc_now()
    t0 = time.monotonic()
    configured_timeout_sec = timeout_sec

    stdout_raw_path = evidence_dir / "child.stdout.bin"
    stderr_raw_path = evidence_dir / "child.stderr.bin"
    stdout_disp_path = evidence_dir / "child.stdout.txt"
    stderr_disp_path = evidence_dir / "child.stderr.txt"
    run_json_path = evidence_dir / "controller_run.json"

    env = build_env(env_allowlist)
    if extra_env:
        for k, v in extra_env.items():
            env[k] = v

    record: Dict[str, Any] = {
        "schema_version": SCHEMA,
        "controller_tool_sha256": sha256_file(Path(__file__)),
        "command_argv": argv,
        "command_line_display": subprocess.list2cmdline(argv),
        "cwd": str(cwd.resolve()) if cwd else None,
        "environment_allowlist": env_allowlist,
        "effective_env_contract": None,
        "started_utc": started,
        "finished_utc": None,
        "elapsed_ms": None,
        "pid": None,
        "exit_code": None,
        "timed_out": False,
        "termination_action": None,
        "process_tree_cleanup_status": None,
        "spawned": False,
        "live_environment_preflight_error": None,
        "stdout_raw_path": str(stdout_raw_path),
        "stdout_raw_sha256": None,
        "stdout_raw_size": None,
        "stderr_raw_path": str(stderr_raw_path),
        "stderr_raw_sha256": None,
        "stderr_raw_size": None,
        "stdout_decode_status": None,
        "stderr_decode_status": None,
        "spawn_error": None,
        "controller_error": None,
        # Route V R0 (V0-B): deadline/output-progress evidence (populated during
        # and after the child run; present as defaults even on preflight reject).
        "configured_timeout_sec": configured_timeout_sec,
        "last_output_growth_utc": None,
        "last_output_size": 0,
        "last_observed_stage": None,
        "last_observed_stage_event": None,
        "silence_before_timeout_ms": None,
        # Route W R0 (W0-D): build-capability preflight evidence + exit gate.
        "build_capability_preflight": None,
        "build_capability_preflight_error": None,
        "build_attestation_path": build_attestation_path,
        # Route W R0 (W0-E): per-attempt evidence preservation.
        "attempt_sequence": attempt_sequence,
    }

    # Route W R0 (W0-E): evidence is preserved per-attempt. `controller_run.json`
    # is the latest-attempt pointer, but every attempt (including preflight
    # rejections) is ALSO written to a monotonic controller_attempt_NNN.json that
    # is never overwritten or deleted.
    def write_evidence(record: Dict[str, Any]) -> None:
        data_bytes = json.dumps(record, indent=2, ensure_ascii=False, sort_keys=True).encode(
            "utf-8"
        ) + b"\n"
        attempt_file = evidence_dir / "controller_attempt_{:03d}.json".format(
            record["attempt_sequence"]
        )
        atomic_write_bytes(attempt_file, data_bytes)
        atomic_write_bytes(run_json_path, data_bytes)

    # Route W R0 (W0-D): enforce the build-capability contract BEFORE spawning.
    # If the child binary is not the exact GTO-capable attested build, the run
    # FAILS with protected_spawn=0, spawned=false, pid=null, exit code 7 — a
    # build-capability preflight rejection distinct from the env/policy exit 6.
    build_preflight = validate_build_capability_preflight(
        build_attestation_path, argv, authorized_head
    )
    record["build_capability_preflight"] = build_preflight
    if not build_preflight["ok"]:
        record["build_capability_preflight_error"] = (
            "authorized GTO live build capability not met: "
            + build_preflight.get("failure_reason", "build_capability_failed")
        )
        write_evidence(record)
        return record

    # Route U R0 (U0-B): enforce the authorized env contract BEFORE spawning. If the
    # effective env does not carry MIDA_GTO_NO_BYPASS=1 (or a bypass/semantic-repair
    # escape hatch is present), the run FAILS at stage=live_environment_preflight
    # with protected_spawn=0 — the child is never started and no route attempt is
    # burned on an environment misconfiguration. Also verify the capture-policy file
    # referenced by the child argv exists (U0-B).
    env_contract = validate_authorized_env(env, env_allowlist)
    policy_preflight = validate_capture_policy_preflight(argv)
    record["effective_env_contract"] = env_contract
    record["capture_policy_preflight"] = policy_preflight
    if not env_contract["ok"] or not policy_preflight["ok"]:
        preflight_errors = []
        if not env_contract["ok"]:
            preflight_errors.extend(env_contract.get("failure_reasons", []))
        if not policy_preflight["ok"]:
            preflight_errors.append(policy_preflight.get("failure_reason", "capture_policy_failed"))
        record["live_environment_preflight_error"] = (
            "authorized GTO live preflight not met: "
            + ", ".join(preflight_errors)
        )
        write_evidence(record)
        return record

    # Open raw .bin handles and hand them DIRECTLY to Popen (bytes mode, no
    # reader thread, no text decode). This is the fix for the Route J R1 crash.
    timed_out = False
    term_action = None
    cleanup_status = None
    returncode = None

    # Route V R0 (V0-B): deadline/output-progress evidence. While the child runs
    # we poll the raw output files to learn (a) when output last grew, (b) the
    # last GTO stage observed in the log, and (c) the silence window before a
    # timeout. This is RECORDING-ONLY: the kill decision remains total-timeout
    # only (V0-C keeps no aggressive no-progress kill). The parsed stage is
    # best-effort evidence and never drives success/failure.
    last_output_growth_utc = started  # output "last grew" at spawn baseline
    last_output_size = 0
    last_observed_stage = None
    last_observed_stage_event = None
    silence_before_timeout_ms = None
    _last_growth_offset = 0.0  # monotonic offset (seconds) from t0 of last growth

    try:
        with open(stdout_raw_path, "wb") as fout, open(stderr_raw_path, "wb") as ferr:
            proc = subprocess.Popen(
                argv,
                stdout=fout,
                stderr=ferr,
                cwd=str(cwd) if cwd else None,
                env=env,
            )
            record["pid"] = proc.pid
            record["spawned"] = True
            poll_interval = 0.25
            # Poll until the child exits or the total wall-clock timeout elapses.
            # We deliberately avoid subprocess.run's blocking wait() so the
            # output-progress evidence can be captured.
            while True:
                # Sample output progress FIRST (even on the exit iteration), so
                # a fast-exiting child's final bytes are still observed. Best
                # effort; ignore transient errors.
                try:
                    size_so_far = 0
                    for p in (stdout_raw_path, stderr_raw_path):
                        if p.exists():
                            size_so_far += p.stat().st_size
                    if size_so_far > last_output_size:
                        last_output_size = size_so_far
                        last_output_growth_utc = utc_now()
                        _last_growth_offset = time.monotonic() - t0
                    new_stage, new_event = _sample_last_stage(
                        stdout_raw_path, stderr_raw_path
                    )
                    if new_stage is not None:
                        last_observed_stage = new_stage
                    if new_event is not None:
                        last_observed_stage_event = new_event
                except Exception:
                    pass
                rc = proc.poll()
                if rc is not None:
                    # Child exited: one more progress sample in case the final
                    # flush landed after the loop-top sample.
                    try:
                        size_so_far = 0
                        for p in (stdout_raw_path, stderr_raw_path):
                            if p.exists():
                                size_so_far += p.stat().st_size
                        if size_so_far > last_output_size:
                            last_output_size = size_so_far
                            last_output_growth_utc = utc_now()
                            _last_growth_offset = time.monotonic() - t0
                        new_stage, new_event = _sample_last_stage(
                            stdout_raw_path, stderr_raw_path
                        )
                        if new_stage is not None:
                            last_observed_stage = new_stage
                        if new_event is not None:
                            last_observed_stage_event = new_event
                    except Exception:
                        pass
                    returncode = rc
                    timed_out = False
                    term_action = None
                    cleanup_status = "exited_naturally"
                    break
                elapsed = time.monotonic() - t0
                if elapsed >= timeout_sec:
                    timed_out = True
                    term_action = "terminate_tree"
                    cleanup_status = "terminated"
                    # Record the silence window BEFORE killing: from last observed
                    # output growth to the moment the timeout fired.
                    silence_before_timeout_ms = int(
                        round((elapsed - _last_growth_offset) * 1000)
                    )
                    # Terminate the whole process tree.
                    try:
                        _terminate_tree(proc.pid)
                        proc.wait(timeout=5)
                    except Exception:
                        try:
                            proc.kill()
                        except Exception:
                            pass
                    returncode = proc.returncode
                    break
                time.sleep(poll_interval)
    except FileNotFoundError as exc:
        record["spawn_error"] = f"executable not found: {exc}"
    except OSError as exc:
        record["spawn_error"] = f"OSError: {exc}"
    except Exception as exc:  # controller-side fault
        record["controller_error"] = f"{type(exc).__name__}: {exc}"

    t1 = time.monotonic()
    record["finished_utc"] = utc_now()
    record["elapsed_ms"] = int(round((t1 - t0) * 1000))
    record["exit_code"] = returncode
    record["timed_out"] = timed_out
    record["termination_action"] = term_action
    record["process_tree_cleanup_status"] = cleanup_status
    # Route V R0 (V0-B): deadline evidence surfaced into controller_run.json.
    record["configured_timeout_sec"] = configured_timeout_sec
    record["last_output_growth_utc"] = last_output_growth_utc
    record["last_output_size"] = last_output_size
    record["last_observed_stage"] = last_observed_stage
    record["last_observed_stage_event"] = last_observed_stage_event
    record["silence_before_timeout_ms"] = silence_before_timeout_ms

    # Raw evidence + display copies (decode best-effort, never authoritative).
    if stdout_raw_path.exists():
        raw_out = stdout_raw_path.read_bytes()
        record["stdout_raw_sha256"] = sha256_bytes(raw_out)
        record["stdout_raw_size"] = len(raw_out)
        dec_out = decode_display(raw_out, "stdout")
        record["stdout_decode_status"] = dec_out["decode_status"]
        stdout_disp_path.write_text(dec_out["display_text"], encoding="utf-8")
    else:
        record["stdout_decode_status"] = "no_output_file"

    if stderr_raw_path.exists():
        raw_err = stderr_raw_path.read_bytes()
        record["stderr_raw_sha256"] = sha256_bytes(raw_err)
        record["stderr_raw_size"] = len(raw_err)
        dec_err = decode_display(raw_err, "stderr")
        record["stderr_decode_status"] = dec_err["decode_status"]
        stderr_disp_path.write_text(dec_err["display_text"], encoding="utf-8")
    else:
        record["stderr_decode_status"] = "no_output_file"

    # Atomic evidence write (W0-E): latest-attempt pointer + monotonic attempt file.
    write_evidence(record)
    return record


def _terminate_tree(pid: int) -> None:
    """Terminate a child and its descendants on Windows via taskkill /T."""
    import subprocess as _sp

    try:
        _sp.run(
            ["taskkill", "/PID", str(pid), "/T", "/F"],
            capture_output=True,
            timeout=15,
        )
    except Exception:
        pass


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="gto_live_route_controller",
        description=(
            "Binary-safe controller for a GTO live-route child process. "
            "Captures stdout/stderr as raw .bin evidence; never decodes during run."
        ),
    )
    parser.add_argument("--evidence-dir", required=True, help="output evidence directory")
    parser.add_argument("--cwd", default=None, help="working directory for the child")
    parser.add_argument("--timeout", type=float, default=600.0, help="timeout seconds")
    parser.add_argument("--env-allowlist", action="append", default=[],
                        help="environment variable names to propagate (repeatable)")
    parser.add_argument("--set-env", action="append", default=[],
                        help="KEY=VALUE extra env (repeatable)")
    parser.add_argument("--build-attestation", default=None,
                        help="absolute path to gto_cli_build_attestation.json (W0-D)")
    parser.add_argument("--authorized-head", default=None,
                        help="authorized baseline commit the attested build must match (W0-D)")
    parser.add_argument("--attempt-sequence", type=int, default=None,
                        help="explicit attempt sequence; if omitted, auto-increment from evidence dir")
    parser.add_argument("command", nargs=argparse.REMAINDER, help="child argv after --")
    args = parser.parse_args(argv)

    extra_env = {}
    for kv in args.set_env:
        if "=" in kv:
            k, v = kv.split("=", 1)
            extra_env[k] = v

    cwd = Path(args.cwd) if args.cwd else None
    # Route W R0 (W0-E): attempt sequence is monotonic and never reused. If not
    # explicitly given, derive it from existing controller_attempt_*.json files.
    attempt_seq = args.attempt_sequence
    if attempt_seq is None:
        evdir = Path(args.evidence_dir)
        attempt_seq = 1
        if evdir.is_dir():
            existing = [
                int(p.stem.split("_")[-1])
                for p in evdir.glob("controller_attempt_*.json")
                if p.stem.split("_")[-1].isdigit()
            ]
            if existing:
                attempt_seq = max(existing) + 1
    record = run_child(
        argv=args.command,
        cwd=cwd,
        evidence_dir=Path(args.evidence_dir),
        env_allowlist=args.env_allowlist,
        timeout_sec=args.timeout,
        extra_env=extra_env,
        build_attestation_path=args.build_attestation,
        authorized_head=args.authorized_head,
        attempt_sequence=attempt_seq,
    )
    print(json.dumps({
        "attempt_sequence": record["attempt_sequence"],
        "exit_code": record["exit_code"],
        "controller_error": record["controller_error"],
        "timed_out": record["timed_out"],
        "spawned": record["spawned"],
        "live_environment_preflight_error": record["live_environment_preflight_error"],
        "build_capability_preflight_error": record["build_capability_preflight_error"],
    }))
    # A build-capability failure means the child binary is NOT the attested
    # GTO-capable build and NO child was spawned. Return exit 7 (distinct from
    # the env/policy exit 6) so the driver can tell which gate rejected.
    if record.get("build_capability_preflight_error"):
        return 7
    # A live_environment_preflight failure means the authorized env contract was not
    # met and NO child was spawned. Return a distinctive code so the driver can tell
    # a preflight rejection (no attempt burned) from a genuine child exit.
    if record.get("live_environment_preflight_error"):
        return 6
    # Return child exit code if available (0..255), else a controller error code.
    ec = record["exit_code"]
    if ec is None:
        return 2 if record.get("controller_error") else 3
    return ec & 0xFF


if __name__ == "__main__":
    sys.exit(main())
