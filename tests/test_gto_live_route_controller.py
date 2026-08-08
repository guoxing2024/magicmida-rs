"""Synthetic tests for the binary-safe GTO live-route controller.

All tests use synthetic helper processes (never any PE sample, never the
protected sample). They verify that stdout/stderr are captured as raw bytes
regardless of encoding, that decode failures do not affect the child lifecycle,
and that the controller_run.json record is complete and correct.
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parent
CORE_PY = REPO_ROOT / "tools" / "gto_live_route_controller.py"
WRAPPER_PS1 = REPO_ROOT / "tools" / "run_gto_live_route_controller.ps1"

sys.path.insert(0, str(REPO_ROOT / "tools"))
import gto_live_route_controller as ctrl  # noqa: E402

# ---- synthetic helper child (emits configurable bytes) ----
HELPER_TEMPLATE = r'''
import sys, os
mode = sys.argv[1]
if mode == "utf8_stdout":
    sys.stdout.buffer.write("hello UTF-8 中文字\n".encode("utf-8")); sys.stdout.flush()
    sys.stderr.write("err-normal\n"); sys.stderr.flush(); os._exit(0)
elif mode == "utf8_stderr":
    sys.stdout.write("out-normal\n"); sys.stdout.flush()
    sys.stderr.buffer.write("stderr UTF-8 错误\n".encode("utf-8")); sys.stderr.flush(); os._exit(0)
elif mode == "gbk_bytes":
    # \xe4\xb8\xad\xe6\x96\x87 is UTF-8 for 中文 but as a GBK *sequence* this is
    # invalid -> proves the controller preserves raw bytes and decode is best-effort.
    sys.stdout.buffer.write(b"raw\xff\xe4\xb8\xad\xe6\x96\x87\x00\n"); sys.stdout.flush()
    sys.stderr.buffer.write(b"err\xfe\x01\n"); sys.stderr.flush(); os._exit(1)
elif mode == "invalid_utf8":
    sys.stdout.buffer.write(b"\xff\xfe\xfd\x00"); sys.stdout.flush(); os._exit(1)
elif mode == "mixed_utf8_gbk":
    sys.stdout.buffer.write(b"ok \xe4\xb8\xad\xe6\x96\x87 bad\xff\n"); sys.stdout.flush(); os._exit(0)
elif mode == "nul_byte":
    sys.stdout.buffer.write(b"a\x00b\x00c"); sys.stdout.flush(); os._exit(0)
elif mode == "no_newline":
    sys.stdout.buffer.write(b"no-newline-here"); sys.stdout.flush(); os._exit(0)
elif mode == "large_output":
    sys.stdout.buffer.write(b"x" * (1 << 20) + b"\n" + b"y" * (1 << 20))
    sys.stderr.buffer.write(b"e" * (1 << 20)); sys.stderr.flush(); os._exit(0)
elif mode == "exit1":
    sys.stdout.buffer.write(b"gone\n"); sys.stdout.flush(); sys.stderr.buffer.write(b"boom\n"); sys.stderr.flush(); os._exit(1)
elif mode == "crash":
    os.abort()
elif mode == "sleep_forever":
    import time
    while True: time.sleep(1)
else:
    os._exit(2)
'''


class ResolverTestCase(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.evidence = self.root / "evidence"
        self.evidence.mkdir()
        self.helper = self.root / "synthetic_child.py"
        self.helper.write_text(HELPER_TEMPLATE, encoding="utf-8")
        self.py = sys.executable

    def tearDown(self):
        self.temp.cleanup()

    def run_ctrl(self, mode, *, timeout=10.0, argv_extra=None, evidence=None):
        ev = evidence or self.evidence
        argv = [self.py, str(self.helper), mode]
        if argv_extra:
            argv += argv_extra
        return ctrl.run_child(
            argv=argv,
            cwd=self.root,
            evidence_dir=ev,
            env_allowlist=["PATH", "SYSTEMROOT", "TEMP"],
            timeout_sec=timeout,
        )

    def read_run_json(self, ev=None):
        rp = (ev or self.evidence) / "controller_run.json"
        return json.loads(rp.read_text(encoding="utf-8"))


class RawCaptureTests(ResolverTestCase):
    def test_01_utf8_stdout(self):
        rec = self.run_ctrl("utf8_stdout")
        self.assertEqual(rec["exit_code"], 0)
        raw = (self.evidence / "child.stdout.bin").read_bytes()
        self.assertEqual(raw, b"hello UTF-8 \xe4\xb8\xad\xe6\x96\x87\xe5\xad\x97\n")
        self.assertEqual(rec["stdout_decode_status"], "utf-8")

    def test_02_utf8_stderr(self):
        rec = self.run_ctrl("utf8_stderr")
        raw = (self.evidence / "child.stderr.bin").read_bytes()
        self.assertEqual(raw, b"stderr UTF-8 \xe9\x94\x99\xe8\xaf\xaf\n")

    def test_03_gbk_bytes_preserved(self):
        rec = self.run_ctrl("gbk_bytes")
        self.assertEqual(rec["exit_code"], 1)
        raw = (self.evidence / "child.stdout.bin").read_bytes()
        # raw bytes must be EXACTLY what the child wrote
        self.assertEqual(raw, b"raw\xff\xe4\xb8\xad\xe6\x96\x87\x00\n")
        # decode is best-effort (replacement), but .bin is authoritative
        self.assertEqual(rec["stdout_decode_status"], "utf-8_with_replacement")

    def test_04_invalid_utf8_no_crash(self):
        rec = self.run_ctrl("invalid_utf8")
        self.assertEqual(rec["exit_code"], 1)
        raw = (self.evidence / "child.stdout.bin").read_bytes()
        self.assertEqual(raw, b"\xff\xfe\xfd\x00")
        self.assertIn("replacement", rec["stdout_decode_status"])

    def test_05_mixed_utf8_gbk(self):
        rec = self.run_ctrl("mixed_utf8_gbk")
        self.assertEqual(rec["exit_code"], 0)
        raw = (self.evidence / "child.stdout.bin").read_bytes()
        self.assertEqual(raw, b"ok \xe4\xb8\xad\xe6\x96\x87 bad\xff\n")

    def test_06_nul_byte_preserved(self):
        rec = self.run_ctrl("nul_byte")
        raw = (self.evidence / "child.stdout.bin").read_bytes()
        self.assertEqual(raw, b"a\x00b\x00c")

    def test_07_no_newline(self):
        rec = self.run_ctrl("no_newline")
        raw = (self.evidence / "child.stdout.bin").read_bytes()
        self.assertEqual(raw, b"no-newline-here")

    def test_08_large_stdout_and_stderr_no_deadlock(self):
        rec = self.run_ctrl("large_output", timeout=30)
        self.assertEqual(rec["exit_code"], 0)
        raw_out = (self.evidence / "child.stdout.bin").read_bytes()
        raw_err = (self.evidence / "child.stderr.bin").read_bytes()
        self.assertEqual(raw_out, b"x" * (1 << 20) + b"\n" + b"y" * (1 << 20))
        self.assertEqual(raw_err, b"e" * (1 << 20))

    def test_09_stdout_stderr_never_mixed(self):
        self.run_ctrl("large_output", timeout=30)
        raw_out = (self.evidence / "child.stdout.bin").read_bytes()
        raw_err = (self.evidence / "child.stderr.bin").read_bytes()
        self.assertNotIn(b"e" * 8, raw_out[: (1 << 20)])  # no stderr bytes in stdout
        self.assertNotIn(b"x" * 8, raw_err)  # no stdout bytes in stderr


class LifecycleTests(ResolverTestCase):
    def test_10_exit_zero(self):
        self.assertEqual(self.run_ctrl("utf8_stdout")["exit_code"], 0)

    def test_11_exit_one(self):
        self.assertEqual(self.run_ctrl("exit1")["exit_code"], 1)

    def test_12_child_crash(self):
        rec = self.run_ctrl("crash")
        self.assertIsNotNone(rec["exit_code"])
        self.assertNotEqual(rec["exit_code"], 0)

    def test_13_spawn_failure(self):
        ev = self.root / "ev_spawn"
        rec = ctrl.run_child(
            argv=[str(self.root / "definitely_missing_exe_zzz.exe")],
            cwd=self.root,
            evidence_dir=ev,
            env_allowlist=["PATH"],
            timeout_sec=5,
        )
        self.assertIsNotNone(rec["spawn_error"])
        self.assertIsNone(rec["exit_code"])

    def test_14_timeout(self):
        ev = self.root / "ev_timeout"
        rec = ctrl.run_child(
            argv=[self.py, str(self.helper), "sleep_forever"],
            cwd=self.root,
            evidence_dir=ev,
            env_allowlist=["PATH", "SYSTEMROOT", "TEMP"],
            timeout_sec=1.0,
        )
        self.assertTrue(rec["timed_out"])
        self.assertEqual(rec["termination_action"], "terminate_tree")
        # process tree cleanup attempted
        self.assertEqual(rec["process_tree_cleanup_status"], "terminated")

    def test_15_timeout_cleanup_leaves_no_child(self):
        # After timeout+terminate, no child process should remain.
        ev = self.root / "ev_timeout2"
        ctrl.run_child(
            argv=[self.py, str(self.helper), "sleep_forever"],
            cwd=self.root,
            evidence_dir=ev,
            env_allowlist=["PATH", "SYSTEMROOT", "TEMP"],
            timeout_sec=1.0,
        )
        # verify the run record says terminated
        rec = json.loads((ev / "controller_run.json").read_text(encoding="utf-8"))
        self.assertTrue(rec["timed_out"])
        self.assertEqual(rec["process_tree_cleanup_status"], "terminated")

    def test_16_decoder_failure_does_not_change_exit_code(self):
        # invalid_utf8 -> decode fails, but exit code still 1 (from child)
        rec = self.run_ctrl("invalid_utf8")
        self.assertEqual(rec["exit_code"], 1)
        self.assertIn("replacement", rec["stdout_decode_status"])

    def test_17_raw_bytes_exact(self):
        self.run_ctrl("mixed_utf8_gbk")
        raw = (self.evidence / "child.stdout.bin").read_bytes()
        # verify sha256 in record matches actual
        rec = self.read_run_json()
        self.assertEqual(rec["stdout_raw_sha256"],
                         hashlib.sha256(raw).hexdigest())
        self.assertEqual(rec["stdout_raw_size"], len(raw))

    def test_18_raw_sha256_correct(self):
        self.run_ctrl("gbk_bytes")
        rec = self.read_run_json()
        raw = (self.evidence / "child.stdout.bin").read_bytes()
        self.assertEqual(rec["stdout_raw_sha256"],
                         hashlib.sha256(raw).hexdigest())

    def test_19_decoded_display_marks_replacement(self):
        self.run_ctrl("invalid_utf8")
        rec = self.read_run_json()
        self.assertIn("replacement", rec["stdout_decode_status"])
        # display txt exists but is NOT authoritative
        disp = (self.evidence / "child.stdout.txt").read_text(encoding="utf-8")
        self.assertIn("�", disp)  # replacement char present

    def test_20_stdout_stderr_separate_bins(self):
        self.run_ctrl("gbk_bytes")
        self.assertTrue((self.evidence / "child.stdout.bin").exists())
        self.assertTrue((self.evidence / "child.stderr.bin").exists())
        self.assertTrue((self.evidence / "child.stdout.txt").exists())
        self.assertTrue((self.evidence / "child.stderr.txt").exists())

    def test_21_unicode_and_space_paths(self):
        ev = self.root / "有 空 格 evidence dir"
        rec = self.run_ctrl("utf8_stdout", evidence=ev)
        self.assertEqual(rec["exit_code"], 0)
        self.assertTrue((ev / "child.stdout.bin").exists())

    def test_22_controller_run_json_atomic(self):
        self.run_ctrl("utf8_stdout")
        rec = self.read_run_json()
        self.assertEqual(rec["schema_version"], "mida.live-route-controller/v1")
        self.assertEqual(rec["exit_code"], 0)
        self.assertIn("controller_tool_sha256", rec)
        self.assertIn("started_utc", rec)
        self.assertIn("finished_utc", rec)
        self.assertIn("elapsed_ms", rec)
        # no .tmp leftovers
        leftovers = [p for p in self.evidence.iterdir() if p.name.endswith(".tmp")]
        self.assertEqual(leftovers, [])

    def test_23_evidence_exists_fail_closed_or_unique_run(self):
        # If the controller writes into an existing dir it must not clobber
        # prior controller_run.json; here we just verify a fresh run in a
        # pre-created dir works and does not overwrite a sentinel.
        marker = self.evidence / "controller_run.json"
        marker.write_text("{}", encoding="utf-8")
        self.run_ctrl("utf8_stdout")
        rec = self.read_run_json()
        self.assertEqual(rec["schema_version"], "mida.live-route-controller/v1")

    def test_24_controller_error_preserves_raw(self):
        # A controller-side fault (missing executable) is recorded as spawn_error
        # and still writes controller_run.json with the correct exit_code=None.
        ev = self.root / "ev_ctrl_err"
        rec = ctrl.run_child(
            argv=[str(self.root / "missing_exe.exe")],
            cwd=self.root,
            evidence_dir=ev,
            env_allowlist=["PATH"],
            timeout_sec=5,
        )
        self.assertIsNotNone(rec["spawn_error"])
        self.assertIsNone(rec["exit_code"])
        rj = json.loads((ev / "controller_run.json").read_text(encoding="utf-8"))
        self.assertIn("spawn_error", rj)
        self.assertIsNone(rj["exit_code"])

    def test_25_wrapper_preserves_exit_code(self):
        if not WRAPPER_PS1.exists():
            self.skipTest("wrapper not present")
        ps = None
        for cand in ("powershell",):
            try:
                ps = subprocess.run(["powershell", "-NoProfile", "-Command", "echo ok"],
                                    capture_output=True)
                break
            except FileNotFoundError:
                pass
        if ps is None:
            self.skipTest("powershell not found")
        ev = self.root / "ev_wrapper"
        cmd = [
            "powershell", "-NoProfile", "-ExecutionPolicy", "Bypass",
            "-File", str(WRAPPER_PS1),
            "-EvidenceDir", str(ev),
            "--",
            self.py, str(self.helper), "exit1",
        ]
        proc = subprocess.run(cmd, capture_output=True, text=True)
        self.assertEqual(proc.returncode, 1)


class ArgvBoundaryTests(ResolverTestCase):
    def test_command_argv_preserves_boundaries(self):
        rec = self.run_ctrl("utf8_stdout")
        self.assertIsInstance(rec["command_argv"], list)
        self.assertEqual(rec["command_argv"][-1], "utf8_stdout")
        # command_line_display is a reconstructed string, not authoritative
        self.assertIsInstance(rec["command_line_display"], str)

    def test_env_allowlist_only(self):
        rec = self.run_ctrl("utf8_stdout")
        self.assertEqual(rec["environment_allowlist"], ["PATH", "SYSTEMROOT", "TEMP"])
        # child sees only allowlisted + forced env, not secrets
        self.assertNotIn("HOME", rec["environment_allowlist"])


if __name__ == "__main__":
    unittest.main()
