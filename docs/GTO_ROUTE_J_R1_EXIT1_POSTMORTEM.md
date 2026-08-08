# GTO Route J R1 Exit-1 Postmortem (O1)

**日期**：2026-08-08
**类型**：纯离线修复与事后分析。未运行任何 protected sample，未生成/启动 candidate，不消耗新的 live round。
**repo HEAD**：`1a12715fe3c1666d3f5f6e6223e8a10883308ba1`

---

## 一、Route J R1 结论规范化（§三）

```
normalized_status           = RouteJ_R1_InstrumentationNotReady
protected_spawn_used        = 1
candidate_generated         = false
candidate_cold_start_used   = 0
cli_exit_code               = 1
cli_failure_stage           = Undetermined
diagnostic_capture_failed   = true
route_j_r1_may_not_be_replayed = true
```

- controller `UnicodeDecodeError` 是**本 controller 的 instrumentation 故障**，不是目标程序 exception，也不得描述成 protected sample 崩溃。
- CLI exit 1 不得自动归因于 runtime rebase planner —— 因为诊断输出已丢失，stage 无法确定。

---

## 二、controller UnicodeDecodeError 精确根因（§四）

**触发代码**（Route J R1 `_controller_spawn.py:42`）：
```python
proc = subprocess.run(cmd, capture_output=True, text=True, env=env, timeout=200)
```

**机制**：
1. `text=True`（`universal_newlines=True`）且未显式 `encoding` → 用 `locale.getpreferredencoding(False)` 解码。
2. 本机 `locale.getpreferredencoding(False)` = **`cp936`（GBK）**；`sys.stdout.encoding` = `gbk`。
3. `subprocess.run` 用 reader thread（`subprocess.py:1598-1599` `_readerthread` → `buffer.append(fh.read())`）在后台解码 stdout/stderr。
4. Rust CLI 输出含非 GBK 可解码字节 → `fh.read()` 抛 `UnicodeDecodeError: 'gbk' codec can't decode byte 0x94...`（Route J R1 实测；synthetic 复现得到 `can't decode byte 0xff`）。
5. reader thread 崩溃 → stdout 缓冲区丢失（Route J R1 仅剩 1 字节 bell `0x07`），stderr 为 `None` → **`unpack.stderr.txt` 未形成**。

**结论确认**（synthetic child 复现，未运行 protected sample）：
- `returncode`（exit code）仍被正确捕获（`1`）。
- stdout 丢失（`None`），stderr 部分丢失。
- 根因：`text=True` + 无显式 encoding。

**未受影响的**：child exit code（仍正确）；但 stdout/stderr 证据丢失。

---

## 三、binary-safe controller（§五/§六）

新增 `tools/gto_live_route_controller.py` + `tools/run_gto_live_route_controller.ps1` + `tests/test_gto_live_route_controller.py`。

关键设计（修复根因）：
1. 不用 `text=True`；启动 child 时直接打开 `wb` 文件句柄传给 `Popen` 的 `stdout`/`stderr`（`Popen` bytes 模式，无 reader thread，运行期零字符解码）。
2. 权威证据：`child.stdout.bin` / `child.stderr.bin`（raw bytes）。
3. 退出后再生成展示副本 `child.stdout.txt` / `child.stderr.txt`（UTF-8 尽力解码；`decode_status` = `utf-8` 或 `utf-8_with_replacement`；`.txt` 非权威）。
4. 记录 `controller_run.json`（原子写）：`command_argv`（保 argv 边界）、`command_line_display`、`environment_allowlist`、`started_utc`/`finished_utc`/`elapsed_ms`、`pid`、`exit_code`、`timed_out`、`termination_action`、`process_tree_cleanup_status`、stdout/stderr 的 raw path + sha256 + size、decode_status、spawn_error、controller_error。
5. 解码失败不影响 child 执行 / exit code / timeout / process-tree cleanup / evidence 写入。
6. 敏感环境变量不全部导出，只按显式 allowlist 透传。
7. timeout 用 `proc.wait(timeout)` + `taskkill /T /F` 清理进程树。

---

## 四、synthetic 测试（§七）

`python -m unittest tests.test_gto_live_route_controller -v` → **Ran 27, OK**，skipped=0。

覆盖：UTF-8 stdout/stderr、GBK bytes、invalid UTF-8、混合、NUL、无换行、大输出（>pipe buffer，无 deadlock）、stdout/stderr 不混写、exit 0/1/crash、spawn 失败、timeout、timeout 后进程树清理、decoder 失败不改 exit code、raw bytes 精确一致、raw SHA-256 正确、replacement 标记、中文+空格路径、controller_run.json 原子写、已有 evidence fail-closed、controller 异常保留 raw、wrapper 保留退出码、argv 边界。

---

## 五、CLI exit-1 静态 fail-path 审计（§八/§九）

`docs/gto_exit_path_catalog.json`：**17 条** fail path，每条含 stage_id / source_file / function / error_type / error_message_prefix / candidate_written / snapshot_manifest_written / likely_before_or_after_observation / required_runtime_state / offline_reproducible / evidence_needed_to_disambiguate。

覆盖：feature/profile gate、capture policy 解析、create-process/attach、observe_gto、process-exit-before-dump、container 检测、heap global 检测、heap slab capture（RequiredRuntimeCaptureMissing）、external resolver build、runtime rebase plan validation、bootstrap install、stub build、rel32 overflow、bootstrap contract validation、plan digest mismatch、final summary not complete、candidate write atomic。

**Rust 错误上下文加固**（窄范围，不改变算法/判定/不添加 fallback）：
- `crates/pe/src/error.rs`：新增 `PeError::GtoStage { stage, error }`，Display = `GTO_UNPACK_FAILED stage=<stage> error=<error>`。
- `crates/pe/src/dumper/dump_process.rs`：6 个 GTO stage 边界从 `PeError::Parse("GTO R0-B: ...")` 改为 `PeError::GtoStage`，stable stage id：`external_resolver_build`、`runtime_rebase_plan_validation`、`bootstrap_install`、`bootstrap_contract_validation`、`bootstrap_plan_digest_mismatch`、`final_summary_not_complete`。
- 保留原始错误 source chain（`{e:#}` 嵌入 `RebaseError`/`HeapBootstrapError` 变体）。
- CLI `run()` 的 `{e:#}` Fatal 日志会自动包含 `GTO_UNPACK_FAILED stage=...`。
- 新增测试证明：planner/bootstrap/contract/digest/summary fail 时 stage 不丢失；GTO stage 错误映射到非零 exit（`EXIT_FATAL`=1），且不误判为 gate failure。

**验收**：`cargo test -p mida-pe` 317 passed（+3）；`cargo test -p mida-cli --features gto-product-recovery` 296 passed（+2）。

---

## 六、Route J R1 exit-1 根因恢复（§十）

**结论：`FailureRemainsUnderdetermined`**

- 原始 stdout 仅 1 字节 bell，stderr 未形成（controller decode bug）。
- Windows event / sysmon 无此运行记录（log 不可用）。
- 多个 fail path（见 catalog）均可能产生 exit 1 且不写 candidate；无直接持久证据指向唯一 stage。
- 因此无法诚实恢复 exact root cause；不作"最可能"冒充。

**ranked hypotheses（明确标注为推测）**：
1. `runtime_rebase_plan_validation` / `RequiredRuntimeCaptureMissing`：GTO 捕获不完整时最典型的 fail-closed 路径。
2. `create_process_attach` / `observe_gto`：protected spawn 或观察失败。
3. `bootstrap_install`（MissingImport / stub 构建失败）。
4. `bootstrap_contract_validation` / `plan_digest_mismatch`。
5. `candidate_write_atomic`：发生在 dump 后，但 candidate 目录为空，故概率较低（除非写到别处）。

**下一步**：下一次 live route（**Route K R1**，不能复用 Route J R1）必须用新 binary-safe controller；届时若失败，`child.stderr.bin` + `controller_run.json` + `GTO_UNPACK_FAILED stage=...` 将精确定位 stage。

---

## 七、边界合规

- 运行 protected sample：**否**。
- 生成/启动 candidate：**否**。
- 消耗 live round：**否**。
- 读取 `D:\Tools\RE\dumps\gto\启动器.exe`：**否**。
- 修改 acceptance / resolver(`_resolve_gto_source_revision.py` 等) / manifest / canonical vault：**否**。
- Route J R1 重跑：**否**。

## 八、修改文件

- 新增：`tools/gto_live_route_controller.py`
- 新增：`tools/run_gto_live_route_controller.ps1`
- 新增：`tests/test_gto_live_route_controller.py`
- 新增：`docs/GTO_ROUTE_J_R1_EXIT1_POSTMORTEM.md`
- 新增：`docs/gto_exit_path_catalog.json`
- 修改：`crates/pe/src/error.rs`（+`PeError::GtoStage`，+3 tests）
- 修改：`crates/pe/src/dumper/dump_process.rs`（6 处 GTO stage 错误上下文）
- 修改：`crates/cli/src/lib.rs`（+2 GTO stage exit-code tests）
