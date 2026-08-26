# 总指挥审计裁决 — IMP-09-CARRIER-R5-R1

**审计日期**：2026-08-25  
**工作树**：`D:\Claude project\magicmida-rs`  
**分支**：`oreans/impl-phase03`  
**实际 HEAD**：`9cd2e4d` (`IMP-09-CARRIER-R5-R1: production lifecycle caller + derived session id + RAII allocation lifecycle + two-round section capacity`)

## 1. 总裁决

| 面 | 裁决 | 依据 |
|---|---|---|
| carrier allocation / provider | **PARTIAL** | `WalkerSessionMemory`、`RpmWalkerProvider`、transactional install 已进入生产编译路径；但尚未证明目标存活窗口与成功执行。 |
| production lifecycle caller | **WIRED-AS-BIND-ONLY** | `AntidebugController::run()` 调用 `bind_walker_from_loader_production()`；返回值只写日志，不改变 outcome。 |
| CREATE_PROCESS 时序 | **BLOCKED_AT_LIFECYCLE_ORDER** | `continue_event` 后 loader 运行，但生产路径最终仍在 `terminate_and_wait()` 之后才调用 `ad_controller.run()`；当前 bind 发生在目标终止后。 |
| post-attach 时序 | **BLOCKED_AT_LIFECYCLE_ORDER** | 观察 / dump 循环结束后先 `terminate_and_wait()`，再 `ad_controller.run()`；bind 晚于观察和终止。 |
| candidate mapping proof | **BLOCKED_AT_MAPPING_PROOF** | candidate 仍由 `module_base + i*0x1000` 派生；没有在派生/绑定前逐项 `VirtualQueryEx`、`MEM_COMMIT`、region/readability、`SizeOfImage` envelope 证明。 |
| WalkerExecute dispatch | **NOT CLOSED** | 当前生产非测试调用点未形成可验收的执行链；静态存在 export 不等于 controller 已 dispatch。 |
| section producer | **NOT IMPLEMENTED** | 生产 `write_section_header()` 写入的是 `COMPLETED_FLAG_PENDING`；全仓生产侧没有 round1/round2 的 DONE section producer。 |
| output consumer | **NOT WIRED** | `take_walker_output()` 没有生产 controller 消费闭环；测试引用不能代替生产证据。 |
| teardown observability | **NOT OBSERVABLE** | `VirtualFreeEx` 返回值和 `GetLastError` 被丢弃；目标退出后 cleanup 失败无法形成 raw evidence。 |
| overall | **HOLD** | 绑定载体不等于运行成功，不等于样本存活，不等于行为等价。 |

## 2. 独立核查事实

### 2.1 生命周期顺序

- CREATE_PROCESS 路径中，`mod.rs` 在 loader / drain 完成后执行 `terminate_and_wait()`，随后才在约 `mod.rs:1397` 调用 `ad_controller.run()`。
- post-attach 路径中，`run_post_attach_path` 完成观察 / dump 后执行 `terminate_and_wait()`，随后才在约 `mod.rs:796` 调用 `ad_controller.run()`。
- `AntidebugController::run()` 在约 `antidebug_controller.rs:979` 执行 production bind，但当前 `walker_bound` 只用于 `WALKER_BINDING=WIRED/NOT_WIRED` 日志。
- 因此当前代码最多证明“尝试 bind”，不能证明 bind 时目标仍存活，也不能把 bind 失败升级为 fail-closed outcome。

### 2.2 Candidate 映射

- `bind_walker_from_loader_production()` 仍只检查 base 非零、canonical、checked-add，然后生成四个 page-spaced candidates。
- `RpmWalkerProvider::read()` 已增加运行时 `VirtualQueryEx` + `MEM_COMMIT` + region bound + full-length RPM 检查；这是**读取时**防线，不是 candidate 列表在绑定前的 mapping proof。
- Loader 侧读取 `SizeOfImage` 并做 export envelope 检查，不能推出 `base+0x1000/0x2000/0x3000` 每一页都已提交、可读或属于允许的 probe carrier。

### 2.3 Section / execute

- `WalkerSessionMemory::write_section_header()` 写入新建 header，完成标志保持 `COMPLETED_FLAG_PENDING`。
- `WalkerExecute` 的 controller consumer 对 PENDING section fail-closed；这说明当前生产绑定后若直接执行，预期应是 abort，而不是 OK。
- DONE section 目前来自测试 helper；没有真实生产 section producer，不能把任何 `WalkerExecute=OK` 测试结果外推成生产验收。

### 2.4 Teardown

- `WalkerSessionMemory::cleanup()` 对两次 `VirtualFreeEx` 都丢弃返回值，没有 `GetLastError`、目标 PID、VA、region 和 cleanup sequence 的 raw record。
- RAII 只能保证尝试清理，不能证明清理成功；目标已退出时尤其不能静默转为 PASS。

## 3. 证据与环境边界

- 当前工作树存在大量既有 untracked `WORK_ORDER_*` / `docs/*` 与 `.serena/`；不能宣称 tracked worktree clean。
- `git diff --check HEAD~2..HEAD` 无输出；但执行 `cargo fmt --all -- --check` 被本机 Rust 环境阻断：`cargo` 尝试创建 `C:\Users\Administrator\.rustup` 时返回 `os error 183`。本次不把格式检查写成 PASS，也不重复同一失败命令。
- 未执行 protected sample、Windows live walker、WPM/CreateRemoteThread、SEH/VEH live test；LIVE-4 仍 **NOT AUTHORIZED**。

## 4. 解除 HOLD 的最小顺序

1. 先完成 **IMP-09-CARRIER-R5-R2**：生命周期窗口、存活证明、candidate mapping proof、execute status fail-closed。
2. 再单独派发 **R5-R3**：section producer + round1/round2 DONE + output consumer；禁止把协议未定的 producer 混入 R5-R2。
3. 最后才审计 teardown observability 和 engineering smoke；任何 live/protected-sample 试验必须另行授权。
