# ARCHITECTURE_MAP — 哪个功能在哪个文件

> 最后更新：2026-08-29　用途：**写工单前先查这里**，把精确文件路径写进工单，不要让 AI 员工自己找。
> 标注：[已验证] = 读过代码或跑过确认；[推断] = 由结构/命名推测。

## 依赖方向 [已验证]

```
core (调试器/进程原语)
 ├── disasm (iced-x86 封装)
 ├── pe      ── 依赖 core + disasm
 ├── tracer  ── 依赖 core + disasm
 ├── packers/themida  ── 依赖 core + pe + disasm + tracer
 ├── packers/ahk_gto  ── 只依赖 core
 └── cli     ── 聚合以上全部 + antidebug + antidebug-runtime

acceptance ── 不依赖任何生产 crate（硬边界，由 dependency_boundary.json 守）
antidebug / antidebug-runtime ── 无 mida-* 内部依赖
```

规模（`.rs` 行数，含测试）：pe 88.6k / cli 53.0k / acceptance 30.9k / packers 18.2k / antidebug-runtime 14.7k / core 13.0k / antidebug 1.8k / tracer 0.8k / disasm 0.6k。

## 入口 [已验证]

| 入口 | 文件 |
|---|---|
| CLI 主程序 `mida-cli` | `crates/cli/src/main.rs` → `crates/cli/src/lib.rs` |
| 命令分派 | `crates/cli/src/commands.rs` |
| 参数解析 / 帮助文本 | `crates/cli/src/args.rs` |
| 验收内核 `mida-acceptance` | `crates/acceptance/src/main.rs` |
| 实验宿主 | `lab/runtime/host_loader/src/main.rs`、`lab/runtime/xx21_monitor/src/main.rs`（**未提交状态的 workspace member**） |

CLI 子命令：`/unpack`、`/generic-unpack`、`/dump-process`、`/verify`、`/offline-preflight`。

## 主干链路：一次 unpack 都经过哪些文件 [已验证]

`crates/cli/src/unpacker/` 是主干，53 个文件。按执行顺序：

| 阶段 | 文件 |
|---|---|
| 主循环 / 会话编排（**最热文件，87 次改动**） | `unpacker/mod.rs` |
| 家族识别与路由（`dual_select_packer`） | `unpacker/plugin_host.rs` |
| create-process / 附加 | `unpacker/session.rs`、`unpacker/post_attach.rs` |
| 反调试控制 | `unpacker/antidebug_controller.rs` + `crates/antidebug/`、`crates/antidebug-runtime/` |
| 异常/AV 处理与取证 | `unpacker/av_handler.rs`、`unpacker/av_query.rs`、`unpacker/exception_evidence.rs` |
| 循环状态机 | `unpacker/loop_state.rs` |
| OEP 扫描 | `unpacker/oep_scan.rs`（+ `oep_evidence.rs`） |
| IAT 观察 / 追踪 / 物化 | `unpacker/iat_observe.rs`（**未提交新文件**）、`iat_trace.rs`、`iat_materialize.rs`、`iat_evidence.rs` |
| 固定基址重定位 | `unpacker/rebase_fixed.rs`（**未提交新文件**） |
| 收尾处理（V3 IAT trace、call-site fixup、anti-dump） | `unpacker/post_loop.rs` |
| dump 触发 | `unpacker/dump.rs` |
| 通用（无 shrink）路线 | `unpacker/generic.rs`、`generic_gate.rs`、`generic_bundle_assembler.rs` |
| GTO 专用宿主 | `unpacker/gto_host.rs`（重型恢复，feature `gto-product-recovery`） |
| 证据包组装 | `unpacker/bundle_assembler.rs`、`unpacker/evidence_schema.rs`、`unpacker/sidecar_io.rs` |
| 各维度证据 | `unpacker/{tls,relocation,section_rebuild}_evidence.rs` |
| 离线 preflight 门 | `crates/cli/src/runner_preflight/{mod,envelope,launch_gate,producer}.rs` |

## PE 重建：`crates/pe/src/` [已验证]

| 功能 | 文件 |
|---|---|
| dump 主流程（**第二热文件，73 次改动**） | `dumper/dump_process.rs` |
| **数据段指针重初始化 / 陈旧指针清洗**（T0.7 会话绑定缺陷所在） | `dumper/data_reinit.rs` |
| 会话模块表 sidecar 消费 | `dumper/sidecar_consumer.rs`（**未提交新文件**） |
| PE 头补丁 | `dumper/header_patch.rs` |
| 节重建 / 引用 | `dumper/sections.rs`、`dumper/section_reference.rs` |
| 导入表重建 | `dumper/import_rebuild.rs`、`dumper/import_section.rs`、`dumper/original_imports.rs` |
| IAT 缺口重定向 / 部分接受 | `dumper/iat_gap_retarget.rs`、`dumper/iat_partial_accept.rs` |
| 运行时 rebase | `dumper/runtime_rebase.rs` |
| 堆/容器快照 | `dumper/heap_global_snapshot.rs`、`dumper/container_snapshot.rs`、`dumper/container_bootstrap.rs` |
| raw slab 一致性 | `dumper/raw_slab_coherence.rs`（+ 5 个测试伴生文件） |
| 输出落盘 | `dumper/output_writer.rs` |
| 系统 DLL 导出解析（T0.9 改动点） | `dll_exports.rs` |
| TLS / 重定位 / 异常表 / 导出表 | `tls.rs`、`relocation.rs`、`exception_table.rs`、`export_table.rs`（各配 `*_observation.rs`） |
| 纯 PE 模型（R1） | `rebuild/`、`rebuild.rs`、`byte_map.rs`、`header/`、`dumper/pure_rebuild_adapter.rs` |

## 验收内核：`crates/acceptance/src/` [已验证]

`main.rs`（CLI）/ `lib.rs` / `gates/mod.rs`（结构门）/ `oreans_gate.rs`（两样品固定门，T0.8 改动点）/
`bundle_gate.rs`（证据包门）/ `preflight.rs`（起飞前校验）/ `implementation_gate.rs` / `check.rs`。

**硬约束**：本 crate 不得依赖任何生产 crate；R0B 永不输出 `Accepted`。

## 配置从哪读 [已验证]

| 配置 | 来源 |
|---|---|
| 样品身份（哈希/大小/家族） | `lab/cases/v2/*.json`（schema：`lab/cases/v2/case-manifest.schema.json`）。**生产代码通过 `include_str!` 在构建期嵌入，不许写哈希字面量** |
| 门禁向量 | `gate_vectors.json` |
| 采集策略 | `crates/cli/src/capture_policy_file.rs` + `crates/pe/src/dumper/capture_policy.rs` |
| 运行 spec / 授权档 | `crates/cli/src/run_spec.rs`、`crates/cli/src/authority_dossier.rs` |
| clippy 警告基线 | `_clippy_baseline`（只降不升） |
| 依赖治理 | `deny.toml`、`Cargo.lock` |
| 工具链 | `rust-toolchain.toml`（1.97.1，`x86_64-pc-windows-msvc`） |

## 高危区（改这些要格外小心）

1. **`crates/cli/src/unpacker/mod.rs`（87 次改动）+ `crates/pe/src/dumper/dump_process.rs`（73 次）** —— 最不稳定的两个文件，任何改动都要跑全量测试。
2. **`crates/pe/src/dumper/data_reinit.rs`** —— 陈旧指针清洗逻辑；判错一个指针就是产物启动即崩（T0.5 已实锤）。
3. **`crates/acceptance/`** —— 一旦引入生产 crate 依赖，整个"独立验收"的前提就没了。
4. **`crates/pe/src/dumper/heap_global_snapshot.rs`（38 次）、`raw_slab_coherence.rs`（30 次）** —— 测试模块曾大到 16k/19.6k 行被迫拆分（WO-9/WO-16）。
5. **`lab/cases/v2/*.json`** —— 改样品 manifest 等于改验收门的判定基准，必须走 manifest 修订评审。
