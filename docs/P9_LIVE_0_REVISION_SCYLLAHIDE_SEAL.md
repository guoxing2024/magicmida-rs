# P9-Live-0 Revision and ScyllaHide Environment Seal

> This work order corrects P9 live authorization prerequisites only. It does not
> start any real sample, does not consume any live slot, does not modify
> validation_summary.json, and does not execute P9 live.

## 一、选定的方案

**方案 A（推荐，已采用）**。

理由：当前仓库 HEAD 是 `b507f88d9389d718346124945dd8107e69c68e66`（P9-Live Authorization Manifest 的 manifest-only 提交），不包含 live 代码变更。现有 P9 代码和二进制已按 `169c122a571207a36f1f48020b9c6622bff74640` 固定。为避免混用 revision，创建了 clean detached worktree 精确 checkout `169c122a` 作为 P9 live candidate source，主 worktree 未修改。

## 二、Revision

| Item | Value |
|---|---|
| 仓库当前 HEAD | `b507f88d9389d718346124945dd8107e69c68e66` |
| **选定 candidate revision** | `169c122a571207a36f1f48020b9c6622bff74640` |
| detached worktree | `D:\Claude project\magicmida-rs-p9-169c122a` |
| worktree HEAD | `169c122a571207a36f1f48020b9c6622bff74640`（== candidate revision） |
| worktree `git status --short` | *(empty — clean)* |
| worktree branch | detached HEAD |
| toolchain | rustc 1.97.1（`--locked` 构建） |

## 三、二进制身份（detached worktree `--locked` release 构建）

| File | canonical path | size | SHA-256 | PE arch |
|---|---|---|---|---|
| mida-cli.exe | `D:\Claude project\magicmida-rs-p9-169c122a\target\release\mida-cli.exe` | 3,588,608 | `7686d2c08a75b42989e9df523c38da7fc5a50703e248b81870f22e652c17f698` | AMD64 (0x8664) |
| mida-acceptance.exe | `D:\Claude project\magicmida-rs-p9-169c122a\target\release\mida-acceptance.exe` | 2,108,416 | `8f8bcdc68b526a1abfed0c82558e120885b0fcbdd3fc92190e7ac147fc576272` | AMD64 (0x8664) |

构建命令：`cargo build -p mida-cli --release --locked --offline` 和
`cargo build -p mida-acceptance --release --locked --offline`（rustc 1.97.1）。

**Verifier 约束（源码验证）：** 只解析 CLI sibling `<cli-dir>/mida-acceptance.exe`
（`resolve_acceptance_bin` / `resolve_acceptance_bin_from_cli`）；不读
`MIDA_ACCEPTANCE_BIN`；拒绝 `--acceptance-bin`；无 PATH fallback；launch 前重校验
canonical path + SHA-256。envelope `verifier_source = <cli-dir>/mida-acceptance.exe`，
`verifier_sha256 = 8f8bcdc6...`。

## 四、runner identity（权威值来自 preflight 生成并经验证 Ready 的 envelope v4）

| Field | origin_macro | lunlun_software |
|---|---|---|
| runner_config_digest | `984582533ecc069e5c3f2aa87b0734c7fdaba190bd9526a059e545fb8cb1de1e` | `d838f51e82064a92f66bda4beecb0283b10fde574d68488fa9c5cda1ffc2e361` |
| pure_rebuild | **true** | **false** |
| features | `['default','oreans-classic']` | same |
| oep_policy | captured | same |
| container_restore | off | same |
| shrink / data_sections | true / false | same |
| timeout / isolation | 120 / blocked-network, single-process, isolated-temp | same |
| capture_policy digest | empty | same |
| tool_revision | `169c122a571207a36f1f48020b9c6622bff74640` | same |
| CLI SHA-256 | `7686d2c0...` | same |
| verifier SHA-256 | `8f8bcdc6...` | same |

两个 digest 不同且不可互换（`pure_rebuild` 不同）。Envelope schema
`mida.runner-config-envelope/v4`。未复用 P7-R2 / P6.3.3 旧 envelope；新 envelope 已
在 `<root>\preflight_out\runner-config-envelope.json` 生成。

## 五、ScyllaHide 环境身份（本次实际 staging 重新计算）

来源（已批准第三方）：`D:\MidaVault\scratch\b0_a1_cargo_target\debug\`，复制到新
execution root 的两个 debug staging 目录 `<root>\scyllahide\baseline\` 和
`<root>\scyllahide\candidate\`。

| File | size | SHA-256 (小写 64 hex) | PE | regular | MOTW |
|---|---|---|---|---|---|
| InjectorCLIx64.exe | 794,624 | `211f7b804f1db43abddbb3dbdf41162d6cee76ae84e0bb38818cdbf4d07cf630` | AMD64 | yes | none |
| HookLibraryx64.dll | 19,968 | `d4b20eed23caebad7efa53e5f2f3c86d445864c2d3e43b343e01c8a9785e800e` | AMD64 | yes | none |
| scylla_hide.ini | 1,324 | `17d51120c13b54e64ea6615ee9b885fa07a4a41bd3008ed559fdbabe8184ff8e` | config (not PE) | yes | none |

- baseline 与 candidate 两 staging 目录 **字节级完全一致**（三文件逐一比对 identical=True）。
- 目录读写探针：baseline 和 candidate 均 write_probe=ok、read_probe=ok。
- 目标 debug 目录：`<root>\scyllahide\baseline\`（reference）和 `<root>\scyllahide\candidate\`（candidate）。
- 无 MOTW Zone.Identifier 阻断。
- 注入日志关键字检查方式：live 时对 InjectorCLI 输出/日志中的注入成功关键字与 ScyllaHide 注入 API 返回状态做断言（不在本工单执行）。

## 六、P9 live root（新，独立）

| Item | Value |
|---|---|
| canonical root | `D:\MidaVault\scratch\p9_live_169c122a_20260806_140803` |
| run_id | `p9_live_169c122a_20260806_140803` |
| source worktree | `D:\Claude project\magicmida-rs-p9-169c122a` |
| candidate revision | `169c122a571207a36f1f48020b9c6622bff74640` |
| CLI SHA | `7686d2c0...` |
| verifier path + SHA | `<root>\staging\mida-acceptance.exe` · `8f8bcdc6...` |
| ScyllaHide 3-file SHA | 见第五节 |
| origin digest | `98458253...` |
| lunlun digest | `d838f51e...` |
| stale/partial/output-collision scan | 0 stale bundles, 0 partial markers |
| worktree clean + HEAD==tool_revision | confirmed (detached worktree HEAD == 169c122a..., clean) |
| disk free | 175.46 GB |

旧 manifest root `...\p9_live_auth_manifest_20260806_134400` **保留，未覆盖、未复用**。

## 七、重新生成候选侧身份（修正后 revision）

- rustc 1.97.1，`--locked`，重新构建 mida-cli 和 mida-acceptance（见第三节）。
- verifier 只能来自 CLI sibling（确认）。
- 重新生成 case-bound envelope v4（`<root>\preflight_out\runner-config-envelope.json`）。
- 重新运行 acceptance 独立 verifier（preflight 内部 sibling 调用）：**两个 case 均 READY**（preflight.json `status: ready`）。
- origin_macro `pure_rebuild=true`；lunlun_software `pure_rebuild=false`；两个 digest 不同且不可互换。

## 八、禁止项符合

- 未启动任何样品进程。
- 未创建 candidate live 输出（仅 staging 了二进制/样品副本供身份校验；`preflight_out` 只含 envelope/preflight 报告，无 candidate dump）。
- 未消耗 46 process / 22 slot 预算。
- 未修改 P7 roots。
- 未修改 validation_summary.json。
- 未声明 P9 live / 10/10 / perfect / universal / final acceptance。
- 未添加 CLI flag、环境变量、PATH fallback 或测试绕过 seam。

## 九、出口报告

- **选定方案**：A（理由见第一节）。
- **exact revision**：`169c122a571207a36f1f48020b9c6622bff74640`。
- **CLI/verifier SHA**：`7686d2c0...` / `8f8bcdc6...`。
- **两 case runner digest**：origin `98458253...`，lunlun `d838f51e...`（preflight 生成 + verifier 验证）。
- **ScyllaHide 三文件 SHA**：`211f7b80...`、`d4b20eed...`、`17d51120...`。
- **两侧 staging 路径**：`<root>\scyllahide\baseline\` 与 `<root>\scyllahide\candidate\`，字节一致。
- **新 execution root**：`D:\MidaVault\scratch\p9_live_169c122a_20260806_140803`。
- **Ready preflight 结果**：`preflight.json status=ready`，两 case READY。
- **0 个真实样品进程**：本工单未创建任何样品进程。
- **0/22 unpack slot 使用**：未消耗任何 unpack slot。
- **validation_summary.json 未变**：blob 与起始一致（见下）。
- **P7 roots 未变**：本工单只读复制已批准样品/不写 P7 root。
- **P9 live 前置条件**：除真实 candidate unpack 的最终 candidate SHA（live 产物）和 ScyllaHide 注入日志实测外，其余身份（revision、二进制、digest、envelope、preflight Ready、ScyllaHide 三文件封存）均已就绪。

**本工单完成后停止，等待审核方重新签发 P9 live 授权。** 未获授权前不得启动任何样品。
