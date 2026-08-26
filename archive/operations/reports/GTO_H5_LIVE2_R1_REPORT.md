# GTO-H5-LIVE-2 Round 1 — 再基线 + 测量报告（WO-301）

**签发依据**: GTO-H5-LIVE-AUTHORIZATION-2（2026-08-22，owner 行国胜委托总指挥签发）
**账本**: GTO-H5-LIVE-2 · Round 1 · used=1/2
**执行**: 唯一 worker · 2026-08-21T17:38–17:42Z
**状态**: COMPLETE — 全败亦是有效交付（授权文件 §二.5）

---

## 一、身份预检（硬门）— PASS

- 工具: tools/resolve_gto_source_revision.ps1
- 结果: **revision_match=true**, resolution_status=ResolvedAuthorizedRevision, resolution_mode=authorized_vault
- 期望: sha256=11473d2e6b00d8a7f079e0e2d7eff9cfd0c7134af3c6bd3ca2e600b637895c86, size=24636416（manifest rev 2）
- 观测: sha256=11473d2e6b00d8a7f079e0e2d7eff9cfd0c7134af3c6bd3ca2e600b637895c86, size=24636416 — **一致**
- vault 对象验证: vault_object_verified=true
- 证据: H5_LIVE2_R1/resolved_source.json（manifest_sha256=fc57928a…, resolver_tool_sha256=4d93b68a…）
- **未消耗轮次**（mismatch 才停；本预检 PASS 后进入正式采集）

## 二、采集（no-bураs​s, Immediate timing）— PASS

- 环境: MIDA_GTO_NO_BYPASS=1, MIDA_GTO_OBSERVATION_ONLY=1（bypass/semantic-repair 变量缺席）
- 命令: mida-cli /unpack <vault artifact.exe> --data-sections --no-shrink --profile=ahk-gto-experimental --container-restore=post-crt --capture-policy=…/capture_policy.json -v
- 结果: exit 0; 候选写入 H5_LIVE2_R1/attempt_001_candidate/gto_unpacked.exe（48,796,672 字节, 12 sections）
- 结构门: EP=0x2d21000（.boot）, exec_ok=true, TLS=0x15c2e10/0x28（hint only; not R0B）, structure_ep_ok=true
- 观察模式: GTO-OBSERVATION-ONLY 下目标已终止（terminate_and_wait clean, pid=3164）—— **无产品候选声称**

## 三、R2 熵测量（dump 时刻 .rdata 密文判定）— KEY DATA

候选 manifest（gto_unpacked.dump_snapshot.json）的 r2_encrypted_region_observations：

| 节 | 熵 (bits/byte) | suspect (>7.5) | 判定 |
|---|---|---|---|
| .text | 6.002 | false | 代码（部分数据混合） |
| .rdata | 3.421 | false | 数据 |
| .data | 1.100 | false | 数据（零/低熵） |
| .pdata | 7.896 | **true** | 高熵（异常：pdata 应为结构化低熵） |
| .fptable | 0.425 | false | 数据 |
| **.rdata0** | **7.426** | false（临界） | **高度疑似密文**（接近阈值） |
| .rdata1 | 4.671 | false | 数据/混合 |
| **.rdata2** | **7.878** | **true** | **确为高熵密文**（24MB 最大段） |
| .rsrc | 5.710 | false | 资源 |

**结论**: .rdata2（24,607,744 字节）在 Immediate dump 时刻熵 7.878 bits/byte > 7.5 阈值 → **dump 时刻 .rdata2 仍为密文**。.rdata0 熵 7.426 逼近阈值（亦高度疑似密文）。**授权文件 §三 的 Round 2 条件部分满足**（Immediate 时刻 .rdata 确为高熵密文）。

## 四、Loader smoke（N=3）— 3/3 全败（有效结果）

候选: attempt_001_candidate/gto_unpacked.exe（sha256=a9141160…）

| run | PID | 退出码 | 判定 |
|---|---|---|---|
| 1 | 25460 | **-1073741819 (0xC0000005)** | AV |
| 2 | 5396 | **-1073741819 (0xC0000005)** | AV |
| 3 | 22712 | **-1073741819 (0xC0000005)** | AV |

约束: 无调试器/无注入/无 bypass/无目标补丁/20s 超时 taskkill /T。证据: H5_LIVE2_R1/loader_smoke/run_{1,2,3}/run_{1,2,3}.json

## 五、与 r27 时代 9/9 崩溃的可比性结论

| 维度 | r27 时代（H5_acceptance_1） | 本次 Round 1 | 可比性 |
|---|---|---|---|
| 样本 | manifest rev 2（11473d2e…） | 同（身份预检确认） | **一致** |
| 候选 | H4D_P6_corrected_final A/B/C | H5_LIVE2_R1 attempt_001 | 不同布局，同类 |
| smoke | 9/9 全 0xC0000005 | 3/3 全 0xC0000005 | **行为一致** |
| 环境 | no debugger/injection/bypass/target patch | 同 | **一致** |
| 崩溃模式 | 加密区乱码游走 → AV | 同退出码（未做 cdb 归因，见非声明） | **退出码可比** |

**结论**: 在样本修订不变、管线 Immediate timing 不变的前提下，loader smoke 崩溃行为与 r27 时代**完全复现**（3/3 vs 9/9，同为 0xC0000005）。R2 熵测量首次提供了 dump 时刻 .rdata2 为密文的**量化证据**，支持 WO-002/WO-102 的"内容是含加密区的运行时快照"结论——**根因未变**。

## 六、非声明段（授权文件 §五）

- ❌ 不声称 gto perfect unpack、product 1.0、"墙已破"
- ❌ 不声称 H5 解锁/签核（仍 BLOCKED_AT_LOADER_SMOKE）
- ❌ smoke 崩溃未做 cdb 归因（本报告为再基线+测量，非 acceptance evidence）
- ❌ 不声称 .pdata 高熵的原因（可能为 dump 布局/覆盖，需后续调查）
- ❌ 不声称 Round 2 已授权（WO-302 设计说明需先产出并报批）

## 七、轮次记账

- GTO-H5-LIVE-2: cap=2, **used=1**（Round 1 本次）, remaining=1
- 证据目录: H5_LIVE2_R1/（append-only, 15 文件, 含 resolved_source/candidate/sidecars/smoke）

## 八、给总指挥的后续建议

1. **WO-302（Round 2 设计说明）条件已部分满足**（.rdata2 熵 7.878 > 7.5）：建议启动 PostSelfDecrypt 设计说明（有界观察窗、仅 core 原语、零写入）
2. .pdata 熵 7.896 异常值得记录（可能干扰后续 smoke 判定，需确认是否 dump 布局所致）
3. 若 Round 2 批准：dump 时机后移的决策数据已就绪（.rdata2 密文基线 7.878）
