# 自查自纠对照 — 专家审计 2026-07-27

> **状态：** Blocked 维持；本文件记录对专家结论的**核实 + 已落地修正**，不宣称产品解封。  
> **HEAD 基线：** `6211e6c` + dirty working tree。  
> **纪律：** 完成 P0 前冻结新功能 / 不堆 GTO 特例。

## 1. 专家结论核实

| ID | 专家声明 | 自查结果 | 处置 |
|----|----------|----------|------|
| P0-1 | EP 修复写穿 section table | **确认**。`ao = e_lfanew+24+SizeOfOptionalHeader` 是节表首；`ao+16` = 首节 `SizeOfRawData`。错误块为**未提交** r27 补丁。 | **已修**：正确 OptionalHeader+16；加 golden 单测 |
| P0-2 | `build_stub_code` 测试签名 18 vs 24 | **确认**。生产调用已 24 参，两处 unit test 仍 18 → E0061。 | **已修**：测试对齐 24 参；去掉 `?;;` 笔误 |
| P0-3 | `Accepted` 可假绿 | **确认**。`parse_json` 只校验 status 枚举；`compose` 只看 `verdict`。`status=fail + verdict=Pass` 可 Accepted。 | **已修**：parse + compose fail-closed；单测拒绝 Pass/fail 不一致 |
| P1-IAT | complete ≠ 全解析 | **同意**（本轮未改语义） | 下一波；冻结宣称 IAT complete |
| P1-FTMGuard | 恢复错区 | **确认**。FTM 把 Themida 设 NX 后，下一次仍只 VirtualProtectEx(.text)。 | **已修**：临时恢复 active guard；再 re-arm .text |
| P1-GTO bypass 默认 | 通用 dumper 默认打固定 RVA | **确认**。原 `!no_bypass` 默认开补丁。 | **已修**：默认 OFF；仅 AhkGtoExperimental 且 `MIDA_GTO_BYPASS=1` |
| P1-覆盖原件 | `--output` / `*MM.exe` | **确认** | **已修**：CLI 同路径拒写；dumper 拒 alias；stub 已存在则 temp 唯一名 |
| P1-bwhook | 自挂起 / 注入无限等 | **同意** | 不合并主路径；本轮不修 bwhook |
| P2 | CI/文档漂移 | **同意** | 后续 Windows CI |

## 2. 本轮代码变更清单

| 文件 | 变更 |
|------|------|
| `crates/pe/src/dumper/dump_process.rs` | 正确 EP 读写；GTO bypass opt-in；输出 alias 拒写；EP 偏移单测 |
| `crates/pe/src/dumper/container_bootstrap.rs` | stub 测试签名；`?;;` |
| `crates/acceptance/src/behavior.rs` | verdict↔status 一致；compose 再校验；单测 |
| `crates/packers/themida/src/guard.rs` | FTMGuard 恢复 active Themida 区 |
| `crates/cli/src/unpacker/helpers.rs` | `--output` 别名输入保护 |
| `crates/core/src/process.rs` | `*MM.exe` 已存在 → temp 唯一路径 |

## 3. 环境变量语义变更（破坏性，正确方向）

| 旧 | 新 |
|----|-----|
| 默认应用 5 个 GTO bypass；`MIDA_GTO_NO_BYPASS=1` 关闭 | **默认不打 bypass**；`MIDA_GTO_BYPASS=1` + AhkGtoExperimental 才打开 |
| `MIDA_GTO_NO_BYPASS` 仍影响 slab / scrub / retarget | 保留研究开关；与 product bypass 脱钩 |

带 bypass 的产物 = **diagnostic**，不得标产品 Accepted。

## 4. 仍 Blocked 的原因

1. 全量 workspace 测试 / Clippy / CI 未宣称全绿。
2. IAT complete 假成功、transform ledger、分层 verdict 未完成。
3. GTO 行为等价仍未达成；BootWatch 仅为 research。
4. `validation_summary.json` 历史 Accepted 叙事未改写。
5. 未提交 BootWatch 大 diff 不得在 P0 验证前当发布 merge。

## 5. 推进顺序

1. 本机验证 P0：`cargo test -p mida-pe/mida-acceptance/mida-themida --offline`
2. 分层状态：`load_no_crash_v0` ≠ 产品 Accepted
3. IAT 全覆盖 + transform ledger
4. BootWatch/softbp 独立 harness
5. Windows CI 门禁

## 6. 验证记录（本机 MSVC 14.44）

| 命令 | 结果 |
|------|------|
| `cargo test -p mida-acceptance --offline --lib` | **11/11 pass**（含 `parse_rejects_pass_verdict_with_fail_status`、`compose_rejects_pass_verdict_with_fail_status`） |
| `cargo test -p mida-pe --lib address_of_entry_point` | **pass** |
| `cargo test -p mida-pe --lib tls_process_attach` | **pass**（签名对齐后可编译） |
| `cargo test -p mida-pe --lib data_offset_uses_dword` | **pass** |
| `cargo check -p mida-packers-themida --offline` | **ok**（FTMGuard 变更可编译） |

仍有既有 warning（unused 等），非本轮引入阻塞。

## 7. 复核轮（同日 residual）— 已再修

| 复核项 | 处置 |
|--------|------|
| IAT `current_slot=total` 假 complete | CLI `product_complete()`：resolved+failed+skipped==total 且 failed==0 且 !aborted；坏 API 计 fail 续走；trash 记 abort |
| themida `trace_imports` 静默 break | 坏结果计 fail 续走；trash abort；日志 product_complete |
| `is_within_image` 忽略边界 | shim 恒 false + 新增 `is_within_image_bounds` + 单测 |
| Accepted 仍可自证 | Pass 需：注册 probe、bilateral reference+sha256、ledger 无未授权 transform；`load_no_crash_v0` 拒 Accepted |
| transform ledger | `BehaviorEvidence.transform_ledger`；无 `equivalence_rule` → 拒 Accept |
| hard link 覆盖 | CLI/dumper：volume serial + file index |
| DLL stub TOCTOU | 始终 %TEMP% 唯一名 + `CopyFileW(bFailIfExists=true)` |
| bwhook 在 workspace | 移出 `members`（research-only） |

## 8. 复核轮验证（MSVC 14.44）

| 命令 | 结果 |
|------|------|
| `cargo test -p mida-acceptance --offline` | **全绿**（含 load_no_crash / none-ref / ledger 拒 Accept） |
| `cargo test -p mida-packers-themida --lib within_image` | **2/2 pass** |
| `cargo check -p mida-cli --offline` | **ok**（IAT product_complete 可编译） |
| `cargo check -p mida-packers-themida` | **ok** |

## 9. 调用链闭环轮（复核 residual）

| 复核缺口 | 处置 |
|----------|------|
| Themida `product_complete` 只写日志 | `TraceImportResult` 携带 total/resolved/failed/skipped/aborted/product_complete；`gate_v3_trace_result(&result)` **只**看 `product_complete` |
| equivalence_rule 任意字符串 | 代码内 `REGISTERED_EQUIVALENCE_RULES` allowlist；`i_pinky_promise` 拒 Accept |
| GTO bypass 无 ledger | dump 写 `*.transform_ledger.json` sidecar（无 rule → 阻 Accept） |
| check→write TOCTOU | `write_output_atomic`：create_new temp → 再查 alias → rename |
| bwhook workspace 继承 | 独立 `version`/`windows` pin，不继承 workspace |

验证：themida gate 3/3、acceptance equivalence 2/2 + behavior_compose 10/10、pe/cli check ok。

## 10. Manifest 强制链轮（sidecar → 证据）

| 复核缺口 | 处置 |
|----------|------|
| sidecar 仅提示、可省略 | dump 后写 **bound** `*.transform_manifest.json`（candidate sha+size+entries）；失败则 **删除 dump** |
| rule 全局字符串 | `(id, kind, rule)` 三元组注册；`gto_bypass + pe_iat_rebuild_v0` 拒 |
| copy fallback | 已删除；rename 失败即 Err |
| bwhook workspace | 根 `exclude` + 子 crate 自有 `[workspace]` |
| `product_complete` 缓存 bool | 改为 `is_product_complete()` 实时计算 |
| acceptance 不读 sidecar | `check-with-behavior` 若存在 sibling manifest → `enforce_into_evidence` |

验证：themida gate 3/3、acceptance lib 14/14、behavior_compose 10/10、pe/cli check ok。

## 11. Fail-closed 收口轮

| 复核缺口 | 处置 |
|----------|------|
| remove dump best-effort | `remove_dump_and_manifest` 收集 residual 路径；清理失败并入 error |
| manifest 无 alias 检查 | `write_bound_transform_manifest(..., input)` 对 manifest 路径做 volume/file-index |
| sibling manifest optional | **始终**写 manifest（含空 ledger）；`check-with-behavior` **默认要求** sibling；lab 用 `--allow-unmanaged-candidate` |
| delete-then-rename 空窗 | Windows `MoveFileExW(REPLACE_EXISTING\|WRITE_THROUGH)`，无先删目标 |
| clean rerun 旧 manifest | 每次 dump 覆盖写最新 bound manifest |

验证：acceptance 全套绿、themida gate 3/3、pe/cli check ok。

## 12. 统一 emit / library managed 轮

| 复核缺口 | 处置 |
|----------|------|
| `.NET` dump 绕过 | headers 覆盖 offset 0；atomic + 始终 manifest；`dump_dotnet_with_source` |
| library 无 manifest 可 Accept | `check_with_behavior` 封顶 Pending；`check_with_behavior_managed` 才可 Accept |
| manifest 非权威 merge | 同键冲突拒；manifest null rule 否决 evidence rule |
| temp 写失败残留 | write/sync 失败删 temp |
| BA3/B-B / validation_summary | BA3 写 empty manifest；B-B 适配；summary **superseded** |

## 13. .NET OEP / compose 可见性 / VerifiedManaged 轮

| 复核缺口 | 处置 |
|----------|------|
| .NET OEP 再减 ImageBase → 0 | 参数改名 `entry_point_rva`，**直接写入** AddressOfEntryPoint |
| CLI 传 `None` source | `dotnet_dump_and_dump_output(..., input)` → `Some(input)` |
| 公开 `compose_with_behavior` | `pub(crate)` + **不再** crate root re-export |
| 手搓 TransformManifest | 字段私有；`VerifiedManagedCandidate::verify` / `from_parsed_manifest` |
| .NET 短读成功 | full-image 短读 **Err** |

## 14. Native 短读 / API 收紧轮

| 复核缺口 | 处置 |
|----------|------|
| native short read 仅 warn | **Err** fail-closed |
| source-less `dump_dotnet` | **删除** public API；仅 `dump_dotnet_with_source(..., &Path)` |
| 公开 empty managed 铸造 | 删除 `empty_for_candidate` / `from_parsed_manifest`；测试走 JSON+`verify` |
| OEP 测试仅算术 | serialize_headers 后重读 AddressOfEntryPoint |

## 15. Transform taxonomy v1 冻结

| 产物 | 内容 |
|------|------|
| `docs/TRANSFORM_TAXONOMY_V1.md` | standard vs ledger vs sample_bypass；注册表；签名前置清单 |
| `docs/ACCEPTANCE_CONTRACT.md` | managed/unmanaged；taxonomy 链接 |
| `TRANSFORM_TAXONOMY_VERSION` | `mida.transform-taxonomy/v1` 常量 |
| dump manifest | 写入 `taxonomy_version` 字段 |

**仍不得 CI 签名**：envelope 未实现；AhkGto overlay/capture 未强制入 ledger。

## 16. taxonomy_version 强制

| 项 | 处置 |
|----|------|
| `Option` + 仅 Some 时校验 | 改为 **必填** `String`；缺失 → `TaxonomyVersionMissing` |
| 未知版本 | `TaxonomyVersionMismatch` |
| 测试 | missing / unknown / exact-match 三测 |
| BA3 fixture manifest | 写入 v1 |

**可宣称：** managed Accept **强制** taxonomy v1 绑定（非“存在则校验”）。

## 17. Capture 入 ledger + taxonomy 错误分类

| 项 | 处置 |
|----|------|
| P2 serde 文本分类 | wire struct `Option` → 显式 `TaxonomyVersionMissing` |
| early overlay | `early_section_overlay` / `capture` |
| heap slab | `heap_slab_restore` / `capture` |
| cs_reinit | `cs_reinit` / `pe_repair` |
| 测试 | missing/unknown 匹配 **enum variant** |

Capture 行 **无** 注册 equivalence → 出现即禁产品 Accept。

## 18. Signature envelope 验证侧

| 项 | 处置 |
|----|------|
| `mida.signature-envelope/v0` | `crates/acceptance/src/envelope.rs` |
| 字段 | taxonomy / candidate / manifest / evidence / probe / ref / tool / git / toolchain / uuid / key |
| 校验 | digest 绑定 + dirty 拒绝 + 空 allowlist fail-closed + HMAC-SHA256 |
| API | `VerifiedSignedBundle` + `check_with_behavior_signed` |
| 自签 | **无** dumper 自签；`sign_hmac_sha256_for_test` 仅测试/CI 工具 |
| Ed25519 | 保留算法 id，未实现 → reject |

## 19. CLI 强制 envelope（cap 策略）

| 项 | 处置 |
|----|------|
| 无 envelope | managed 若会 Accepted → **降为 Pending** + warning |
| 有 envelope | `verify_bundle` + `check_with_behavior_signed` |
| lab | `--allow-unsigned-managed`（BA3/BB） |
| 密钥 | `--envelope-key-id` + `--envelope-hmac-key-hex` / 同名 env |

## 20. Envelope 信任断链修复（审计 P0/P1）

| 项 | 处置 |
|----|------|
| 验签后可换 evidence | `verify_bundle` 从 hashed JSON 解析并 **封存**；`check_with_behavior_signed(bytes, opts, signed)` 无外部 evidence 参数 |
| 调用者控制 HMAC 信任根 | 默认拒 HMAC；需 `--allow-hmac-lab` + `allow_hmac_lab`；产品路径无 Ed25519 时 **拒绝** 把 caller HMAC 当产品信任 |
| report 覆盖 manifest/envelope | alias 检查纳入 transform_manifest + signature_envelope File handle |
| heap bootstrap 未入 ledger | 安装成功记 `heap_bootstrap` / `capture`（与 `heap_slab_restore` 分离） |

## 21. Library cap + freshness policy

| 项 | 处置 |
|----|------|
| unsigned managed library | `check_with_behavior_managed` → **Pending cap** |
| lab Accept | 显式 `check_with_behavior_managed_lab` / CLI `--allow-unsigned-managed` |
| 唯一非 lab Accept API | `check_with_behavior_signed` |
| 删除 `allow_key()` | 仅 `hmac_lab_key()` |
| freshness | `created_utc` 解析 + `max_age_secs`（默认 7d）+ `expires_utc` + clock skew |
| run_uuid / toolchain | 非空 + UUID-like / 非空 |
| producer/commit allowlist | policy 可选强制 |
| alias 测试 | manifest exact + hard-link；envelope failed-verify 不截断 |

## 22. GTO-CTX-DIFF（分析主线）

| 项 | 结论 |
|----|------|
| dump | `launcher_bw39.exe` SHA `bcf18e6e…99b0` |
| 线性环 | FETCH→inc r10→dec rbp→jne FETCH / ALT |
| SOI 谓词 | **RBP==0 + 无 per-lap trap** → VIP=SOI；**RBP≥1** → 消除 SOI，进 ALT |
| INT3/TF | 把 `dec 0` 锁成 ZF=0 线性前缀，**不是**产品路径 |
| VSP | 解释 `[rdi]`/…f8；**不**单独解释 SOI |
| 残留 | RBP=0 free-run 下 **写 r10=SOI 的指令 RIP** 未钉死 |
| 文档 | `docs/KI3…§12.6.12`；`MidaVault/scratch/bootwatch/gto_ctx_diff_report.md` |

## 23. GTO free-run 阶梯（RBP→VSP→ALT ret）

| 阶 | 结果 |
|----|------|
| RBP=0x515 in stub | 无 SOI；VIP 线性至 ALT |
| + VSP @ fetch1 | 越过 `mov [rdi],r11d` |
| ALT body | **`add rbx,rax` + `push/ret` → `0x16f6ba711`**（3/3） |
| 根因类 | `[r8]` 流解码出的 eax 使 rbx 落在非镜像 |

## 24. R9 默认恢复纠偏 → 再晋升

| 阶段 | 处置 |
|------|------|
| 审计 P1 | 曾撤回 R9 默认（free-run 后段非镜像 RIP） |
| GTO-ALT-LIVE-DIFF | 首 ALT RET 在 freeze R9 下 **3/3 镜像内** `0x1405feb75`，模型 bit-exact |
| 现策略 | R9 **默认恢复**；`MIDA_BOOTWATCH_NO_R9=1` 分析关断 |
| 测试 | stub：默认含 RBP+R9；NO_RBP / NO_R9 |

后段 `0x1c2e9bc*` = 首 handler 之后 VIP 被 `mov r10,[rsp+rax]` 污染，**不是**
首 RET 失败。

## 25. GTO-STACK-EA-DIFF（restart 字段闭环）

| 项 | 结果 |
|----|------|
| 指令 | `mov r10,[rsp+rax] @ 0x1405febb8` |
| `rax` / `ea_rel` | `0x90` / **`0x7e0`**（3/3） |
| slot → r10 | **`0x1b75950`** bit-exact（3/3） |
| 分类 | `heap_or_user`（非镜像 VIP） |
| free-run | 仍 AV（悬空 pointee `+8` 或后继非镜像） |
| 证据 | `gto_stack_ea_diff_runs/capture_r*.json` |

P1 纠偏已落地：R15 stub 共用 RBP/R9；`VmRestartPolicy` 消测试 env 竞态。

## 26. GTO-POINTEE-CAPTURE-1

| 项 | 结果 |
|----|------|
| 同 freeze 读槽 | `rsp+0x90` → `0x7fe7e0`（3/3） |
| live pointee | **`0x100000000`**（3/3），非旧 `0x1b75950` |
| VirtualQueryEx | **MEM_FREE** — 合法拒绝，无 `slot.bin` |
| 代码 | `query_region_full` / `MemoryRegionInfo`；`capture_stack_slot_pointee`；sidecar `*.slot.json` |
| 标签 | restart 侧 `unknown_user_va`（不再伪称 heap） |

**负结果也是闭环：** DISPATCH 时刻该槽不是可恢复堆对象；不得用 bw39 死进程 VA 伪造。

## 27. 仍 Blocked

1. **GTO-POINTEE-EPOCH** — 在 `0x1405febb8` 实际执行时（或等价 VIP 纪元）再捕获 committed/readable region。
2. 最小 pointee 恢复 + free-run 过下一转移 → GTO-UI-1。
3. Stub 内嵌 VSP；产品 authenticity / CI 支线。

**可从 residual 移除：** DISPATCH freeze 能否做 MBI 槽捕获（能）；槽是否恒为旧 `0x1b75950`（否）。

**不宣称脱壳完成或 UI。状态 Blocked。**
