# GTO Product Recovery — Route Q R0 Offline Repair Work Order

**签发日期：** 2026-08-09  
**签发角色：** 审计 / 派单负责人  
**绑定基线：** `d11580695c349648e40674b493c2f939458d9608`  
**绑定分支：** `oreans/two-sample-mainline`  
**前序终态：** `RouteP_R1_CandidateNotReady` / `raw_slab_overlay` / `TransformPreimageDrift`

---

## 0. 决策

**正式授权 Route Q R0，仅限离线代码修复、synthetic/unit/integration 测试和证据整理。**

Route P 永久冻结，不存在 Route P R2。Route Q R0 不包含 protected spawn、live capture、candidate 生成或启动。Route Q R1 不是本工单的一部分，必须在本工单通过审计后另行书面放行。

本路线的唯一主目标：

> 让 ProbeWindow / InteriorSubview 的 transforms 明确以 authoritative slab slice `S` 为输入 preimage，并让 overlay 只应用可证明从该 preimage 派生的写入。

禁止用“忽略冲突”“保留 T”“跳过 +0x28”“降低 fail-closed”等局部绕法关闭问题。

---

## 1. 已确认事实

Route P R1 的关键三方字节：

```text
child = 0x8aa5f8
kind = InteriorSubview
size = 0x70
field = Label.mName +0x28
C = 0x00                 # t1 child capture
S = 0xf0                 # t2 authoritative slab
T = 0x28                 # transformed result
```

实际产生 `T=0x28` 的 transform 已收窄为 `repair_label_names_after_scrub`：

```text
label_live + LABEL_INLINE_NAME_OFF
= 0x8aa5f8 + 0x30
= 0x8aa628
```

当前 `transform_ids` 仅提供 child 级 provenance，无法证明某个具体 transform 写了哪个 byte/run。这是必须同时补齐的审计缺口。

---

## 2. 工作范围

严格串行执行：

```text
Q0-A  authoritative transform-input seeding
  -> Q0-B byte/run-level transform provenance
  -> Q0-C three-way overlay 改造
  -> Q0-D Label.mName 定向回归
  -> Q0-E 全量离线门禁与审计包
```

一个阶段未过，不进入下一阶段。最多允许两轮“实现 -> 测试 -> 修正”；两轮仍未通过则终态为 `RouteQ_R0_NotReady`，留下 residual，不得转 live 碰运气。

---

## 3. Q0-A — Authoritative transform-input seeding

### 要求

在 raw child/slab capture 完成、任何 transform 开始前，为每个可映射的 heap child 建立显式 transform preimage basis：

| Extent | Transform preimage | 规则 |
|---|---|---|
| `ObservedAllocation` | `C` | 必须先证明 `C == S` |
| `BackingObject` | `C` | 必须先证明 `C == S` |
| Container | `C` | 必须先证明 `C == S` |
| `ProbeWindow` | `S` | exact range 映射后，以 slab slice seed transform input |
| `InteriorSubview` | `S` | exact range 映射后，以 slab slice seed transform input |
| `SyntheticDerived` | synthetic | 不参与 raw coherence |

### 强制证据

新增明确的数据结构或 ledger，至少记录：

- `capture_id`
- child old base / size / extent kind
- slab old base / offset
- basis：`ChildCapture` 或 `AuthoritativeSlabSlice`
- `C` digest
- `S` digest
- transform-input digest
- 是否发生 seed

不得仅靠注释或隐式调用顺序声称 transform 使用了 `S`。

### Fail-closed

以下任一情况必须拒绝：

- child 无法唯一映射到 slab；
- offset/size overflow；
- slab slice 长度不完整；
- strict extent 出现 `C != S`；
- probe/interior 宣称 slab basis，但 transform-input digest 与 `S` 不一致。

---

## 4. Q0-B — Byte/run-level transform provenance

保留现有 child 级 `transform_ids` 兼容字段，但新增 contiguous write-run provenance。

每个 run 至少包含：

- child identity：capture id / old base / size；
- `transform_id`；
- child-relative offset；
- length；
- before digest / after digest；
- first before byte / first after byte；
- 可选完整 before/after bytes（若尺寸受控）。

`record_transform_applied` 或等价机制必须按每个 transform 的 before/after diff 生成 run，而不是只给整个 child 挂一个 transform id。

对本次几何，synthetic test 必须能输出等价证据：

```text
transform_id = repair_label_names_after_scrub
child_offset = 0x28
before = authoritative S-derived value
final = preserved pointer or safely repaired pointer
```

不得再把 `mark_labels_non_nested` 错归为 `+0x28` writer。

---

## 5. Q0-C — Three-way overlay 改造

定义：

- `C`：raw child capture；
- `S`：authoritative slab slice；
- `P`：实际 transform input preimage；
- `T`：最终 transformed child。

### Strict extents

```text
P = C = S
write-set = { i | T[i] != P[i] }
```

任何 `C != S` 继续按 `RawCaptureDrift` fail-closed。

### Probe/interior extents

```text
P = S
capture drift = { i | C[i] != S[i] }
write-set = { i | T[i] != P[i] }
backing starts from S
```

处理规则：

1. `C != S` 且 `T == S`：记录 `NonWriteSlabAuthoritative`，不写 overlay。
2. `C != S` 且 `T != S`：只有在 ledger 证明 transform 从 `P=S` 顺序派生时才允许写入，并记录新的 resolution（建议名：`TransformReplayedOnAuthoritativePreimage`）。
3. transform basis 缺失、digest 不匹配或 write run 无法归属：`TransformPreimageDrift` / 新的明确错误，fail-closed。
4. overlapping views 仍按最终 byte value 解决；same-byte different-value 冲突继续拒绝。
5. input order 不得改变 patched slab、overlay ledger 或 drift ledger。

不能把所有 probe drift 无条件转为 pass。放行依据必须是“transform 确实从 S 派生”，不是 extent kind 本身。

---

## 6. Q0-D — Label.mName 定向修复与测试矩阵

必须增加以下 synthetic tests：

1. **C null / S exact captured pointer**  
   预期：以 S seed；保留 pointer；`+0x28` 无 transform write。

2. **C null / S captured interior pointer**  
   预期：从 authoritative parent 提取 wide string，建立 exact snapshot；pointer 语义保持。

3. **C null / S dangling pointer / inline name valid**  
   预期：scrub 以 S 为 before 清零，repair 再写 `label_live+0x30`；byte provenance 显示两步顺序；overlay 合法。

4. **C/S 在 mName qword 内部分字节漂移**  
   预期：不得拼接 C/S 形成混合指针；必须使用完整 S qword 或拒绝。

5. **mark_labels_non_nested attribution**  
   预期：只归属 `+0x23`，不得归属 `+0x28`。

6. **Route P exact geometry regression**  
   child size `0x70`、first drift `0x28`、InteriorSubview；以 synthetic full-qword S pointer 覆盖现场几何。

7. **S pointer 不可分类且 inline 不可恢复**  
   预期：保持 fail-closed；不得伪造非空 mName。

8. **determinism**  
   调换 child/input order，transform-input ledger、write-run ledger、patched slab digest 一致。

---

## 7. 主要修改目标

预期写集限定为：

- `crates/pe/src/dumper/heap_global_snapshot.rs`
- `crates/pe/src/dumper/raw_slab_coherence.rs`
- `crates/pe/src/dumper/dump_process.rs`
- `crates/pe/src/dumper/snapshot_manifest.rs`（只用于输出新 ledger/schema）
- 对应 Rust tests
- Route Q R0 离线结果文档

如需修改 resolver、authorized vault、sample manifest、candidate acceptance、live controller 或 protected-launch 代码，必须停工并重新报审；本工单不授权这些范围。

---

## 8. 明确禁止

- protected sample spawn；
- cold-start candidate；
- Route P R2；
- Route Q R1；
- 读取/修改 canonical vault；
- 修改 resolver 或 revision binding；
- 将 `TransformPreimageDrift` 降级为 warning；
- 特判地址 `0x8aa5f8`、offset `0x28` 或本次 slab base；
- “冲突时保持 T”“冲突时跳过 write”“先生成 candidate 再观察”；
- 将 synthetic test pass 描述成 live blocker 已修复；
- push / PR / 远程发布。

---

## 9. 离线验收门

全部满足才允许签署 `RouteQ_R0_OfflineRepairReady`：

### 静态与单测

- `cargo fmt --all -- --check`：0 diff；
- 当前 R0-G tests：27/27，不得删减或放宽断言；
- R0-F.1：20/20；
- R0-F.2：25/25；
- 新 Route Q tests：至少 8 个，全部通过；
- `cargo test -p mida-pe`：不得低于基线 480 passed，0 failed；
- `cargo test -p mida-cli --features gto-product-recovery`：不得低于基线 296 passed / 0 failed，现有 ignored 保持可解释。

### 审计性质

- 不存在 hard-coded live address/sample-specific byte bypass；
- manifest 可独立证明每个 transformed child 的 preimage basis；
- byte/run ledger 能唯一定位 `+0x28` writer；
- strict extent 规则没有被削弱；
- old R0-G fail-closed negative tests 继续成立；
- repo diff 只在授权写集；
- 无 candidate、无 debuggee PID、无 live evidence claim。

### 结果文档

新增 Route Q R0 offline result，必须列出：

- commit/diff baseline；
- 修改文件；
- preimage/overlay 状态机；
- 新旧测试计数；
- exact synthetic reproduction；
- 已知剩余风险；
- 是否建议申请 Route Q R1。

---

## 10. Route Q R0 终态

只允许二选一：

### `RouteQ_R0_OfflineRepairReady`

表示离线模型、测试和证据过门；**不表示 live 已修复，不表示可生成 candidate。** 此状态仅允许审计负责人考虑签发独立的 Route Q R1。

### `RouteQ_R0_NotReady`

表示任一验收门未过。必须保留 fail-closed，写 residual，禁止进入 live。

---

## 11. 后续 Route Q R1 放行条件（当前未授权）

只有 Route Q R0 获得 `OfflineRepairReady` 后，审计负责人才能另行签发 Q R1。未来 Q R1 默认预算上限：

- 1 route attempt；
- 1 protected spawn；
- 0 rerun；
- 0 cold-start，除非 raw slab overlay 已成功并自然生成 candidate，且新工单明确授权；
- 失败即新 route letter，不复用 Q R1。

Q R1 的首要观察点不是 UI/OEP，而是：

1. Route P exact geometry 是否仍出现；
2. transform-input ledger 是否证明 `P=S`；
3. `repair_label_names_after_scrub` 的 `+0x28` write 是否基于 authoritative preimage；
4. raw slab overlay 是否完成；
5. candidate 是否自然产生。

---

## 12. 派单结论

**立即开工 Route Q R0。实现人员先做 Q0-A，不得直接改 overlay 放行条件。**

审核顺序：

1. 先审 preimage seeding 与 ledger；
2. 再审 byte/run provenance；
3. 再审 overlay 状态机；
4. 最后跑全量离线门禁。

没有 authoritative transform-input 证据，任何“修复了 +0x28”的 patch 一律退回。
