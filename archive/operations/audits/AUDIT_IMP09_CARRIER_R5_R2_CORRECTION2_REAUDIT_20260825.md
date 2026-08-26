# 总指挥复核裁定 — IMP-09-CARRIER-R5-R2-CORRECTION-2

**复核日期**：2026-08-25  
**分支**：`codex/imp09-carrier-r5-r2`  
**当前审计提交**：`3a5614e8084099469e39a0cf9e279d1c4be26983`  
**实现最终提交**：`4d5e9d27138cfba8f88a566de48f57ed68f04c07`

## 1. 独立裁定

```ini
R5_R2_CORRECTION_SOURCE = ACCEPTED_AT_SOURCE_LEVEL
R5_R2_CORRECTION_2 = PARTIAL
R5_R2_CORRECTION_2_OVERALL = HOLD
R5_R2_CORRECTION_3 = DISPATCHED
R5_R3_SECTION_PRODUCER = LOCKED
R5_R4_TEARDOWN_OBSERVABILITY = LOCKED
PROTECTED_SAMPLE = NOT_AUTHORIZED
LIVE_4 = NOT_AUTHORIZED
```

代码修改范围仍未扩大；`3a5614e` 只增加 sibling overlay、空的 diff-check raw 文件和 C2 manifest。

## 2. 已确认通过项

- 当前 branch/tip 实测为 `codex/imp09-carrier-r5-r2` / `3a5614e8084099469e39a0cf9e279d1c4be26983`。
- `final_head` 正确绑定实现提交 `4d5e9d27138cfba8f88a566de48f57ed68f04c07`。
- 旧报告未被原地修改，磁盘 SHA-256 为：
  `d7ed84d8c6c69f7bd4be5d2c409e03c16e149bf32d114c9bad1d841be5a694f4`。
- sibling overlay 磁盘 SHA-256 为：
  `b46dee13dff46af14a2e2051ba9223027cd3ba0bd049221619e07ece4c6327bf`。
- manifest 列出的 11 个外部 raw/source/diff 文件独立重算均匹配。
- `self_sha256` 字段按其声明的“移除 self_sha256 字段后再哈希”规则重算匹配：
  `0cd40746cbb13ba8cfaf1bcfe426c97fe69d83ba223aa7f766b6a099b941b8ca`。
- `offline_mock=true`、`live_authorized=false`、`protected_sample=NOT_AUTHORIZED`、`production_target_dispatch=NOT_IMPLEMENTED` 均保持分层。
- tracked changes 为 0；没有发现 R5-R2 生产逻辑、`runner_preflight.rs`、target-side dispatch 或 live 测试改动。

## 3. 独立发现的阻断

### 3.1 manifest 自身的 listed-vs-disk 哈希错误

`evidence/r5r2/imp09_carrier_r5_r2_c2_manifest.json` 当前磁盘 SHA-256：

```text
a5bef749a82b4314aa04468daa3a534779079dbda67a2db350d55fe348b73b88
```

但 C2 manifest 的 `integrity.manifest_listed_vs_disk.file_hashes` 对同一路径登记为：

```text
68c48b0b51f5a66fd7ba0b397667aea0d81d4e396d654b4aab542122975a92cf
```

因此 `listed-vs-disk = 12/12 all match` 不成立。11 个外部文件匹配，manifest 自身这一项不匹配。

这里不能把 `self_sha256`（去掉自身字段后的稳定哈希）冒充 manifest 原始文件 SHA-256；二者必须明确分成两个校验域。

### 3.2 untracked baseline 计数漂移

C2 manifest 声明：

```text
untracked_baseline.count = 51
```

本次独立执行 `git status --porcelain=v1` 实测：

```text
tracked_changes = 0
untracked_entries = 52
```

因此 baseline 也不能宣称已完全闭环。C3 必须登记完整路径清单，而不是只登记一个无法复核的数字。

### 3.3 用户交付摘要中的 self hash 与磁盘事实不一致

交付摘要提到 `self_sha256 = e3866f19...`；当前磁盘 manifest 的字段实际为 `0cd40746...`。C3 必须只引用磁盘文件和可重算结果，不沿用摘要中的旧值。

## 4. 禁止事项

- 不得原地修改 C2 manifest、C2 overlay 或旧审计文档。
- 不得重跑测试来掩盖 manifest 元数据错误。
- 不得修改任何 R5-R2 production logic。
- 不得进入 R5-R3/R5-R4。
- 不得接入 target-side dispatch、protected sample、LIVE-4、CreateRemoteThread、WPM live 或其他 live authorization。

## 5. 下一单

执行 `WORK_ORDER_IMP-09-CARRIER-R5-R2-CORRECTION-3_20260825.md`，只允许生成新的 sibling C3 manifest/overlay 与校验 sidecar；C2 证据保持冻结。
