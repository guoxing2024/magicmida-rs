# 总指挥复核裁定 — IMP-09-CARRIER-R5-R2-CORRECTION-3

**复核日期**：2026-08-25  
**分支**：`codex/imp09-carrier-r5-r2`  
**当前 tip**：`8a1d272d6f84b035e74a79f1eca2141a4f9f4b96`  
**实现最终提交**：`4d5e9d27138cfba8f88a566de48f57ed68f04c07`

## 1. 独立裁定

```ini
R5_R2_CORRECTION_SOURCE = ACCEPTED_AT_SOURCE_LEVEL
R5_R2_CORRECTION_3 = PARTIAL
R5_R2_CORRECTION_3_OVERALL = HOLD
R5_R2_CORRECTION_4 = DISPATCHED
R5_R3_SECTION_PRODUCER = LOCKED
R5_R4_TEARDOWN_OBSERVABILITY = LOCKED
PROTECTED_SAMPLE = NOT_AUTHORIZED
LIVE_4 = NOT_AUTHORIZED
```

`41ce7ee` 与 `8a1d272` 没有触碰生产逻辑；本轮阻断全部在证据元数据层。

## 2. 已独立确认

- 当前 branch/tip 正确：`codex/imp09-carrier-r5-r2` / `8a1d272d6f84b035e74a79f1eca2141a4f9f4b96`。
- `implementation_final_head` 正确绑定 `4d5e9d27138cfba8f88a566de48f57ed68f04c07`。
- C2 manifest 原始 SHA 仍为 `a5bef749a82b4314aa04468daa3a534779079dbda67a2db350d55fe348b73b88`，未被原地修改。
- C3 raw manifest SHA 与外部 sidecar 匹配：
  `5e15bdcb25588ef73429ec46128a6bacb70615a70d9e9670c1c6461f374faa04`。
- C3 登记的 11 个 external artifacts 独立重算全部匹配。
- C3 manifest 的 56 条路径数组与清单文本内容逐项匹配。
- source hashes、`git_diff_check_raw.txt`、offline-only authorization state 均保持正确。

## 3. 独立阻断

### 3.1 C3 self hash 按自声明规则不匹配

C3 manifest 声明的 self hash：

```text
a4e2c8505eecafe8eeb31ed288ffca1d7513158f5c4c7c5b202e84b842afa91a
```

manifest 的 `hash_contract` 声明规则是：移除 `self_sha256` 字段后，对其余最终 UTF-8 manifest 内容进行 SHA-256。

按该字节级规则独立重算当前磁盘文件，结果为：

```text
c8b511479657ae832989bbcfcabac6275fee486e42776d0b1ed96386b38d5d6a
```

因此 `self_sha256 = MATCH` 不成立。若实际使用了 JSON canonicalization 或其他序列化规则，必须把算法、编码、换行和序列化字节定义写死，并提供可重复的 verifier；当前 manifest 没有这样的定义。

### 3.2 untracked 清单 SHA 不匹配

C3 manifest 登记：

```text
untracked_baseline.list_sha256 = 0f62998f722c4df7fe48f71d8bbbe43acfe82fce1f000897b0da4493aec23755
```

当前磁盘清单独立重算：

```text
64a883f1851ba78bab1e7a24d4839e91a211ad1f94e8b266cc38dcad21e987e7
```

这与 `8a1d272` 对清单注释的修改一致：清单内容变了，但 manifest 未同步更新。`56/56` 只能证明路径集合文本相等，不能证明清单文件 hash 绑定正确。

### 3.3 capture-time 路径不能冒充当前集合

清单文本包含：

```text
tmp_c3_build.py
```

当前磁盘该文件不存在；当前 live status 为 55 个 untracked 项，且当前集合与 capture-time 集合差异为该路径。这个历史捕获本身可以保留，但必须明确 `capture_time_set != current_live_set`，不得用 `55 = 56 - 1` 推导集合完全一致。

## 4. 下一单

执行 `WORK_ORDER_IMP-09-CARRIER-R5-R2-CORRECTION-4_20260825.md`：冻结 C3，使用新的 sibling manifest/overlay/sidecar，重新完成 self hash 算法绑定和 untracked 清单哈希绑定。不得原地修改 C3 或更早证据。
