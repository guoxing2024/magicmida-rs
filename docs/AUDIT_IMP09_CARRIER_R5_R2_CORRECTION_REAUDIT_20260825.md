# 总指挥复核裁定 — IMP-09-CARRIER-R5-R2-CORRECTION

**复核日期**：2026-08-25  
**分支**：`codex/imp09-carrier-r5-r2`  
**当前实际 tip**：`4d5e9d27138cfba8f88a566de48f57ed68f04c07`  
**基线**：`9cd2e4d`  
**范围**：R5-R2-CORRECTION 三个提交 `7c0dc8d..4d5e9d2`

## 1. 总裁决

```ini
IMPLEMENTATION_CORRECTION = ACCEPTED_AT_SOURCE_LEVEL
MAPPING_PROOF_TYPE = ACCEPTED
R5_R2_SPECIAL_TESTS = ACCEPTED_16_0
FULL_MIDA_CLI_TEST = CONDITIONALLY_ACCEPTED_507_0_EVIDENCE
FORMAT_GATE = NOT_PASS_AS_CLAIMED
RAW_EVIDENCE_SEMANTICS = PARTIAL_CLOSURE
HEAD_REBIND = FAILED_DOC_STILL_BINDS_7C_NOT_4D
SELF_HASH_CLOSURE = FAILED_DOC_HASH_DRIFT
OVERALL = HOLD
```

**结论**：本轮没有发现新的生产逻辑硬错误；但正式验收仍 HOLD。原因是证据包没有绑定实际最终 tip，且证据元数据/自哈希闭环不足。不得把 `READY_FOR_RE_AUDIT` 升级为 `ACCEPTED`，不得派发依赖该 gate 的 R5-R3/R5-R4 实施单。

## 2. 已独立确认通过的部分

### 2.1 `region_type` 修正真实存在

当前源码已包含：

- `CandidateMappingProof.region_type: u32`；
- `mbi.Type.0` 原值记录；
- engineering `VirtualAlloc` 测试断言 `0x20000`；
- sidecar 四个 candidate 均记录 `131072`。

独立解析：

```text
evidence/r5r2/mida_antidebug_walker.evidence.json
schema = mida.antidebug-walker/v1
PID = 17088
events = 6
candidate_items = 4
all_passed = true
region_type = 131072,131072,131072,131072
raw status = 0 on execute_exit
```

该 sidecar 是生产 writer 生成的工程轨道证据，但 bridge 是 offline mock；它不是目标侧 live dispatch，也不能被升级成 live PASS。

### 2.2 R5-R2 专项测试

提交的 subset 输出记录：

```text
16 passed; 0 failed; 1 ignored
```

这与当前 R5-R2 新增测试范围相符。

### 2.3 完整 `mida-cli` 测试证据

三份提交输出均记录：

```text
507 passed; 0 failed; 1 ignored
```

因此当前机器上可以接受为：

```ini
MIDA_CLI_FULL_TEST = REPRODUCED_PASS_ON_SUBMITTED_MACHINE
```

但此前独立审计二进制曾得到 `504 passed / 3 failed`。交付报告给出的 hard-link fallback 解释是合理假设，三次后续 507/0 是复现证据；不过这些原始输出本身没有保留完整的命令、HEAD、时间、退出码和独立 stderr 元数据，因此还不能完成 cryptographic/evidence closure。

### 2.4 fmt 状态标注正确

交付已明确：

```ini
format_gate = NOT PASS
```

当前 fmt 原始输出显示退出为非零且存在既有全仓格式债；没有把它冒充 PASS。这一项语义标注通过，但证据文件自身仍缺少完整命令元数据。

## 3. 阻断项

### 3.1 最终 HEAD 绑定错误

当前实际 tip：

```text
4d5e9d27138cfba8f88a566de48f57ed68f04c07
```

但：

```text
docs/AUDIT_IMP09_CARRIER_R5_R2_20260825.md:175
```

仍写：

```text
CORRECTION HEAD: 7c0dc8d...
```

`f0bd0df` 只把文档绑定到了 `7c0dc8d`；最后的 `4d5e9d2` 只新增 final gate 文件，没有重新绑定审计文档。因此“HEAD 重绑完成”不成立。

### 3.2 文档自哈希漂移

文档 §5 列出：

```text
AUDIT_IMP09_CARRIER_R5_R2_20260825.md
0ae1c1b1478f4482adcf3b95cc5073726131ecf7125fcb53affb5cdeaf9d9ef5
```

当前磁盘文件 SHA-256 为：

```text
d7ed84d8c6c69f7bd4be5d2c409e03c16e149bf32d114c9bad1d841be5a694f4
```

该条自哈希没有闭环。源码四文件的列示 SHA 与当前磁盘内容相符；问题集中在文档自身及最终 tip 绑定。

### 3.3 原始命令证据不满足完整证据合同

当前测试输出文件能够证明测试结果文本，但未机器化记录以下字段：

- 实际命令字符串；
- 实际 HEAD；
- 开始/结束时间；
- 进程退出码；
- 独立 stdout 文件 SHA-256；
- 独立 stderr 文件 SHA-256；
- 运行时 source hash binding。

文档中的“stdout+stderr+exit code 0”是报告声明，不能替代文件中的可重算元数据。`r5r2_correction_fmt_check.txt` 还包含大量原始 trailing whitespace/ANSI 输出；这是 raw log 可以保留的现象，但应通过外置 metadata manifest 管理，不能直接声称 `diff --check` clean。

### 3.4 工作树不是 clean

tracked 文件没有修改，但当前仍有大量 untracked 历史工作单、旧审计文档和本地审计输出。不能写 `workspace clean`。本项不是 R5-R2 源码阻断，但必须在最终证据 manifest 中按 baseline/untracked-local 分类登记。

## 4. 不受本轮影响的边界

```ini
PRODUCTION_TARGET_DISPATCH = NOT_IMPLEMENTED
SECTION_PRODUCER = NOT_DISPATCHED
RUNTIME_SIDE_PROBE_EXECUTION = NOT_IMPLEMENTED
TEARDOWN_GETLASTERROR_OBSERVABILITY = NOT_DISPATCHED
PROTECTED_SAMPLE = NOT_AUTHORIZED
LIVE_4 = NOT_AUTHORIZED
```

offline mock sidecar 的 `raw status=0` 只能证明 mock seam 和 writer/schema，不证明目标侧 WalkerExecute 成功。

## 5. 解除 HOLD 的最小条件

1. 新增 sibling correction overlay，明确 `4d5e9d27138cfba8f88a566de48f57ed68f04c07` 为有效最终 tip，并把旧文档标为 superseded；不得静默改写已提交历史证据。
2. 生成外置 evidence manifest，逐项绑定：命令、HEAD、时间、退出码、stdout/stderr 路径、文件 SHA-256、源文件 SHA-256。
3. 对三次 `507/0`、一次 R5-R2 subset、other-crates、fmt 输出和工程 sidecar 全部登记。
4. 明确记录旧的 `504/3` 是另一个二进制/权限环境观察，不删除、不覆盖；若无法提供原始 symlink privilege/fallback 记录，结论只能写“后续环境复现通过，初次失败原因未完全机器证实”。
5. 重新执行 `git diff --check`，raw logs 可以保留 trailing whitespace，但必须在 manifest 中标注并把“源码 diff-check”和“raw log hygiene”分开。
6. 在上述证据闭环前，不派发 R5-R3/R5-R4 实施工作。
