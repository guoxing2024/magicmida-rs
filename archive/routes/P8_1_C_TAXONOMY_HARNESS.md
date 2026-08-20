# P8.1-C —— 可复现 gate taxonomy harness

**状态:** 实现完成（P8.1-C 阶段）
**范围:** 纯离线工程。未访问 D:/MidaVault、未打开/启动任何真实样品、未创建任何样品进程、未执行 P9。

## 目标

把 P8-A 的 `failure_taxonomy` 分类逻辑固化为**显式可复现的命令行工具**：对一份 v8 two-sample gate report（`bundle_gate_report.json`）做只读的逐 sample failure 分类，输出稳定 JSON（绑定输入 SHA-256），使分类结果可被审计从相同字节复现。

## 命令

```
mida-acceptance classify-gate-report <bundle_gate_report.json> [--report PATH]
```

- 输入必须**显式指定**；工具**只读**，绝不修改输入，也绝不写入 P7-R2 execution root。
- 输出 JSON 字段（`mida_acceptance::failure_taxonomy::GateReportClassification`）：
  - `input_sha256` —— 精确输入字节的 SHA-256（64 位小写 hex）
  - `total_failures` —— 全 sample failure 总数
  - `samples[]`：
    - `case_id`
    - `total_failures`
    - `buckets` —— 桶名 → 计数（BTreeMap 稳定序）
    - `other_count` —— 落入 `Other` 的数量（永不静默丢弃）
    - `other_failures` —— 每条 `Other` 的原始文本，保持 report 顺序
    - `unclassified` —— 恒为 0（`Other` 是唯一 catch-all）
- 退出码：`0` = 成功，`1` = I/O 或 schema 错误。

## 人工运行（synthetic 输入）

由于 P7-R2 原始 `bundle_gate_report.json` 是 P7-R2 execution root 的一次性现场产物（未提交、不复制），此处用一份**与 P7-R2 分类口径一致的 synthetic 输入**做端到端人工运行；`failure_taxonomy` 单元测试已用合成 failure 串覆盖 P7-R2 各桶的真实文本（origin 9/298、lunlun 1423/43，见 P8_A_FAILURE_TAXONOMY.md）。

**输入文件（临时 scratch，运行后删除，未提交）：**
```json
{
  "schema_version": "mida.oreans-two-sample-gate/v8",
  "gate_id": "oreans_two_sample_perfect_unpack",
  "required_cases": ["origin_macro", "lunlun_software"],
  "excluded_cases": [],
  "samples": [
    { "case_id": "origin_macro", "failures": [
        "prerequisite failed: structured OEP evidence: VA is missing",
        "prerequisite failed: structured IAT evidence: structured IAT report: Unresolved status at slot 1",
        "prerequisite failed: structured relocation evidence: final relocation DYNAMIC_BASE is not set",
        "a brand-new gate message not yet classified"
    ]},
    { "case_id": "lunlun_software", "failures": [
        "prerequisite failed: structured section rebuild evidence: duplicate section name",
        "another unknown failure"
    ]}
  ],
  "final_verdict": "open"
}
```

**命令：**
```
mida-acceptance.exe classify-gate-report <scratch>/synthetic_gate_report.json
```

**输入 SHA-256：**
```
9d58552b3cf7edd24ffdc16ea51a912f15739db89509ace4d374f55bb2d536d1
```

**输出（exit=0）：**
```json
{
  "input_sha256": "9d58552b3cf7edd24ffdc16ea51a912f15739db89509ace4d374f55bb2d536d1",
  "total_failures": 6,
  "samples": [
    {
      "case_id": "origin_macro",
      "total_failures": 4,
      "buckets": { "iat-unresolved": 1, "oep": 1, "relocation": 1 },
      "other_count": 1,
      "other_failures": ["a brand-new gate message not yet classified"],
      "unclassified": 0
    },
    {
      "case_id": "lunlun_software",
      "total_failures": 2,
      "buckets": { "section-rebuild": 1 },
      "other_count": 1,
      "other_failures": ["another unknown failure"],
      "unclassified": 0
    }
  ]
}
```

结果验证：origin 的 `oep`/`iat-unresolved`/`relocation` 与已知 P7-R2 分类口径一致；`section-rebuild` 正确归类；两条未知 failure 均落入 `Other` 且带原始文本、计入总数——**不静默丢弃**。

## 设计

- `failure_taxonomy::classify_gate_report(&[u8]) -> Result<GateReportClassification, String>`：解析 report 只读 `case_id` + `failures` 两字段（lean schema，与真实 v8 report 兼容，不重派生任何 gate 决策）。
- `Other` 是唯一 catch-all：未知 failure 计入 `other_count` 且保留原始文本与顺序，绝不折叠到已知桶。
- 输入 SHA-256 与分类绑定同一份字节，保证可复现。

## 默认测试不访问 Vault

默认 `cargo test -p mida-acceptance --offline` 只用仓库内 synthetic fixture；`classify-gate-report` 只读取调用方显式指定的输入路径，不触碰 D:/MidaVault，不包含任何真实 candidate / sample / 原始 sidecar。P7-R2 原始报告未提交、未复制到本仓库。

## 明确 pin

- 本阶段不处理 behavior oracle、isolated replay 10/10、最终验收（v8 gate 仍可保持 open）。
- 本阶段只固化 failure 分类 harness，不修改任何 producer / gate / PE emission 决策。
