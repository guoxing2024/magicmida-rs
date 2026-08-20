# MIDA-ADR-3A Closeout Correction（未跟踪文件数量修正）

> **性质：** closeout 报告事实修正。不改代码、不新建提交、不删除/暂存/修改任何历史遗留文件。
> **日期：** ADR-3A 审计后。

## 1. 修正内容

ADR-3A closeout 报告第 18 项原文写：

> "未修改 CLI 生产接线（`crates/cli`/`core`/`pe`/`acceptance`/`tracer`/`disasm`/`packers`/`tools`/`lab`/`.github` 全部 clean，唯一未跟踪是历史遗留 `lab/authority_reviews/`）"

该描述不准确。`git status --short -uall`（展开未跟踪目录）的只读核验结果为：

| 项 | 数量 | 说明 |
|---|---|---|
| 未跟踪总数 | **109** | 全部为历史遗留，未进入任何 ADR-3A 提交 |
| docs/ | **97** | 历史 GTO/lab 结果文档（`docs/GTO_ROUTE_*`、`docs/GTO_RouteY_*` 等） |
| lab/ | **12** | 历史证据条目：`lab/authority_reviews/RouteY_R1_GTO_LAUNCHER_REV2_CONTROLLED_DYNAMIC_AUTHORIZATION_REVIEW_4_20260815T042456Z/` 下 12 个文件 |

> 注：`git status --short`（默认折叠未跟踪目录）显示 lab 为 1 个目录条目，展开（`-uall`）为 12 个文件。上一份报告误用折叠计数。

## 2. 修正后的事实声明

- HEAD = `a7d71a95af946dd7ae6017220511c277bec9af76`（ADR-3A 提交）；
- untracked = **109**（docs 97 + lab 12）；
- 历史文件**均未进入** ADR-3A commit（`git show --name-only HEAD` 仅 11 个 tracked 文件：`crates/antidebug/**` 6 个 + `Cargo.toml` + `Cargo.lock` + ADR-3 文档 3 个）；
- 109 个未跟踪文件均为提交前已存在的历史遗留（GTO 结果文档与 authority review 证据），与 ADR-3A 交付无关；
- 本次修正未删除、未暂存、未修改这 109 个文件；
- 修正后工作树状态与审计方核验一致。

## 3. 审计对照

| 审计项 | 结果 |
|---|---|
| ADR-3A 代码交付 | 通过 |
| ADR-3A 提交范围 | 通过（11 tracked 文件，无 GTO/lab/历史文件混入） |
| ADR-3A 测试报告 | 按交付证据通过 |
| ADR-3A closeout 文本 | **本文件修正后通过** |

## 4. 约束声明

- 未修改 `crates/**`（除 ADR-3A 已提交的 `crates/antidebug`）；
- 未修改 `tools/**`、`lab/**`、`.github/**`、Cargo 配置；
- 未新建提交（本修正为文档记录，不构成 commit）；
- 未执行样本、未执行 ScyllaHide、未做差分。