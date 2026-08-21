# 工作单批次 6 — Round 2 书面放行 + 壳归因程序(总指挥签发)

**签发人**: 项目总指挥 · 2026-08-22
**WO-401A 复审结论**: 4 项缺陷全部修复并经代码级核验 + 独立测试复跑
(全量 2272/0/2,EXIT=0;T1-T6 6/6;fmt PASS)。**预实弹门通过。**

---

## WO-402 书面放行(GTO-H5-LIVE-2 Round 2 实弹)

**放行范围(仅限以下,一次运行窗口)**:

1. **授权门使用规则**:`MIDA_GTO_LIVE2_AUTHORIZED=1` **仅允许在本次 unpack 调用进程环境设置**
   (单命令前缀式,如 `$env:MIDA_GTO_LIVE2_AUTHORIZED="1"; mida-cli ...`),禁止写入 shell profile/
   脚本全局/系统环境;运行后立即清除;manifest 出现 `live2_authorized=true` 即视为本次授权的消费凭证。
2. 执行序(不可调换):
   - 身份预检硬门(`resolve_gto_source_revision.ps1`;mismatch 即停,**不耗轮次**);
   - `MIDA_GTO_NO_BYPASS=1` + `--dump-timing=post-self-decrypt`;
   - 观察窗结局三选一(C1/C2/C3),时间线侧车无论结局核验落盘;
   - 若产出候选:loader smoke N≥3;
   - 报告 `docs/GTO_H5_LIVE2_R2_REPORT.md`:熵时间线全量、判据触发记录、
     **eager-vs-lazy 显式结论**(C3+平坦高熵 ⇒ lazy 成立,是有效科学结果)、
     smoke 结果、非声明段、记账 used=2/2。
3. 红线:授权文件 §四 全文继承(bypass/DRx/VEH/注入/目标写入/样本入 git/ADR7/Oreans 门)。
4. **本轮消耗后 remaining=0**;任何后续(含 F6 判据迭代)需新治理。

## WO-601(P2,可与 WO-402 并行)壳归因验证程序(离线,零实弹)

**背景**: 总指挥 2026-08-22 静态取证(vault rev2 对象):无 `.vmp*/.boot/.themida` 节名、
全库无任何厂商字符串(Themida/WinLicense/Oreans/VMProtect 全 miss)、原始节全部虚拟化
(raw=0)、导入表与版本信息加密、EP=`call $+0x188F` 进 `.rdata2`。
**"Themida" 从未被确证**——现有依据仅为行为特征(运行时乱序节名 `.,\W`、TLS 时刻解析器、
unwind 混淆),属 SecureEngine 系间接证据。

### 任务(全部只读 vault 字节,合法)

1. YARA/签名规则库比对(themida/winlicense/vmp 公开规则,离线扫描 vault 对象);
2. TLS 回调链静态解析(目录 0x15C2E10,位于 .rdata2 内)+ EP stub 模式对照表;
3. `.fptable`/`.rdata0-2`/历史 `.KI3` 命名溯源(跨 rev1/rev2/rev3 布局演变);
4. 行为特征矩阵:SecureEngine vs VMP vs 其他商业壳 × 本样本已观测行为
   (随机节名/TLS 解析器/unwind 混淆/惰性解密假设);
5. 输出 `docs/GTO_PACKER_ATTRIBUTION_REPORT.md`:结论必须分级标注
   (`confirmed` / `suspected-secureengine-class` / `unverified`);
6. 措辞修正清单:列出全库需把 "Themida" 断言改为分级措辞的文档位置
   (**本单只列清单不改写**,改写须另批,避免污染历史治理记录)。

**验收**: 报告落盘;零样本执行;不改任何既有文档断言。

---

**执行顺序**: WO-402(已放行,即刻可跑)‖ WO-601;两单分开提交。
**签发**: 项目总指挥 · 2026-08-22
