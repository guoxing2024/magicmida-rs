# AUTHORIZATION-XX-FULL — 熊熊 rev2 主攻战役全权授权

- **签署人（owner）**: 项目所有者（chat 授权，2026-08-27）
- **授权范围**:
  1. 熊熊 rev2（sha256 `7800980301207bf2f851d00a50f7f18e0dcd61a0f2b1581ca609ddcc0f2f1ea7`, 5,793,808 bytes）intake、manifest revision 授权、实弹账本（XX ledger, 4 格起步）由总指挥（审计/派单角色）全权批复，无需逐单再签。
  2. 总目标: 熊熊 rev2 完美脱壳（明文代码可读 + 正常运行 + 行为标记对齐）；完成后转 GTO 启动器战役。
  3. GTO 线 T3-3..T3-5 冻结期间不消耗 GTO 账本。
- **不可 delegation 项保留**: 样本对外分发禁止（沿用 TR §A 边界）；无干扰模式强制；vault mismatch 即 STOP；对外表述口径不变。
- **外部产物处置**: `D:\Tools\RE\dumps\gto\unpacked启动器_unpacked.exe`、`vc140.pdb` 为其他项目未验证逆向产物，按 owner 指示忽略（不使用、不隔离）。
- **生效**: 即时。收口或目标达成时出具战役报告。

---

# 终签节 — XX 战役收官（总指挥，2026-08-28）

## 判据终审（全部亲验）

- S1 结构 R0B：12/12 PASS
- S2 明文：.text 100%（222/222 块 ent<6.5，2688 prologue，OEP=0x1010 原生 MSVC CRT，壳节全剥离）
- S3 存活：load_no_crash 10/10（meta.json 逐条亲验 a1~a10 av=0 survived=True）
- S4 行为对齐：窗口标题/模块集/config.ini 字节级一致，无行为差异披露项

## 产物锚定

- 候选：`D:/MidaVault/lab/evidence/xiongxiong_duokai/xx11_attempt_20260828-112236/rev2_unpacked.exe`
- sha256：`36043cb4e82a500dbf94472d6219b0beac35823cebcd2d28fbdbaa4ab796c79b`（1,539,072 B，终签时二次复算一致）
- 五 sidecar + transform_manifest + unpack.stdout 同目录

## 账本终态

- XX I 期：4/4 耗尽；XX II 期：**7/8**，末格收回不使用（收官验证机动格未消耗）
- 关键配置永久登记：ScyllaHide K 版 ini（hash 17d51120…，关闭 KiUserExceptionDispatcher/NtContinue hook，保留 DR 隐藏）——可复现性关键，GTO 线直接复用

## 方法论登记（两条）

1. 遥测驱动假设推翻 ×2（XX-6 遥测推翻 XX-5 假设；XX-16 补证推翻 XX-10"行为真实化"伪归因）——收官前最后一问制度有效
2. live 观测真值优先于静态推断 ×1（XX-9 slot 0"三方闭合"被 XX-10 live 真值推翻）

## 后续动作（非阻塞，形式性）

- objects/sha256 正式入库（`36/36043cb4…`）与战役报告文件由 worker 补齐，哈希以本节登记为准
- GTO 线（T3-3 E16 会话 / T3-4 OEP 定位 / T3-5 tr_candidate_v2）**即刻解冻**，重启裁决书另出，XX 战役可迁移资产（K 版 ScyllaHide 配置、二次 trace、分级接受、OEP prologue 回溯、双区域 poll）逐项映射

**签署：总指挥（AI），owner 指令执行，2026-08-28**

---

## XC 追加节 — 样品独立特征化优先（owner 指令，2026-08-28）

**指令全文**: "样品身份由自身特征决定，不由节名表观或伴随关系推断。样品独立特征化优先，伴随关系与节名表观不构成家族证据。"

**执行登记（worker-I）**:
- XC-1 ④ "资产全部直接适用"作废，降级为待验假设
- manifest `tier=winlice` → `tier=unclassified_candidate`（`oreans_candidate` 保留为 hypothesis 字段，不入正式分类）
- 产出 `CORE_INDEPENDENT_CHARACTERIZATION.md`（特征矩阵 + 家族证据分级 + 基于自身特征的脱壳策略）
- 家族证据分级: 厂商字符串 **none** / 结构同构 **suspected→strong** / 运行时行为 **suspected** / 工具识别 **tool-output**
- 资产复用前提: 任何熊熊管线资产复用必须基于 core.dll 自身实证，禁止引用"与熊熊同代"

**账本**: XX-III 维持 0/4（XC-2 未消耗格子；特征化为预研工单，不计格）
