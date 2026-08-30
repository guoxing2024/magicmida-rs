# 外部专家技术咨询答复（原文归档）

- 归档: 2026-08-31 · 总指挥存档
- 来源: 老板转达的外部专家答复（针对 docs/EXPERT_CONSULT_BRIEF_20260831.md，commit 2faf806）
- 性质: 外部意见，未经我方实验独立验证；总指挥审计结论见 docs/DECISIONS.md D-054
- 免责说明（专家原文自带）: 以下基于公开的 Themida/WinLicense 逆向研究与 SecureEngine 已知机制的一般性分析，不涉及授权绕过、注册码构造、伪授权服务或壳内校验补丁。仅回答您明确列出的六个问题。

---

## 先给结论（TL;DR）

快照 → 重建路线，对 WinLicense 保护件而言基本是已知死路，且您 C-10 的表征就是"死路"的教科书形态。
在您的约束下（无有效注册码、无原授权服务器、拒绝任何击穿），唯一有工程可行性的路是 (c)：按 GetAppVersion / Run 契约做干净重写。
原版能否走完授权：如果为在线激活且原服务器不可复活，则否；如果为离线算法校验，则理论上原版仍可能激活，但与您重建件的问题正交——重建件即使有码也不会通过。

## 逐问答

### Q1 —"dump + 重建的 WinLicense 件在新进程卡死"是否已知死路？

是。这在 Themida/WinLicense 逆向社区（tuts4you、exetools 归档、Rolles/VMP-lift 学术线）里是长期结论，理由是叠加的：

- **SecureEngine 的会话绑定校验**：VM 在 boot 阶段采集大量"环境指纹"作为后续 VM handler 派发的密钥源料——PEB.ProcessHeap、Ldr 链、TEB.ClientId、若干 syscall stub 前若干字节、__readgsqword(0x60)、KUSER_SHARED_DATA 的部分字段、以及在 boot 完成前多次 RDTSC/QueryPerformanceCounter 的差值。这些几乎全部只在"原进程时间线内首次 boot 时"有效；您把它们连同别的 VM 状态一起冻结进快照，新进程里的对应值全变，但快照里的密钥源料没变——VM 走进"派发到不合法 handler"分支时并不 AV，而是跳到静默陷阱（下面 Q2）。
- **滚动解密 + 就地擦除**：.winlice 里许多 VM 段是 JIT 解密、执行完立刻重新加密或写零；您在 t1 时刻的快照，只材料化了 t1 之前已解密过的段，t1 之后 VM 需要跳入的段仍在密文——但解密所需的 key schedule 是从 boot 之初的环境指纹推出来的，新会话里推出的 key 与快照里已材料化那部分内容不自洽。
- **句柄/线程/TLS 绑定**：您 Run 线程等的那个句柄，很可能是 boot 期由壳自己 NtCreateEvent/NtCreateSemaphore 出来、句柄值和内核对象双向存进 VM 上下文的。新进程里内核对象根本没生成，句柄槽里放的是"上一进程会话的数值副本"，NtWaitForSingleObject 直接得到 STATUS_INVALID_HANDLE 或死等——取决于壳选择哪种沉默模式。

已知能"跑起来"的做法很少且都不适用于您的目标：

- **OEP dump**（授权已通过后、VM 已把明文控制流交回宿主的极短窗口内 dump）：这是 Themida 老手们对 exe 常用的路子，可产出"能独立运行的明文 exe"。但：(i) 只对 exe 生效，DLL 因为 TLS/DllMain 时序问题窗口更窄或不存在；(ii) 需要授权先通过（您明确没有）；(iii) 新版本 Themida 的"virtualization + mutation"会让"OEP 存在"这个假设本身失效（很多函数根本没有"回到原始 x64 指令"的时刻）。
- **多时刻多次 dump 拼接**：社区偶有尝试，但对付的是简单壳。对 WinLicense 3.x/VM 保护件基本没有成功案例被公开验证过——因为"时刻 A 有效的密文段 + 时刻 B 有效的 VM 上下文"在新进程里仍然构不成自洽状态。
- **专用 unpacker**：unlicense（ergrelet/unlicense）走的是运行时 hook + 等 OEP 到达 + dump + Scylla 修 IAT 的经典路线；对 WinLicense exe 有部分成功记录，对 DLL 支持很差；且它假设授权能自然通过——不适用您的场景。

### Q2 — C-10 形态对应什么机制？

您描述的 "一个线程在 .winlice 全速空转 + Run 线程在 NtWaitForSingleObject 永等 + 无 AV / 无窗口 / 无网络" 是 SecureEngine "silent tamper response" 的典型指纹之一。Themida SDK 显式设计了多档反调试/反篡改响应，其中"沉默档"就是刻意不 crash、不弹框、不返回错误——目的正是恶心逆向者（AV 会给你调用栈，沉默不给）。

具体两条链路都典型：

- **VM 全速空转线程**：VM dispatcher 命中"完整性/环境指纹不匹配"的守卫 handler 后进入一个 opaque loop——它读一些运行时数值参与自身循环条件，条件在正常环境下才可能满足。这个 loop 本身也是 VM 化的，所以您的线性反汇编看不到明显跳转结构，.winlice 内部只显现为热点 PC。
- **Run 线程永等**：您猜的方向对——它等的是只在原进程首次 boot 时被"授权/材料化"路径产生的信号对象。可能是：授权对话框线程给它 SetEvent 的完成事件；VM 内部某个 late-decryption 阶段完成后 signal 的对象；或者反调试 helper 线程的 heartbeat。新进程里这三者都不会有。

所以 C-10 不是 bug，是 feature——它就是给"内存快照拿来重放"这类攻击的默认应答。您已经跳过了三层前哨（DYNAMIC_BASE、会话指针、EP stub），碰到的是最深一档：VM 内部状态机自洽性校验。这一层没有单点补丁能过——它是分布式跨 handler 的鲁棒设计。

### Q3 — 三条路的现实性评估

**(a) 继续快照重建 — 不推荐。** 前两问已给理由。您已经做到了公开案例里能做到的极限（会话指针普查器 hard=0、EP 修回、DllMain 存活），再往下就是要在新进程里"制造"一个与快照内 VM 密钥源料自洽的环境——这需要您在不知道 VM handler 具体形状的前提下反推它读了哪些环境指纹、以什么顺序参与哪一路密钥 schedule。这实际上等价于把 VM 反出来一部分（即路线 b）。

**(b) VM 追踪/模拟 — 技术上可行，工程上不理性。** 可行路径是 DBI（Intel PIN / DynamoRIO / Frida-stalker / QBDI）在原版可运行环境里 trace VM dispatcher，识别 handler，lift 到 IR，再语义等价地重放/静态还原被 VM 保护的函数体。参考工作：Rolf Rolles 的 Themida VM 反混淆系列、Tim Blazytko 的 VMProtect 分析、vtil-core 的 IR 设计。问题：(i) 现代 Themida 的 handler 是每次保护时 mutated 的，没有通用 handler 表；(ii) core.dll 只有 2 个导出，但导出后面的调用图未知，Run 内部可能牵到几十 kLoC 的原始逻辑；(iii) 您本来就没有能让原版完整跑起来到"授权后"状态的路子（没有码 + 服务器可能已死），VM trace 走不深，只能看到进入授权分支之前那一小段。ROI 极差。

**(c) 按 2 个导出契约干净重写 — 最现实。** 理由：

- 接口面小得反常：只有 GetAppVersion、Run 两个导出。宿主对 DLL 的语义依赖被压缩到这两个函数的行为契约上——这在保护件里是罕见的窄口，正是干净重写的理想条件。
- 您已经掌握了绝大部分外部可观测契约：后端 IP、/dll/core-version.json、/download/clear.ps1、AddOns 部署逻辑（宿主未静态导入 urlmon → 全部在 core 内部完成，等价于说：core 的对外行为几乎全部是 HTTP，即协议可观测）。
- 您可以合法建 mock 后端在 127.0.0.1 上（不是伪授权服务器，是协议镜像用来比对行为的桩），把原版跑通到窗口前的每一步 HTTP 请求-响应流量抓下来，作为"契约规范"的实证支撑。授权对话之后的行为您没证据，也就不重写那部分（或走"授权失败"分支的等价语义）。
- 法律与红线：干净重写 = clean-room reimplementation，公开先例（Wine 之于 Win32、ReactOS 之于 NT、许多 game preservation 项目）说明其合法性依赖于"契约来自外部可观测行为，实现代码不来自反编译产物"。您的证据库现在正好是外部行为侧的资产。建议实作时把"observation notes（外部可见行为）"和"implementation code（新写）"分两个人/两个 git 历史来隔离，事后可审计。

**推荐路线：(c)。** 放弃 (a)，把 (b) 的少量工作用于帮助形成 (c) 的行为契约（例如通过 PIN trace 原版 boot 阶段的 syscall 序列、网络包序列，作为 spec 补充证据），而不是用于还原 VM 语义。

### Q4 — 是否遗漏了工具/研究？

在不含击穿授权校验这个前提下，社区可用素材相当有限。您可能没系统看过的：

- Rolf Rolles：msreverseengineering.com 上关于 Themida VM 的多篇长文，最系统的公开材料（虽已数年未更新）。
- Tim Blazytko / synthesis-based deobfuscation：syntia、msynth——把 VM handler 视为黑盒函数、用程序综合恢复语义。对 mutation-heavy VM 更有效。
- unlicense（ergrelet/unlicense）：对 WinLicense exe 有部分成功记录；DLL 支持差，但其中 IAT 修复与 OEP 侦测的代码可作参考，若您决定回到 (a) 路线可读。
- ScyllaHide / x64dbg themida 插件：主要是反反调试，对您 C-10 这种沉默陷阱没有直接帮助（它防的是 debug detection，不是 tamper detection）。
- QBDI / Frida-stalker：比 PIN 轻量的 DBI，用于原版可运行时的动态观测。
- vtil-core（Can Bölük）：VM lifting 的 IR 与 pipeline，主要面向 VMProtect，思路可迁。
- game/DRM preservation 圈子的案例记录（Themida-protected 老游戏的 reimplementation）：大多数最终选择的是干净重写而非解 VM，间接印证 Q3 结论。

DLL 特有的坑：DllMain 上下文中壳能做的事被 loader lock 严格限制，这既是您能让"进程存活"的原因（壳很多重活推迟到线程里做），也是快照重放特别难成功的原因（很多 loader 关联的内核对象在新进程 loader 阶段就已经与快照不一致）。这不是您漏掉工具的问题，是路线本身的问题。

### Q5 — WinLicense 注册码校验的常见形态 & 原服务器已死时的可行性

WinLicense 支持两大类校验，且同一保护件可以同时启用：

- **离线（"registration keys"）**：注册码本身是内含用户名/许可范围/校验字段的字符串，通过非对称签名（Themida 内建 SDK 里是 RSA 类）验证。只要 SDK 时代的公钥被烧在 .winlice 里就能纯离线校验，不需要联网。
- **在线（"license activation"）**：DLL/EXE 与许可服务器一次或多次握手，服务器下发 unlock blob 写入本地（磁盘、注册表、隐蔽区）。之后可离线运行、但首次激活强依赖服务器；有的部署还带定期回连续订检查。

您的 core.dll 内嵌了 HTTP 后端 IP 且宿主不导入 urlmon，说明 core 内部至少有联网能力——但联网不一定是授权用的（也可能只是 version check + AddOns 分发，正是您抓到的两条路径）。要区分：

- 抓一次原版 boot 到"授权窗口出现前"的完整出站流量（在 mock IP 上镜像该后端，观察请求形态）。
- 看窗口出现时是不是只有 /dll/core-version.json 一类无授权关联的请求命中——若是，则大概率离线校验为主，联网只做非授权用途；若还有其它到未知路径的握手，则在线激活的可能性较高。

关于"原服务器已死"：

- 若为纯离线：与服务器无关，原版任何时候都可以通过——但您没有有效注册码，这条路对您关闭（且您明确不构造码）。
- 若为在线激活且原服务器已不可达：原版没有合法路径完成首次激活。除非原厂商仍在运营激活基础设施；否则原版这一份从"未激活"变"已激活"的路径在物理上就不存在了。这不是逆向能解决的问题，是服务生命周期问题。这也再次指向 Q3 的 (c)：既然原版本身都可能已经无法合法激活，"忠实还原 core.dll"作为目标就失去了大部分意义——按契约干净重写反而是唯一能让宿主平台继续可用的路。

### 一点方法论建议（不改变您的路线，只降未来风险）

- 在正式转向 (c) 之前，做一次"契约充分性 audit"：把您手上宿主对 core 的所有调用点（GetProcAddress 之后的所有 call 站）列全，标注每个调用点前后宿主的可观测状态改变（磁盘写入、注册表、进程创建、网络）。这份表就是 (c) 的接受测试规范。宿主静态导入零 urlmon 命中这一事实对您非常有利——说明宿主完全不 peek core 的网络细节，(c) 的实现有很大的自由度。
- 把 (a) 现有资产不要扔：会话指针普查器、EP 修补链路、evidence 库对 (c) 的意义是行为证据而非重建目标。它们证明您已经把宿主-DLL 边界摸清楚了。
- 法律侧的一步小事：如果最终产物要交付，建议在 (c) 的仓库 README 里明写 clean-room 隔离流程（谁写 spec、谁写 code、两侧代码互不参考），这是标准做法，能极大降低后续争议成本。

### 关于原始证据

Q3 的建议不依赖更多证据也能给出；如果您希望进一步细化：最有价值的补充证据是原版 boot 到"授权窗口出现"这段的完整 syscall + 网络 trace（在您的隔离环境中用 mock 后端跑一次即可）。它既能明确 core 联网是否与授权相关（Q5），也能给 (c) 的接受测试规范做锚。逐票报告本身对回答这几个问题增益已经不大——您在简报里给出的信息量已经够判断路线了。
