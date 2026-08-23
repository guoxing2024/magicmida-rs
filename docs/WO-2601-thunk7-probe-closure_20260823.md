# WO-2601 交付 — thunk7 probe runtime layout + exact-byte closure

**审计基线**：`639eee3`（Batch 25 最终 HEAD）
**性质**：local x64 runtime + design fixture；不实现生产 thunk；不运行远程

## 1. 修复的缺陷（Batch 25 审计）

| 缺陷 | 修复 |
|------|------|
| Args10 无 reserved 字段 → rsp_probe 实际在 +0x40，探针写 +0x48，读零值假阳性 | 布局改为 ThunkArgs7Probe（reserved +0x40、rsp_probe +0x48、sizeof 0x50）+ `_Static_assert` |
| 无真实写入证明（清零字段低 4 位通过） | 非零 sentinel `0xDEADBEEFCAFEBABE`，探针必须覆盖它 |
| "65B"叙述错误 | 修正为 production 60B / test 64B |
| production call@0x35 与 test call@0x39 未分离 | 分离并逐字节验证 |

## 2. 布局（冻结，与 WO-2501-thunk7-runtime-contract.h 一致）

~~~c
typedef struct ThunkArgs7Probe {
    uint64_t fn_ptr;     /* +0x00 */
    uint64_t arg0;       /* +0x08 */
    uint64_t arg1;       /* +0x10 */
    uint64_t arg2;       /* +0x18 */
    uint64_t arg3;       /* +0x20 */
    uint64_t arg4;       /* +0x28 */
    uint64_t arg5;       /* +0x30 */
    uint64_t arg6;       /* +0x38 */
    uint64_t reserved;   /* +0x40 */
    uint64_t rsp_probe;  /* +0x48 (written by 49 89 63 48) */
} ThunkArgs7Probe;         /* 0x50 */
_Static_assert(sizeof(ThunkArgs7Probe) == 0x50);
_Static_assert(offsetof(ThunkArgs7Probe, reserved) == 0x40);
_Static_assert(offsetof(ThunkArgs7Probe, rsp_probe) == 0x48);
~~~

## 3. Production 60B vs Test 64B（分离，冻结）

### 3.1 production THUNK7_CODE（60B，call rax @0x35）

字节（与 WO-2301-thunk7-fixture.h THUNK7_CODE 逐字节一致）：

~~~text
49 89 CB 49 8B 03 49 8B 4B 08 49 8B 53 10 4D 8B 43 18 4D 8B 4B 20
48 83 EC 38 4D 8B 53 28 4C 89 54 24 20 4D 8B 53 30 4C 89 54 24 28
4D 8B 53 38 4C 89 54 24 30 FF D0 48 83 C4 38 C3
~~~

- call rax (FF D0) 位于 **0x35**
- SHA-256：`9B6F4A7A138B3C4C5523CEDD047745C96AA83CA01614BEB703E4994DA2E1F017`
- 验证：fixture 数组提取 SHA == obj .text$mn 前 60B 重构 SHA == 上述值（三者一致）

### 3.2 test extension（64B，probe @0x35-0x38，call rax @0x39）

在 production 的 0x35 处插入 4B probe（`49 89 63 48` = mov [r11+0x48], rsp）：

~~~text
... 4C 89 54 24 30 49 89 63 48 FF D0 48 83 C4 38 C3
                    ^probe@0x35  ^call@0x39
~~~

- SHA-256（test 64B）：`01DC2017D8825EFD7E1C3FBE186C2FACF36FB22F2338C493C422E659476E17AE`
- 测试版仅用于本机 ABI harness；**生产 thunk 禁止包含 probe**

## 4. 三项独立检查结果（LOCAL x64，非远程）

源：D:\Temp\thunk7_final_test.c（C_HASH `1196A360...`）+ thunk7_final_full.asm（ASM_HASH `94552912...`）
输出：D:\Temp\thunk7_threecheck_stdout.txt（OUT_HASH `5D84C68F...`）

~~~text
ok   arg pass-through: all 7 intact
ok   callee entry rsp mod 16 = 8
ok   call pre-rsp mod 16 = 0 (probe wrote 000000d758d7f6a0)
ok   reserved +0x40 intact
THUNK7 THREE-CHECK PASS
EXIT=0
~~~

| 检查 | 方法 | 结果 |
|------|------|------|
| 1. arg pass-through | callee asm stub 写 slot[0..6]，比对 7 值 | PASS |
| 2. callee entry alignment | asm stub 入口**首指令**记录 rsp mod 16（无 prologue 干扰） | PASS（=8） |
| 3. call-pre-rsp | probe 写 +0x48；**sentinel 0xDEADBEEFCAFEBABE 被真实覆盖**（probe wrote 真实 rsp 值），mod 16 == 0 | PASS（=0） |
| 附加. reserved 完整性 | +0x40 未被探针触碰（值保持 0xA5A5...） | PASS |

**sentinel 证明**：rsp_probe 预置 0xDEADBEEFCAFEBABE；探针执行后该值变为真实 rsp
（如 0x000000d758d7f6a0）——证明 `49 89 63 48` 确实写入了 +0x48，非零值读取
（非清零假阳性）。

## 5. obj 字节证明

- thunk7_final_full.obj：.text$mn rawptr=140, rawsize=127，OBJ_HASH `9D76E5E0...`
- test 64B = obj 前 64 字节（dumpbin 逐指令确认 probe @0x35、call @0x39）
- production 60B = obj 前 56B + FF D0 + obj[60..63]（add+ret），SHA `9B6F4A7A...`
  == fixture THUNK7_CODE SHA（三者闭环）

## 6. 边界声明

- local x64 ABI PASS 仅证明本机调用约定；远程执行（WPM/CreateRemoteThread/SEH/VEH）
  待 LIVE-4，本工单不构成 Windows/remote PASS。
- 未修改 crates/ 生产代码。

---
（WO-2601 交付，绑定 639eee3）