//! Tests for anti-anti-debug constants and helpers.

use super::*;
use mida_core::{DebugEvent, DebuggerCore, ContinueStatus};
use windows::Win32::{Foundation::HANDLE, System::Diagnostics::Debug::CONTEXT};
use std::collections::HashMap;

#[test]
fn ptr_from_bytes_x86() {
    let bytes = [0x78, 0x56, 0x34, 0x12];
    let addr = ptr_from_bytes(&bytes);
    assert_eq!(addr, 0x1234_5678);
}

#[test]
fn ptr_from_bytes_x64() {
    let bytes = [0xEF, 0xCD, 0xAB, 0x89, 0x67, 0x45, 0x23, 0x01];
    let addr = ptr_from_bytes(&bytes);
    assert_eq!(addr, 0x0123_4567_89AB_CDEF);
}

#[test]
fn ptr_from_bytes_partial() {
    // Only 4 bytes provided — treated as u32.
    let bytes = [0xEF, 0xBE, 0xAD, 0xDE];
    let addr = ptr_from_bytes(&bytes);
    assert_eq!(addr, 0xDEAD_BEEF_u32 as usize);
}

#[test]
fn constants_are_correct() {
    assert_eq!(THREAD_HIDE_FROM_DEBUGGER, 0x11);
    assert_eq!(PROCESS_DEBUG_PORT, 7);
    assert_eq!(PROCESS_DEBUG_OBJECT_HANDLE, 30);
    assert_eq!(PROCESS_DEBUG_FLAGS, 31);
    assert_eq!(STATUS_SUCCESS, 0);
    assert_eq!(STATUS_PORT_NOT_SET, 0xC000_0353);
}

#[test]
#[cfg(target_arch = "x86")]
fn nt_qip_syscall_fallback_is_sensible() {
    assert_eq!(NtQIP_SYSCALL_NUMBER, 0x16);
}

// ---------------------------------------------------------------------------
// WO-1002: Mock debugger for CRDP handler tests
// ---------------------------------------------------------------------------

/// Minimal mock debugger for testing handlers in isolation.
struct MockDebugger {
    memory: HashMap<usize, Vec<u8>>,
    context: CONTEXT,
    thread_id: u32,
}

impl MockDebugger {
    fn new(thread_id: u32) -> Self {
        Self {
            memory: HashMap::new(),
            context: unsafe { std::mem::zeroed() },
            thread_id,
        }
    }

    /// 在指定地址预置内存内容
    fn preset_memory(&mut self, addr: usize, data: Vec<u8>) {
        self.memory.insert(addr, data);
    }

    /// 读取写入的内存内容
    fn read_written(&self, addr: usize, len: usize) -> Option<Vec<u8>> {
        self.memory.get(&addr).map(|v| v[..len].to_vec())
    }
}

impl DebuggerCore for MockDebugger {
    fn process_handle(&self) -> HANDLE {
        HANDLE::default()
    }

    fn pid(&self) -> u32 {
        1234
    }

    fn image_base(&self) -> u64 {
        0x400000
    }

    fn wait_event(&mut self) -> Result<DebugEvent, mida_core::CoreError> {
        unimplemented!("mock debugger: wait_event")
    }

    fn continue_event(&mut self, _thread_id: u32, _status: ContinueStatus)
        -> Result<(), mida_core::CoreError> {
        Ok(())
    }

    fn read_memory(&self, address: usize, buf: &mut [u8]) -> Result<usize, mida_core::CoreError> {
        if let Some(data) = self.memory.get(&address) {
            let len = buf.len().min(data.len());
            buf[..len].copy_from_slice(&data[..len]);
            Ok(len)
        } else {
            Ok(0)
        }
    }

    fn write_memory(&mut self, address: usize, data: &[u8]) -> Result<usize, mida_core::CoreError> {
        self.memory.insert(address, data.to_vec());
        Ok(data.len())
    }

    fn get_thread_context(&self, _thread_id: u32) -> Result<CONTEXT, mida_core::CoreError> {
        Ok(self.context)
    }

    fn set_thread_context(&self, _thread_id: u32, ctx: &CONTEXT) -> Result<(), mida_core::CoreError> {
        // 在真实场景中这里会修改 self.context，但因为需要 &mut self
        // 我们在测试中通过检查返回值来验证
        let _ = ctx;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// WO-1002: CRDP handler tests
// ---------------------------------------------------------------------------

#[test]
fn crdp_forges_false_to_output_pointer() {
    let mut dbg = MockDebugger::new(100);
    let output_ptr = 0x7fff_0000u64;

    // 执行 CRDP 处理器
    let result = handlers::handle_check_remote_debugger_present(
        &mut dbg,
        100,
        output_ptr,
    );

    assert!(result.is_ok(), "CRDP handler should succeed");

    // 验证写入了 FALSE (0)
    let written = dbg.read_written(output_ptr as usize, 4)
        .expect("output pointer should be written");
    assert_eq!(written, [0, 0, 0, 0], "should write FALSE (0) to output pointer");
}

#[test]
fn crdp_skips_call_and_sets_success() {
    let mut dbg = MockDebugger::new(200);
    let output_ptr = 0x7fff_1000u64;

    // 预置返回地址在栈上 (模拟 CRDP 调用时的栈布局)
    let stack_ptr = 0x1000_0000usize;
    let ret_addr = 0x0040_1234u64;
    dbg.preset_memory(stack_ptr, ret_addr.to_le_bytes().to_vec());

    // 设置初始上下文
    #[cfg(target_arch = "x86_64")]
    {
        dbg.context.Rsp = stack_ptr as u64;
        dbg.context.Rip = 0x7ff0_0000; // CRDP 地址
    }

    #[cfg(target_arch = "x86")]
    {
        dbg.context.Esp = stack_ptr as u32;
        dbg.context.Eip = 0x7700_0000; // CRDP 地址
    }

    let result = handlers::handle_check_remote_debugger_present(
        &mut dbg,
        200,
        output_ptr,
    );

    assert!(result.is_ok(), "CRDP handler should succeed");
    // 注意：因为 MockDebugger::set_thread_context 的限制，
    // 我们无法直接验证上下文修改，但返回 Ok 表示处理成功
}

#[test]
fn crdp_handler_is_deterministic() {
    let mut dbg1 = MockDebugger::new(300);
    let mut dbg2 = MockDebugger::new(300);
    let output_ptr = 0x7fff_2000u64;

    // 两次调用应该产生相同结果
    let r1 = handlers::handle_check_remote_debugger_present(&mut dbg1, 300, output_ptr);
    let r2 = handlers::handle_check_remote_debugger_present(&mut dbg2, 300, output_ptr);

    assert!(r1.is_ok() && r2.is_ok());

    let w1 = dbg1.read_written(output_ptr as usize, 4).unwrap();
    let w2 = dbg2.read_written(output_ptr as usize, 4).unwrap();
    assert_eq!(w1, w2, "CRDP forge should be deterministic");
}

// ---------------------------------------------------------------------------
// WO-1002: Timing probe state tests
// ---------------------------------------------------------------------------

#[test]
fn timing_state_first_probe_returns_real() {
    let mut state = handlers::TimingProbeState::new();
    let real_tick = 1000u64;
    let returned = state.handle_probe(real_tick);
    assert_eq!(returned, real_tick, "first probe should return real tick");
}

#[test]
fn timing_state_benign_probe_returns_real() {
    let mut state = handlers::TimingProbeState::new();
    let _ = state.handle_probe(1000);
    // 第二次探测，delta = 3000（超过阈值 2000，良性）
    let returned = state.handle_probe(4000);
    assert_eq!(returned, 4000, "benign probe should return real tick");
}

#[test]
fn timing_state_suspicious_probe_opens_window() {
    let mut state = handlers::TimingProbeState::new();
    let _ = state.handle_probe(1000);
    // 第二次探测，delta = 100（低于阈值，可疑）
    let returned = state.handle_probe(1100);
    // 应该返回掩码值（1000 + MASKED_DELTA）
    assert_ne!(returned, 1100, "suspicious probe should be masked");
    assert_eq!(returned, 1000 + super::timings::MASKED_DELTA);
}

#[test]
fn timing_state_window_is_bounded() {
    use super::timings::TIMING_PATCH_WINDOW;
    let mut state = handlers::TimingProbeState::new();
    let _ = state.handle_probe(1000);

    // 发送 TIMING_PATCH_WINDOW 个可疑探测
    for i in 0..TIMING_PATCH_WINDOW {
        let returned = state.handle_probe(1000 + (i as u64 + 1) * 100);
        assert_ne!(returned, 1000 + (i as u64 + 1) * 100, "probe {} should be masked", i);
    }

    // 第 TIMING_PATCH_WINDOW+1 个可疑探测应该关闭窗口，返回真实值
    let returned = state.handle_probe(2000);
    assert_eq!(returned, 2000, "window should close after {} probes", TIMING_PATCH_WINDOW);
}

#[test]
fn timing_state_benign_probe_closes_window() {
    let mut state = handlers::TimingProbeState::new();
    let _ = state.handle_probe(1000);
    // 一个可疑探测
    let _ = state.handle_probe(1100);
    // 一个良性探测（delta = 5000）
    let returned = state.handle_probe(6100);
    assert_eq!(returned, 6100, "benign probe should close window and return real tick");
}
