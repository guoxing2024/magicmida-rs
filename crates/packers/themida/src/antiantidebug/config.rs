//! WO-1004 Phase 4: Oreans 双轨配置与切换逻辑
//!
//! 设计约束（来自 WO-902 Phase 4）：
//! - 环境变量 `MIDA_ANTIDEBUG_MODE` 控制模式：`legacy` (默认) 或 `self`
//! - `legacy` = ScyllaHide 注入（Oreans 原有行为）
//! - `self` = 自研处理器（Phase 1-3 实现的处理器）
//! - 默认行为零变化（legacy），生产翻转需单独授权
//! - 提供回滚开关：运行时可切换回 legacy

use std::sync::atomic::{AtomicU8, Ordering};

/// 反调试模式
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum AntidebugMode {
    /// 传统模式：使用 ScyllaHide 注入（Oreans 原有行为）
    Legacy = 0,
    /// 自研模式：使用 Phase 1-3 实现的处理器
    SelfDeveloped = 1,
}

impl AntidebugMode {
    /// 从环境变量读取配置
    ///
    /// 读取 `MIDA_ANTIDEBUG_MODE` 环境变量：
    /// - "legacy" 或未设置 → Legacy
    /// - "self" → SelfDeveloped
    /// - 其他值 → Legacy (fail-safe)
    pub fn from_env() -> Self {
        match std::env::var("MIDA_ANTIDEBUG_MODE") {
            Ok(val) => match val.to_lowercase().as_str() {
                "self" => AntidebugMode::SelfDeveloped,
                "legacy" | "" => AntidebugMode::Legacy,
                _ => {
                    tracing::warn!(
                        value = val,
                        "Unknown MIDA_ANTIDEBUG_MODE value, defaulting to legacy"
                    );
                    AntidebugMode::Legacy
                }
            },
            Err(_) => AntidebugMode::Legacy, // 未设置，默认 legacy
        }
    }

    /// 转换为 u8（用于原子操作）
    pub fn as_u8(self) -> u8 {
        self as u8
    }

    /// 从 u8 转换回枚举
    pub fn from_u8(val: u8) -> Self {
        match val {
            1 => AntidebugMode::SelfDeveloped,
            _ => AntidebugMode::Legacy,
        }
    }
}

/// 全局反调试模式（支持运行时切换）
static GLOBAL_MODE: AtomicU8 = AtomicU8::new(0); // 默认 Legacy

/// 初始化全局反调试模式（从环境变量读取）
///
/// 应在程序启动时调用一次。如果多次调用，后续调用会被忽略。
pub fn initialize_mode() {
    let mode = AntidebugMode::from_env();
    GLOBAL_MODE.store(mode.as_u8(), Ordering::SeqCst);
    tracing::info!(mode = ?mode, "Antidebug mode initialized");
}

/// 获取当前全局反调试模式
pub fn current_mode() -> AntidebugMode {
    AntidebugMode::from_u8(GLOBAL_MODE.load(Ordering::SeqCst))
}

/// 运行时切换反调试模式（回滚开关）
///
/// ## 安全性
///
/// 此函数允许运行时从 SelfDeveloped 回滚到 Legacy（紧急回滚场景）。
/// 不建议在生产环境中频繁切换，仅用于故障恢复。
pub fn set_mode(mode: AntidebugMode) {
    let old_mode = current_mode();
    GLOBAL_MODE.store(mode.as_u8(), Ordering::SeqCst);
    tracing::warn!(
        old_mode = ?old_mode,
        new_mode = ?mode,
        "Antidebug mode changed at runtime"
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mode_from_env_defaults_to_legacy() {
        // 如果环境变量未设置，应该默认为 Legacy
        std::env::remove_var("MIDA_ANTIDEBUG_MODE");
        let mode = AntidebugMode::from_env();
        assert_eq!(mode, AntidebugMode::Legacy);
    }

    #[test]
    fn mode_from_env_recognizes_self() {
        std::env::set_var("MIDA_ANTIDEBUG_MODE", "self");
        let mode = AntidebugMode::from_env();
        assert_eq!(mode, AntidebugMode::SelfDeveloped);
        std::env::remove_var("MIDA_ANTIDEBUG_MODE");
    }

    #[test]
    fn mode_from_env_recognizes_legacy() {
        std::env::set_var("MIDA_ANTIDEBUG_MODE", "legacy");
        let mode = AntidebugMode::from_env();
        assert_eq!(mode, AntidebugMode::Legacy);
        std::env::remove_var("MIDA_ANTIDEBUG_MODE");
    }

    #[test]
    fn mode_from_env_is_case_insensitive() {
        std::env::set_var("MIDA_ANTIDEBUG_MODE", "SELF");
        let mode = AntidebugMode::from_env();
        assert_eq!(mode, AntidebugMode::SelfDeveloped);
        std::env::remove_var("MIDA_ANTIDEBUG_MODE");
    }

    #[test]
    fn mode_from_env_unknown_defaults_to_legacy() {
        std::env::set_var("MIDA_ANTIDEBUG_MODE", "unknown");
        let mode = AntidebugMode::from_env();
        assert_eq!(mode, AntidebugMode::Legacy);
        std::env::remove_var("MIDA_ANTIDEBUG_MODE");
    }

    #[test]
    fn mode_roundtrip_u8() {
        assert_eq!(
            AntidebugMode::from_u8(AntidebugMode::Legacy.as_u8()),
            AntidebugMode::Legacy
        );
        assert_eq!(
            AntidebugMode::from_u8(AntidebugMode::SelfDeveloped.as_u8()),
            AntidebugMode::SelfDeveloped
        );
    }

    #[test]
    fn global_mode_can_be_changed() {
        initialize_mode(); // 初始化为默认值
        let initial = current_mode();

        set_mode(AntidebugMode::SelfDeveloped);
        assert_eq!(current_mode(), AntidebugMode::SelfDeveloped);

        set_mode(AntidebugMode::Legacy);
        assert_eq!(current_mode(), AntidebugMode::Legacy);

        // 恢复初始状态
        set_mode(initial);
    }
}
