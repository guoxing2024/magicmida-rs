//! lib.rs for host_loader: pure helpers kept out of main so they are
//! unit-testable (XC-4 ② minimal-surface contract).

/// Pure: parse the DLL path from argv / env (first non-empty wins).
pub fn resolve_dll_path(args: &[String], env: Option<String>) -> Option<String> {
    args.first()
        .filter(|s| !s.is_empty())
        .cloned()
        .or(env.filter(|s| !s.is_empty()))
}

#[cfg(test)]
mod tests {
    use super::resolve_dll_path;

    #[test]
    fn argv_wins_over_env() {
        assert_eq!(
            resolve_dll_path(
                &["C:\\vault\\core.dll".to_string()],
                Some("C:\\env\\core.dll".to_string())
            ),
            Some("C:\\vault\\core.dll".to_string())
        );
    }

    #[test]
    fn env_used_when_argv_empty() {
        assert_eq!(
            resolve_dll_path(&[], Some("C:\\env\\core.dll".to_string())),
            Some("C:\\env\\core.dll".to_string())
        );
    }

    #[test]
    fn none_when_both_empty() {
        assert_eq!(resolve_dll_path(&[], None), None);
    }
}
