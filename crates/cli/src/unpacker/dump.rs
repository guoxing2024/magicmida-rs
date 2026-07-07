//! Dump the `.text` section from a running process.

use std::path::Path;
use anyhow::anyhow;
use tracing::{debug, warn};
use windows::Win32::System::Threading::{
    OpenProcess, QueryFullProcessImageNameW, PROCESS_NAME_FORMAT,
    PROCESS_QUERY_INFORMATION, PROCESS_VM_READ,
};
use mida_pe::PeHeader;
use crate::log::{self, LogType};
use super::session::ReadOnlyProcessDebugger;

/// Dump the de-virtualised `.text` section from a running (unpacked) process.
pub fn dump_process_code(pid: u32, unpacked_file: &Path) -> Result<(), anyhow::Error> {
    // SAFETY: pid is a valid OS process ID; handles are closed before return.
    let h_process = unsafe {
        OpenProcess(
            PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
            false,
            pid,
        )
    }
    .map_err(|e| anyhow!("Cannot open process {}: {e}", pid))?;

    let mut path_buf: Vec<u16> = vec![0u16; 260];
    let mut len = path_buf.len() as u32;
    // SAFETY: h_process is valid; path_buf is valid and sized.
    let success = unsafe {
        QueryFullProcessImageNameW(
            h_process,
            PROCESS_NAME_FORMAT(0),
            windows::core::PWSTR(path_buf.as_mut_ptr()),
            &mut len,
        )
    };

    let image_path: std::path::PathBuf = if success.is_ok() && len > 0 {
        let wide_str = &path_buf[..len as usize];
        String::from_utf16_lossy(wide_str).into()
    } else {
        warn!("Could not query process image name for PID {pid}");
        return Err(anyhow!(
            "Cannot determine process image path for PID {pid} — \
             the process may have exited or access is denied."
        ));
    };

    let pe = PeHeader::from_file(&image_path)
        .map_err(|e| anyhow!("Failed to parse PE of running process: {e}"))?;

    let is_64bit = pe.is_64bit;
    debug!(?image_path, is_64bit, "Resolved process image");

    let ro_dbg = ReadOnlyProcessDebugger {
        h_process,
        image_base: pe.image_base,
    };

    let written = mida_packers_themida::dump_process_code(&ro_dbg, &pe, unpacked_file)
        .map_err(|e| anyhow!("dump_process_code failed: {e}"))?;

    log::log(
        LogType::Good,
        &format!("Dumped {} bytes to {}", written, unpacked_file.display()),
    );

    // SAFETY: the handle was opened by this function and is no longer needed.
    unsafe {
        let _ = windows::Win32::Foundation::CloseHandle(h_process);
    }

    Ok(())
}
