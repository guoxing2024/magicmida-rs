//! Reinitialize stale CRT heap state before transferring control to the OEP.

use std::collections::{HashMap, HashSet};

use tracing::{info, warn};

use crate::header::PeHeader;
use crate::import_table::ImportTableBuilder;

use super::container_snapshot::ContainerSnapshot;

const IMAGE_SCN_CNT_CODE: u32 = 0x0000_0020;
const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;
const IMAGE_SCN_MEM_READ: u32 = 0x4000_0000;
const IMAGE_SCN_MEM_WRITE: u32 = 0x8000_0000;
const STUB_SIZE: usize = 26;
const MAX_LOAD_TO_CALL_DISTANCE: usize = 48;

const HEAP_APIS: [&str; 3] = ["HeapAlloc", "HeapReAlloc", "HeapFree"];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct HeapBootstrap {
    heap_global_rva: u32,
    get_process_heap_iat_rva: u32,
}

/// Add a small x64 entry-point bootstrap when the dumped image contains a
/// process-local heap handle consumed by multiple Win32 heap APIs.
///
/// If containers are provided, installs a full container restoration stub instead.
///
/// Returns the bootstrap RVA when one was installed, otherwise `None`.
pub(crate) fn install_heap_bootstrap(
    pe: &mut PeHeader,
    dump_buf: &[u8],
    imports: &ImportTableBuilder,
    original_entry_point: u32,
    containers: &[ContainerSnapshot],
    debugger: Option<&mut dyn mida_core::DebuggerCore>,
) -> Option<u32> {
    if !pe.is_64bit {
        return None;
    }

    // If we have containers, use TLS callback approach (correct timing)
    if !containers.is_empty() {
        let get_process_heap_iat_rva = find_import_rva(imports, "GetProcessHeap")?;
        let heap_alloc_iat_rva = find_import_rva(imports, "HeapAlloc")?;

        info!(
            "TLS bootstrap IAT addresses: GetProcessHeap={:#x}, HeapAlloc={:#x}",
            get_process_heap_iat_rva, heap_alloc_iat_rva
        );

        // Detect critical global variables from OEP
        let critical_rvas = super::global_vars::detect_critical_vars_from_oep(
            pe,
            dump_buf,
            original_entry_point,
            50,
        );

        info!("Detected {} critical variables from OEP", critical_rvas.len());

        // Capture runtime values if debugger available
        let global_vars = if let Some(dbg) = debugger {
            super::global_vars::detect_global_vars(pe, dbg, &critical_rvas, 8)
        } else {
            warn!("No debugger provided - cannot capture runtime values for global vars");
            vec![]
        };

        return super::tls_bootstrap::install_tls_callback_bootstrap(
            pe,
            containers,
            &global_vars,
            get_process_heap_iat_rva,
            heap_alloc_iat_rva,
            original_entry_point,
        );
    }

    // For non-container cases, try to detect heap bootstrap
    let bootstrap = detect_heap_bootstrap(pe, dump_buf, imports)?;

    // Otherwise use the simple heap bootstrap
    let section_idx = pe.create_section_index(".boot", 0x200);
    let stub_rva = pe.sections[section_idx].virtual_address;
    let stub = match build_stub(stub_rva, original_entry_point, bootstrap) {
        Some(stub) => stub,
        None => {
            pe.sections.remove(section_idx);
            pe.nt_headers.optional_header.size_of_image = pe
                .sections
                .last()
                .map(|section| {
                    crate::utils::align_up(
                        section.virtual_address.saturating_add(section.virtual_size),
                        pe.nt_headers.optional_header.section_alignment,
                    )
                })
                .unwrap_or(pe.nt_headers.optional_header.size_of_headers);
            warn!("Heap bootstrap targets are outside the x64 relative-address range");
            return None;
        }
    };

    let section = &mut pe.sections[section_idx];
    section.characteristics = IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ;
    section.header.characteristics = section.characteristics;
    section.header.virtual_size = 0x200;
    section.virtual_size = 0x200;
    section.header.size_of_raw_data = 0x200;
    section.raw_size = 0x200;
    section.extra_data = Some(stub);

    info!(
        stub_rva = format_args!("{stub_rva:#x}"),
        heap_global_rva = format_args!("{:#x}", bootstrap.heap_global_rva),
        get_process_heap_iat_rva = format_args!("{:#x}", bootstrap.get_process_heap_iat_rva),
        original_entry_point = format_args!("{original_entry_point:#x}"),
        "Installed pre-OEP process heap bootstrap"
    );

    Some(stub_rva)
}

fn detect_heap_bootstrap(
    pe: &PeHeader,
    dump_buf: &[u8],
    imports: &ImportTableBuilder,
) -> Option<HeapBootstrap> {
    let get_process_heap_iat_rva = find_import_rva(imports, "GetProcessHeap")?;
    let heap_api_slots: HashMap<u32, &str> = imports
        .modules
        .iter()
        .flat_map(|module| module.thunks.iter())
        .filter_map(|thunk| {
            let name = thunk.function_name.as_deref()?;
            HEAP_APIS
                .contains(&name)
                .then_some((thunk.iat_address, name))
        })
        .collect();
    if heap_api_slots.is_empty() {
        return None;
    }

    let mut evidence: HashMap<u32, HashSet<&str>> = HashMap::new();
    for section in pe
        .sections
        .iter()
        .filter(|section| section.characteristics & IMAGE_SCN_MEM_EXECUTE != 0)
    {
        let start = section.virtual_address as usize;
        let end = start
            .saturating_add(section.virtual_size as usize)
            .min(dump_buf.len());
        let Some(code) = dump_buf.get(start..end) else {
            continue;
        };

        for call_offset in 0..=code.len().saturating_sub(6) {
            if code[call_offset] != 0xff || code[call_offset + 1] != 0x15 {
                continue;
            }
            let call_rva = section.virtual_address.saturating_add(call_offset as u32);
            let call_target =
                rip_relative_target(call_rva, 6, &code[call_offset + 2..call_offset + 6]);
            let Some(api_name) = call_target.and_then(|rva| heap_api_slots.get(&rva).copied())
            else {
                continue;
            };

            let search_start = call_offset.saturating_sub(MAX_LOAD_TO_CALL_DISTANCE);
            let load = (search_start..call_offset).rev().find(|&offset| {
                offset + 7 <= call_offset
                    && code[offset..offset + 3] == [0x48, 0x8b, 0x0d]
                    && !code[offset + 7..call_offset]
                        .windows(2)
                        .any(|bytes| bytes == [0xff, 0x15])
            });
            let Some(load_offset) = load else {
                continue;
            };
            let load_rva = section.virtual_address.saturating_add(load_offset as u32);
            let Some(global_rva) =
                rip_relative_target(load_rva, 7, &code[load_offset + 3..load_offset + 7])
            else {
                continue;
            };
            if is_stale_writable_global(pe, dump_buf, global_rva) {
                evidence.entry(global_rva).or_default().insert(api_name);
            }
        }
    }

    let (heap_global_rva, api_evidence) = evidence
        .into_iter()
        .max_by_key(|(_, api_evidence)| api_evidence.len())?;
    // One isolated call is too weak: require the same global to feed at least
    // two distinct heap operations before changing the executable entry point.
    if api_evidence.len() < 2 {
        return None;
    }

    Some(HeapBootstrap {
        heap_global_rva,
        get_process_heap_iat_rva,
    })
}

fn find_import_rva(imports: &ImportTableBuilder, wanted: &str) -> Option<u32> {
    imports
        .modules
        .iter()
        .flat_map(|module| module.thunks.iter())
        .find(|thunk| thunk.function_name.as_deref() == Some(wanted))
        .map(|thunk| thunk.iat_address)
}

fn rip_relative_target(
    instruction_rva: u32,
    instruction_len: u32,
    displacement: &[u8],
) -> Option<u32> {
    let bytes: [u8; 4] = displacement.try_into().ok()?;
    let next = i64::from(instruction_rva) + i64::from(instruction_len);
    u32::try_from(next + i64::from(i32::from_le_bytes(bytes))).ok()
}

fn is_stale_writable_global(pe: &PeHeader, dump_buf: &[u8], rva: u32) -> bool {
    let in_writable_section = pe.sections.iter().any(|section| {
        let end = section
            .virtual_address
            .saturating_add(section.virtual_size.max(section.raw_size));
        section.characteristics & IMAGE_SCN_MEM_WRITE != 0
            && rva >= section.virtual_address
            && rva.saturating_add(8) <= end
    });
    if !in_writable_section {
        return false;
    }

    let offset = rva as usize;
    let Some(bytes) = dump_buf.get(offset..offset.saturating_add(8)) else {
        return false;
    };
    let Ok(value_bytes) = <[u8; 8]>::try_from(bytes) else {
        return false;
    };
    let value = u64::from_le_bytes(value_bytes);
    let image_start = pe.nt_headers.optional_header.image_base;
    let image_end = image_start.saturating_add(pe.size_of_image() as u64);
    let plausible_user_handle = (0x1_0000..=0x0000_7fff_ffff_ffff).contains(&value);
    value != 0 && plausible_user_handle && !(image_start..image_end).contains(&value)
}

fn build_stub(
    stub_rva: u32,
    original_entry_point: u32,
    bootstrap: HeapBootstrap,
) -> Option<Vec<u8>> {
    let mut stub = Vec::with_capacity(0x200);
    stub.extend_from_slice(&[0x48, 0x83, 0xec, 0x28]); // sub rsp, 28h

    stub.extend_from_slice(&[0xff, 0x15]); // call qword ptr [rip+disp32]
    let call_next = stub_rva.checked_add(stub.len() as u32)?.checked_add(4)?;
    stub.extend_from_slice(&relative_displacement(
        call_next,
        bootstrap.get_process_heap_iat_rva,
    )?);

    stub.extend_from_slice(&[0x48, 0x89, 0x05]); // mov qword ptr [rip+disp32], rax
    let store_next = stub_rva.checked_add(stub.len() as u32)?.checked_add(4)?;
    stub.extend_from_slice(&relative_displacement(
        store_next,
        bootstrap.heap_global_rva,
    )?);

    stub.extend_from_slice(&[0x48, 0x83, 0xc4, 0x28]); // add rsp, 28h
    stub.push(0xe9); // jmp rel32
    let jump_next = stub_rva.checked_add(stub.len() as u32)?.checked_add(4)?;
    stub.extend_from_slice(&relative_displacement(jump_next, original_entry_point)?);
    debug_assert_eq!(stub.len(), STUB_SIZE);
    stub.resize(0x200, 0xcc);
    Some(stub)
}

fn relative_displacement(next_rva: u32, target_rva: u32) -> Option<[u8; 4]> {
    let displacement = i64::from(target_rva) - i64::from(next_rva);
    i32::try_from(displacement).ok().map(i32::to_le_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stub_targets_import_global_and_oep() {
        let bootstrap = HeapBootstrap {
            heap_global_rva: 0x145d50,
            get_process_heap_iat_rva: 0xfd480,
        };
        let stub = build_stub(0x200000, 0x1000, bootstrap).unwrap();

        assert_eq!(stub.len(), 0x200);
        assert_eq!(&stub[..4], &[0x48, 0x83, 0xec, 0x28]);
        assert_eq!(
            rip_relative_target(0x200004, 6, &stub[6..10]),
            Some(bootstrap.get_process_heap_iat_rva)
        );
        assert_eq!(
            rip_relative_target(0x20000a, 7, &stub[13..17]),
            Some(bootstrap.heap_global_rva)
        );
        assert_eq!(
            rip_relative_target(0x200015, 5, &stub[22..26]),
            Some(0x1000)
        );
    }

    #[test]
    fn rip_relative_target_sign_extends_negative_displacement() {
        assert_eq!(
            rip_relative_target(0x2000, 6, &(-0x1006i32).to_le_bytes()),
            Some(0x1000)
        );
    }
}
