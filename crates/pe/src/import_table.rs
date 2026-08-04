//! Import table data structures for PE reconstruction.
//!
//! Corresponds to the `TImportThunk`, `TOriginalImport` types and
//! related helpers in `Dumper.pas`.

use tracing::debug;

/// A single import thunk (entry in the Import Address Table).
///
/// Each thunk links a slot in the IAT to a specific function (by name or
/// ordinal) exported by a module.
#[derive(Debug, Clone)]
pub struct ImportThunk {
    /// RVA of this entry within the IAT.
    pub iat_address: u32,

    /// Name of the imported function (`None` for ordinal-only imports).
    pub function_name: Option<String>,

    /// Ordinal number if the import is by ordinal (`None` for name imports).
    pub ordinal: Option<u16>,

    /// Whether this is a 64-bit PE (affects pointer size in the IAT).
    pub is_64bit: bool,
}

/// A module contributing imports to the reconstructed executable.
///
/// One `ImportModule` is produced for every DLL the target links against.
#[derive(Debug, Clone)]
pub struct ImportModule {
    /// DLL name (lowercase, e.g. `"kernel32.dll"`).
    pub name: String,

    /// Ordered list of thunks belonging to this module.
    pub thunks: Vec<ImportThunk>,
}

/// Builder that accumulates resolved import modules and can serialise
/// the import directory, hint/name table, and IAT into a byte buffer
/// suitable for writing into a new `.import` PE section.
///
/// Corresponds to the import-reconstruction logic in
/// `TDumper.Process` (second half, after pass 2).
#[derive(Debug, Clone)]
pub struct ImportTableBuilder {
    /// Modules in import order (matching the zero-delimited groups in the
    /// original IAT).
    pub modules: Vec<ImportModule>,

    /// Whether the target PE is 64-bit (`true`) or 32-bit (`false`).
    pub is_64bit: bool,
}

// ---------------------------------------------------------------------------
// PE import directory constants
// ---------------------------------------------------------------------------

/// Marker for ordinal imports — bit 31 (or 63 on x64) distinguishes
/// ordinal from name/RVA entries.
pub const IMAGE_ORDINAL_FLAG32: u32 = 0x8000_0000;

/// 64-bit ordinal flag (top bit of a u64).
pub const IMAGE_ORDINAL_FLAG64: u64 = 0x8000_0000_0000_0000;

/// Size of `IMAGE_IMPORT_DESCRIPTOR` in bytes (20 bytes).
pub const IMPORT_DESCRIPTOR_SIZE: usize = 20;

/// Size of one IAT/INT slot (pointer-sized — 4 or 8 bytes).
pub fn iat_slot_size(is_64bit: bool) -> usize {
    if is_64bit {
        8
    } else {
        4
    }
}

// ---------------------------------------------------------------------------
// ImportTableBuilder
// ---------------------------------------------------------------------------

impl ImportTableBuilder {
    /// Create an empty builder.
    pub fn new(is_64bit: bool) -> Self {
        Self {
            modules: Vec::new(),
            is_64bit,
        }
    }

    /// Add a module with the given name (empty thunk list).
    pub fn add_module(&mut self, name: &str) -> &mut ImportModule {
        self.modules.push(ImportModule {
            name: name.to_lowercase(),
            thunks: Vec::new(),
        });
        // SAFETY: We just pushed an element, so the new last index is valid
        let idx = self.modules.len() - 1;
        &mut self.modules[idx]
    }

    /// Find the IAT slot RVA for a function already in the table (read-only).
    /// Used after `build_import_section_no_iat` assigned IAT addresses.
    pub fn find_function_iat(&self, func: &str) -> Option<u32> {
        self.modules
            .iter()
            .flat_map(|m| m.thunks.iter())
            .find(|t| t.function_name.as_deref() == Some(func))
            .map(|t| t.iat_address)
    }

    /// Ensure a function exists in the import table under the given DLL.
    /// Returns the IAT slot RVA for the function (creating module + thunk
    /// if absent). Used by the heap-bootstrap stub to guarantee helper
    /// imports (e.g. `VirtualAlloc`) are available even when the original
    /// sample did not import them.
    pub fn ensure_function(&mut self, dll: &str, func: &str) -> Option<u32> {
        let dll_lower = dll.to_lowercase();
        let idx = self.modules.iter().position(|m| m.name == dll_lower);
        let mi = match idx {
            Some(i) => i,
            None => {
                self.add_module(dll);
                self.modules.len() - 1
            }
        };
        let exists = self.modules[mi]
            .thunks
            .iter()
            .any(|t| t.function_name.as_deref() == Some(func));
        if exists {
            self.modules[mi]
                .thunks
                .iter()
                .find(|t| t.function_name.as_deref() == Some(func))
                .map(|t| t.iat_address)
        } else {
            // Compute IAT address: after all existing thunks across modules.
            // The import section builder assigns IAT addresses in build order;
            // we use a placeholder that gets resolved during section build.
            // Actually the builder uses existing iat_address on thunks. We need
            // to assign one. Use the max existing + 8.
            let max_iat = self
                .modules
                .iter()
                .flat_map(|m| m.thunks.iter())
                .map(|t| t.iat_address)
                .max()
                .unwrap_or(0);
            let iat = if max_iat > 0 { max_iat + 8 } else { 0 };
            self.modules[mi]
                .thunks
                .push(crate::import_table::ImportThunk {
                    iat_address: iat,
                    function_name: Some(func.to_string()),
                    ordinal: None,
                    is_64bit: self.is_64bit,
                });
            // Return 0 if we couldn't compute a real IAT (builder will reassign)
            if iat > 0 {
                Some(iat)
            } else {
                None
            }
        }
    }

    /// Produce the on-disk `.import` section WITHOUT the embedded IAT, plus
    /// an ordered list of thunk slot values (hint/name RVAs) to write into
    /// the original IAT the protector filled at runtime.
    ///
    /// Returns `(section_data, thunks)` where:
    /// - `section_data` is the `.import` section content (descriptors followed
    ///   by hint/name strings). `OriginalFirstThunk` is zero because this
    ///   layout intentionally uses the original IAT as the lookup table.
    /// - `thunks` is a flat vector of slot values (one u64 per name-hinted
    ///   import, plus a null terminator per module) to be written at
    ///   `original_iat_rva` so the PE loader resolves them at load time.
    pub fn build_import_section_no_iat(
        &self,
        section_va: u32,
        original_iat_rva: u32,
    ) -> (Vec<u8>, Vec<u64>) {
        let ptr_size = iat_slot_size(self.is_64bit);

        // A PE import descriptor cannot contain a zero gap inside its thunk run:
        // the loader treats the first zero as the terminator. Split each DLL's
        // thunks into physically contiguous runs and emit one descriptor per run.
        let mut runs: Vec<(&ImportModule, Vec<&ImportThunk>)> = Vec::new();
        for module in &self.modules {
            // Check if thunks have valid addresses
            let has_addresses = module.thunks.iter().any(|t| t.iat_address != 0);

            if !has_addresses {
                // No addresses - treat entire module as one run
                if !module.thunks.is_empty() {
                    runs.push((module, module.thunks.iter().collect()));
                }
            } else {
                // Has addresses - split into contiguous runs
                let mut current: Vec<&ImportThunk> = Vec::new();
                for thunk in &module.thunks {
                    let contiguous = current.last().is_none_or(|previous| {
                        previous.iat_address.saturating_add(ptr_size as u32) == thunk.iat_address
                    });
                    if !contiguous {
                        runs.push((module, std::mem::take(&mut current)));
                    }
                    current.push(thunk);
                }
                if !current.is_empty() {
                    runs.push((module, current));
                }
            }
        }

        // ---- Pass 1: compute sizes using INTERLEAVED layout ----
        // Layout: [descriptors][DLL0 name][DLL0 hints][DLL1 name][DLL1 hints]...
        // This matches Pascal Magicmida's layout.
        let desc_count = runs.len() + 1; // + null terminator
        let desc_size = desc_count * IMPORT_DESCRIPTOR_SIZE;

        // Calculate each contiguous run's DLL-name and hint/name storage.
        let mut run_sizes: Vec<usize> = Vec::new();
        for (module, thunks) in &runs {
            let dll_name_size = module.name.len() + 1;
            let hint_names_size: usize = thunks
                .iter()
                .map(|thunk| {
                    thunk
                        .function_name
                        .as_ref()
                        .map(|name| 2 + name.len() + 1)
                        .unwrap_or(0)
                })
                .sum();
            run_sizes.push(dll_name_size + hint_names_size);
        }

        let total_data_size: usize = run_sizes.iter().sum();
        let total_size = desc_size + total_data_size;
        let mut data = vec![0u8; total_size];

        // Start writing data after descriptors
        let mut data_cursor = desc_size;

        let mut desc_offset: usize = 0;

        // Calculate IAT slot count
        // If thunks have iat_address set, use max address; otherwise use total thunk count
        let max_iat_rva = self
            .modules
            .iter()
            .flat_map(|module| module.thunks.iter())
            .map(|thunk| thunk.iat_address)
            .max()
            .unwrap_or(original_iat_rva);

        let slot_count = if max_iat_rva > original_iat_rva {
            // Thunks have addresses - use address range
            max_iat_rva
                .saturating_sub(original_iat_rva)
                .checked_div(ptr_size as u32)
                .unwrap_or(0) as usize
                + 2
        } else {
            // Thunks have no addresses (all 0) - use sequential count
            let total_thunks: usize = self.modules.iter().map(|m| m.thunks.len()).sum();
            total_thunks + self.modules.len() + 2 // +1 null per module, +2 padding
        };

        let mut out_thunks = vec![0u64; slot_count];

        debug!(
            "desc_size={:#x}, total_data_size={:#x}, total_size={:#x}",
            desc_size, total_data_size, total_size
        );
        debug!("section_va={:#x}", section_va);

        // ---- Pass 2: Write data using INTERLEAVED layout ----
        let mut current_iat_rva = original_iat_rva;
        let ptr_size = iat_slot_size(self.is_64bit) as u32;

        for (run_index, (module, thunks)) in runs.iter().enumerate() {
            debug!(
                "Run {}: {} ({} thunks) at offset {:#x}",
                run_index,
                module.name,
                thunks.len(),
                data_cursor
            );

            // Write DLL name
            let dll_name_offset_in_section = data_cursor;
            let name_bytes = module.name.as_bytes();
            data[data_cursor..data_cursor + name_bytes.len()].copy_from_slice(name_bytes);
            data_cursor += name_bytes.len() + 1; // +1 for null terminator

            let dll_name_rva = section_va + dll_name_offset_in_section as u32;

            // Use thunk's iat_address if non-zero, otherwise allocate sequentially
            let module_ft_rva = if let Some(first_thunk) = thunks.first() {
                if first_thunk.iat_address != 0 {
                    first_thunk.iat_address
                } else {
                    current_iat_rva
                }
            } else {
                current_iat_rva
            };

            // No separate ILT is emitted by this layout. OFT=0 tells the
            // Windows loader to use FirstThunk as the lookup table. Pointing
            // OFT at the live IAT is unsafe when that range contains any
            // process-local value: the loader interprets it as an RVA.
            data[desc_offset..desc_offset + 4].copy_from_slice(&0u32.to_le_bytes());
            data[desc_offset + 4..desc_offset + 8].copy_from_slice(&0u32.to_le_bytes());
            data[desc_offset + 8..desc_offset + 12].copy_from_slice(&0u32.to_le_bytes());
            data[desc_offset + 12..desc_offset + 16].copy_from_slice(&dll_name_rva.to_le_bytes());
            data[desc_offset + 16..desc_offset + 20].copy_from_slice(&module_ft_rva.to_le_bytes());
            desc_offset += IMPORT_DESCRIPTOR_SIZE;

            // Write hint/name entries and collect IAT slot values
            let mut thunk_iat_rva = module_ft_rva;
            for thunk in thunks {
                let name = &thunk.function_name;
                let ord = thunk.ordinal;
                let hint_offset_in_section = data_cursor;
                let slot_val: u64 = if let Some(ref name_str) = name {
                    let hnrva = section_va + hint_offset_in_section as u32;
                    data[data_cursor..data_cursor + 2].copy_from_slice(&0u16.to_le_bytes());
                    data_cursor += 2;
                    let nb = name_str.as_bytes();
                    data[data_cursor..data_cursor + nb.len()].copy_from_slice(nb);
                    data_cursor += nb.len() + 1; // +1 for null terminator

                    // NO alignment needed (Pascal doesn't align hint/name entries)

                    hnrva as u64
                } else if let Some(ord_val) = ord {
                    if self.is_64bit {
                        IMAGE_ORDINAL_FLAG64 | (ord_val as u64)
                    } else {
                        (IMAGE_ORDINAL_FLAG32 | (ord_val as u32)) as u64
                    }
                } else {
                    0
                };

                // Use sequential IAT address instead of thunk.iat_address
                let slot_index = thunk_iat_rva
                    .saturating_sub(original_iat_rva)
                    .checked_div(ptr_size)
                    .unwrap_or(0) as usize;

                if let Some(slot) = out_thunks.get_mut(slot_index) {
                    *slot = slot_val;
                }

                thunk_iat_rva += ptr_size;
            }

            // Advance IAT address for next module (thunks + null terminator)
            current_iat_rva += ((thunks.len() + 1) * ptr_size as usize) as u32;

            // The next physical slot is already zero and terminates this module.
        }

        (data, out_thunks)
    }

    /// Serialise the import directory, hint/name table, and the resolved IAT
    /// into a single byte vector.
    ///
    /// # Layout
    ///
    /// ```text
    /// +--------------------------+  ← offset 0
    /// | Import descriptors       |
    /// |  (one per module + null) |
    /// +--------------------------+
    /// | Hint/Name table          |
    /// |  (one entry per thunk)   |
    /// +--------------------------+
    /// | Import Address Table     |
    /// |  (pointer-sized entries) |
    /// +--------------------------+
    /// ```
    ///
    /// # Returns
    ///
    /// `(data, strings_rva_base, iat_rva_base)` where:
    /// - `data` is the complete section content.
    /// - `strings_rva_base` is the RVA offset within `data` where the
    ///   hint/name table starts (for `ImportDescriptor.Name`).
    /// - `iat_rva_base` is the RVA offset within `data` where the IAT
    ///   starts (for `ImportDescriptor.FirstThunk`).
    pub fn build_section_data(&self, section_va: u32) -> (Vec<u8>, u32, u32) {
        let ptr_size = iat_slot_size(self.is_64bit);

        // ---- Pass 1: compute sizes ----

        // Descriptors: one per module + null terminator
        let desc_count = self.modules.len() + 1;
        let desc_size = desc_count * IMPORT_DESCRIPTOR_SIZE;

        // Hint/Name entries: collect all non-ordinal thunks
        let mut name_entries: Vec<(&str, u16)> = Vec::new();
        for m in &self.modules {
            for t in &m.thunks {
                if let Some(ref name) = t.function_name {
                    // Hint is always 0 for us (we don't know the real hint)
                    name_entries.push((name, 0u16));
                }
            }
        }

        // Each hint/name entry: 2 bytes hint + null-terminated name
        let mut strings_size: usize = 0;
        for &(name, _) in &name_entries {
            strings_size += 2 + name.len() + 1; // hint + name + null
        }

        // DLL name strings (one per module, null-terminated)
        let mut dll_strings_size: usize = 0;
        for m in &self.modules {
            dll_strings_size += m.name.len() + 1;
        }

        // IAT: one slot per thunk, plus null terminator per module
        // Each module's IAT is null-terminated; the descriptors reference
        // sub-ranges of the IAT. We lay out the IAT as one contiguous block.
        let mut iat_size: usize = 0;
        for m in &self.modules {
            iat_size += (m.thunks.len() + 1) * ptr_size; // entries + null
        }

        // ILT (Import Lookup Table): same size as IAT, contains Hint/Name RVAs
        // The loader reads from ILT (OriginalFirstThunk) and writes to IAT (FirstThunk)
        let ilt_size = iat_size;

        let total_strings = dll_strings_size + strings_size;
        let total_size = desc_size + total_strings + iat_size + ilt_size;

        let mut data = vec![0u8; total_size];

        let strings_base = desc_size as u32;
        let iat_base = (desc_size + total_strings) as u32;
        let ilt_base = (desc_size + total_strings + iat_size) as u32;

        // ---- Pass 2: write descriptors ----

        let mut dll_str_cursor = strings_base as usize;
        let mut hint_name_cursor = strings_base as usize + dll_strings_size;
        let mut iat_cursor = iat_base as usize;
        let mut ilt_cursor = ilt_base as usize;

        let mut desc_offset: usize = 0;
        for m in &self.modules {
            let _thunk_count = m.thunks.len();

            // Write DLL name string
            let name_bytes = m.name.as_bytes();
            data[dll_str_cursor..dll_str_cursor + name_bytes.len()].copy_from_slice(name_bytes);
            // Convert section offset to RVA by adding section_va
            let dll_name_rva =
                section_va + strings_base + (dll_str_cursor - strings_base as usize) as u32;
            dll_str_cursor += name_bytes.len() + 1; // + null

            // Write descriptor
            // OriginalFirstThunk: we set to 0 (not used by the loader after
            // the PE is loaded — the IAT is authoritative).
            let original_first_thunk_rva =
                section_va + ilt_base + (ilt_cursor - ilt_base as usize) as u32;
            let first_thunk_rva = section_va + iat_base + (iat_cursor - iat_base as usize) as u32;

            // Descriptor fields (20 bytes):
            //   +0  OriginalFirstThunk (u32) — RVA of ILT for this module
            //   +4  TimeDateStamp      (u32) — set to 0
            //   +8  ForwarderChain     (u32) — set to 0
            //   +12 Name               (u32) — RVA of DLL name
            //   +16 FirstThunk         (u32) — RVA of IAT for this module
            data[desc_offset..desc_offset + 4]
                .copy_from_slice(&original_first_thunk_rva.to_le_bytes());
            data[desc_offset + 4..desc_offset + 8].copy_from_slice(&0u32.to_le_bytes());
            data[desc_offset + 8..desc_offset + 12].copy_from_slice(&0u32.to_le_bytes());
            data[desc_offset + 12..desc_offset + 16].copy_from_slice(&dll_name_rva.to_le_bytes());
            data[desc_offset + 16..desc_offset + 20]
                .copy_from_slice(&first_thunk_rva.to_le_bytes());

            desc_offset += IMPORT_DESCRIPTOR_SIZE;

            // Write IAT and ILT entries (both contain the same values initially)
            for t in &m.thunks {
                let slot_val: u64 = if let Some(ref name) = t.function_name {
                    // Point to hint/name entry
                    let hnrva = section_va
                        + strings_base
                        + (hint_name_cursor - strings_base as usize) as u32;

                    // Write hint (2 bytes, zero) then name
                    data[hint_name_cursor..hint_name_cursor + 2]
                        .copy_from_slice(&0u16.to_le_bytes());
                    hint_name_cursor += 2;
                    let nb = name.as_bytes();
                    data[hint_name_cursor..hint_name_cursor + nb.len()].copy_from_slice(nb);
                    hint_name_cursor += nb.len() + 1;

                    hnrva as u64
                } else if let Some(ord) = t.ordinal {
                    if self.is_64bit {
                        IMAGE_ORDINAL_FLAG64 | (ord as u64)
                    } else {
                        (IMAGE_ORDINAL_FLAG32 | (ord as u32)) as u64
                    }
                } else {
                    0
                };

                // Write to both IAT and ILT
                if self.is_64bit {
                    data[iat_cursor..iat_cursor + 8].copy_from_slice(&slot_val.to_le_bytes());
                    iat_cursor += 8;
                    data[ilt_cursor..ilt_cursor + 8].copy_from_slice(&slot_val.to_le_bytes());
                    ilt_cursor += 8;
                } else {
                    data[iat_cursor..iat_cursor + 4]
                        .copy_from_slice(&(slot_val as u32).to_le_bytes());
                    iat_cursor += 4;
                    data[ilt_cursor..ilt_cursor + 4]
                        .copy_from_slice(&(slot_val as u32).to_le_bytes());
                    ilt_cursor += 4;
                }
            }

            // Null terminators for this module's IAT and ILT
            for _ in 0..ptr_size {
                data[iat_cursor] = 0;
                iat_cursor += 1;
                data[ilt_cursor] = 0;
                ilt_cursor += 1;
            }
        }

        // Null terminator descriptor (already zero-initialised at desc_offset)

        (data, strings_base, iat_base)
    }

    /// Number of non-null import descriptors emitted by
    /// [`Self::build_import_section_no_iat`]. A DLL contributes more than one
    /// descriptor when its physical IAT slots contain gaps.
    pub fn emitted_descriptor_count(&self) -> usize {
        let ptr_size = iat_slot_size(self.is_64bit) as u32;
        self.modules
            .iter()
            .map(|module| {
                module
                    .thunks
                    .iter()
                    .enumerate()
                    .filter(|(index, thunk)| {
                        *index == 0
                            || module.thunks[*index - 1]
                                .iat_address
                                .saturating_add(ptr_size)
                                != thunk.iat_address
                    })
                    .count()
            })
            .sum()
    }

    /// Total number of thunks across all modules.
    pub fn thunk_count(&self) -> usize {
        self.modules.iter().map(|m| m.thunks.len()).sum()
    }

    pub fn module_count(&self) -> usize {
        self.modules.len()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_builder_produces_valid_section() {
        let builder = ImportTableBuilder::new(true);
        let (data, strings_base, iat_base) = builder.build_section_data(0x1000);

        // One null descriptor = 20 bytes + no strings + no IAT
        assert_eq!(data.len(), 20);
        assert_eq!(strings_base, 20);
        assert_eq!(iat_base, 20);
        // All zeros (null descriptor)
        assert!(data.iter().all(|&b| b == 0));
    }

    #[test]
    fn single_module_with_name_import() {
        let mut builder = ImportTableBuilder::new(false); // 32-bit
        {
            let m = builder.add_module("kernel32.dll");
            m.thunks.push(ImportThunk {
                iat_address: 0x2000,
                function_name: Some("CreateFileW".into()),
                ordinal: None,
                is_64bit: false,
            });
        }

        let section_va = 0x1000;
        let (data, strings_base, iat_base) = builder.build_section_data(section_va);

        // 2 descriptors (1 + null) = 40 bytes
        // DLL string: "kernel32.dll" + null = 13 bytes (12 + 1)
        // Hint/Name: 2 + "CreateFileW"(11) + null = 14 bytes
        // IAT: 2 pointers (1 thunk + null) * 4 = 8 bytes
        // ILT: 2 pointers (1 thunk + null) * 4 = 8 bytes (Import Lookup Table)
        // Total = 40 + 13 + 14 + 8 + 8 = 83
        assert_eq!(
            data.len(),
            83,
            "build_section_data creates full PE format with both IAT and ILT"
        );
        assert_eq!(strings_base, 40);

        let expected_iat_base = 40 + 13 + 14; // 67
        assert_eq!(iat_base, expected_iat_base as u32);

        // Check descriptor points to DLL name at section_va + strings_base
        let dll_rva = u32::from_le_bytes(data[12..16].try_into().unwrap_or([0; 4]));
        assert_eq!(dll_rva, section_va + strings_base);

        // Check descriptor FirstThunk points to IAT
        let iat_rva = u32::from_le_bytes(data[16..20].try_into().unwrap_or([0; 4]));
        assert_eq!(iat_rva, section_va + iat_base);

        // IAT slot should point to hint/name entry
        let hn_rva = u32::from_le_bytes(
            data[iat_base as usize..iat_base as usize + 4]
                .try_into()
                .unwrap_or([0; 4]),
        );
        let expected_hn_rva = section_va + strings_base + 13; // after DLL name
        assert_eq!(hn_rva, expected_hn_rva);
    }

    #[test]
    fn no_iat_builder_preserves_original_slot_rvas() {
        let mut builder = ImportTableBuilder::new(true);
        let first = builder.add_module("first.dll");
        first.thunks.push(ImportThunk {
            iat_address: 0x1000,
            function_name: Some("First".into()),
            ordinal: None,
            is_64bit: true,
        });
        let second = builder.add_module("second.dll");
        second.thunks.push(ImportThunk {
            iat_address: 0x1100,
            function_name: Some("Second".into()),
            ordinal: None,
            is_64bit: true,
        });

        let (section, thunks) = builder.build_import_section_no_iat(0x5000, 0x1000);

        assert_eq!(builder.emitted_descriptor_count(), 2);
        assert_eq!(
            u32::from_le_bytes(section[0..4].try_into().unwrap()),
            0,
            "no separate ILT: OriginalFirstThunk must remain zero"
        );
        assert_eq!(
            u32::from_le_bytes(section[16..20].try_into().unwrap()),
            0x1000
        );
        assert_eq!(
            u32::from_le_bytes(section[20..24].try_into().unwrap()),
            0,
            "every split descriptor must keep OriginalFirstThunk zero"
        );
        assert_eq!(
            u32::from_le_bytes(section[36..40].try_into().unwrap()),
            0x1100
        );
        assert_eq!(thunks.len(), 34);
        assert_ne!(thunks[0], 0);
        assert!(thunks[1..32].iter().all(|&slot| slot == 0));
        assert_ne!(thunks[32], 0);
        assert_eq!(thunks[33], 0);
    }

    /// Every non-null descriptor from `build_import_section_no_iat` must keep
    /// `OriginalFirstThunk == 0` and a non-zero `FirstThunk` (loader uses FT as ILT).
    #[test]
    fn no_iat_every_descriptor_oft_zero_firstthunk_nonzero() {
        let mut builder = ImportTableBuilder::new(true);
        let mod_a = builder.add_module("kernel32.dll");
        mod_a.thunks.push(ImportThunk {
            iat_address: 0x2000,
            function_name: Some("CreateFileW".into()),
            ordinal: None,
            is_64bit: true,
        });
        mod_a.thunks.push(ImportThunk {
            iat_address: 0x2008,
            function_name: Some("ReadFile".into()),
            ordinal: None,
            is_64bit: true,
        });
        // Gap forces a split descriptor for the same DLL.
        mod_a.thunks.push(ImportThunk {
            iat_address: 0x2020,
            function_name: Some("CloseHandle".into()),
            ordinal: None,
            is_64bit: true,
        });
        let mod_b = builder.add_module("ntdll.dll");
        mod_b.thunks.push(ImportThunk {
            iat_address: 0x2100,
            function_name: None,
            ordinal: Some(42),
            is_64bit: true,
        });

        let (section, thunks) = builder.build_import_section_no_iat(0x6000, 0x2000);
        let desc_count = builder.emitted_descriptor_count();
        assert!(desc_count >= 2, "expected split + ordinal descriptors");

        for i in 0..desc_count {
            let base = i * IMPORT_DESCRIPTOR_SIZE;
            let oft = u32::from_le_bytes(section[base..base + 4].try_into().unwrap());
            let name = u32::from_le_bytes(section[base + 12..base + 16].try_into().unwrap());
            let ft = u32::from_le_bytes(section[base + 16..base + 20].try_into().unwrap());
            assert_ne!(name, 0, "descriptor {i} must be non-null");
            assert_eq!(oft, 0, "descriptor {i}: OriginalFirstThunk must be 0");
            assert_ne!(ft, 0, "descriptor {i}: FirstThunk must be non-zero");
        }

        // Null terminator descriptor
        let term = desc_count * IMPORT_DESCRIPTOR_SIZE;
        assert_eq!(
            u32::from_le_bytes(section[term + 12..term + 16].try_into().unwrap()),
            0
        );

        // Ordinal slot carries the high-bit flag; name slots are non-zero RVAs;
        // zeros between runs are module/run terminators.
        assert!(thunks.iter().any(|&s| s == (IMAGE_ORDINAL_FLAG64 | 42)));
        assert!(thunks
            .iter()
            .any(|&s| s != 0 && s & IMAGE_ORDINAL_FLAG64 == 0));
        assert!(thunks.iter().any(|&s| s == 0));
    }

    #[test]
    fn no_iat_ordinal_and_hint_name_slots() {
        let mut builder = ImportTableBuilder::new(true);
        let m = builder.add_module("mixed.dll");
        m.thunks.push(ImportThunk {
            iat_address: 0x3000,
            function_name: Some("ByName".into()),
            ordinal: None,
            is_64bit: true,
        });
        m.thunks.push(ImportThunk {
            iat_address: 0x3008,
            function_name: None,
            ordinal: Some(7),
            is_64bit: true,
        });

        let (section, thunks) = builder.build_import_section_no_iat(0x7000, 0x3000);
        assert_eq!(u32::from_le_bytes(section[0..4].try_into().unwrap()), 0);
        assert_ne!(u32::from_le_bytes(section[16..20].try_into().unwrap()), 0);

        assert_ne!(thunks[0], 0);
        assert_eq!(
            thunks[0] & IMAGE_ORDINAL_FLAG64,
            0,
            "hint/name is not ordinal"
        );
        assert_eq!(thunks[1], IMAGE_ORDINAL_FLAG64 | 7);
        assert_eq!(thunks[2], 0, "module terminator");
    }

    #[test]
    fn ordinal_import_sets_flag() {
        let mut builder = ImportTableBuilder::new(true); // 64-bit
        {
            let m = builder.add_module("ntdll.dll");
            m.thunks.push(ImportThunk {
                iat_address: 0x3000,
                function_name: None,
                ordinal: Some(42),
                is_64bit: true,
            });
        }

        let (data, _, iat_base) = builder.build_section_data(0x1000);
        let slot = u64::from_le_bytes(
            data[iat_base as usize..iat_base as usize + 8]
                .try_into()
                .unwrap_or([0; 8]),
        );
        assert_eq!(slot, IMAGE_ORDINAL_FLAG64 | 42);
    }

    #[test]
    fn iat_slot_size_respects_arch() {
        assert_eq!(iat_slot_size(false), 4);
        assert_eq!(iat_slot_size(true), 8);
    }
}
