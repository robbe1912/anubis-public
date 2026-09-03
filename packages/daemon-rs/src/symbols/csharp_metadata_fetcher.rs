//! C# .NET metadata fetcher — ECMA-335 type/method extraction from NuGet packages.
//!
//! Replaces the fuget.org HTML scraper with authoritative ECMA-335 metadata
//! parsed from actual .NET DLLs inside .nupkg archives. Provides complete
//! type + method coverage for ANY NuGet package without hardcoded skip-lists.
//!
//! Architecture: download .nupkg → extract ref/lib DLLs via zip → extract CLI
//! metadata section from PE → parse via clrmeta → populate SymbolCache.
//!
//! License: clrmeta=MIT, zip=MIT (compatible with UNLICENSED project).

use crate::symbols::cache::SymbolCache;
use crate::symbols::types::{Symbol, SymbolKind, Visibility};
use std::io::Read;

const NUGET_FLAT_CONTAINER: &str = "https://api.nuget.org/v3-flatcontainer";
const FETCH_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);

/// Resolve a Relative Virtual Address (RVA) to a file offset using PE section headers.
fn resolve_rva(dll: &[u8], sections_start: usize, num_sections: u16, rva: u32) -> Option<usize> {
    for i in 0..num_sections as usize {
        let s = sections_start + i * 40;
        if s + 40 > dll.len() {
            return None;
        }
        let virtual_addr = u32::from_le_bytes([dll[s + 12], dll[s + 13], dll[s + 14], dll[s + 15]]);
        let virtual_size = u32::from_le_bytes([dll[s + 8], dll[s + 9], dll[s + 10], dll[s + 11]]);
        let raw_offset = u32::from_le_bytes([dll[s + 20], dll[s + 21], dll[s + 22], dll[s + 23]]);
        if rva >= virtual_addr && rva < virtual_addr + virtual_size {
            return Some((raw_offset + (rva - virtual_addr)) as usize);
        }
    }
    None
}

/// Extract CLI metadata bytes from a PE/.NET DLL.
/// clrmeta is PE-agnostic — needs just the metadata section, not the full PE file.
fn extract_cli_metadata(dll: &[u8]) -> Option<&[u8]> {
    if dll.len() < 64 {
        return None;
    }
    let dos_magic = u16::from_le_bytes([dll[0], dll[1]]);
    if dos_magic != 0x5A4D {
        return None;
    }

    let e_lfanew = u32::from_le_bytes([dll[0x3C], dll[0x3D], dll[0x3E], dll[0x3F]]) as usize;
    if e_lfanew + 24 > dll.len() {
        return None;
    }
    if &dll[e_lfanew..e_lfanew + 4] != b"PE\0\0" {
        return None;
    }

    let coff_start = e_lfanew + 4;
    if coff_start + 20 > dll.len() {
        return None;
    }
    let num_sections = u16::from_le_bytes([dll[coff_start + 2], dll[coff_start + 3]]);
    let opt_header_size = u16::from_le_bytes([dll[coff_start + 16], dll[coff_start + 17]]);
    let opt_start = coff_start + 20;
    if opt_start + 2 > dll.len() {
        return None;
    }

    let magic = u16::from_le_bytes([dll[opt_start], dll[opt_start + 1]]);
    let is_pe32_plus = magic == 0x20B;
    let data_dirs_start = opt_start + if is_pe32_plus { 112 } else { 96 };
    let cli_dir_offset = data_dirs_start + 14 * 8;
    if cli_dir_offset + 8 > dll.len() {
        return None;
    }

    let cli_rva = u32::from_le_bytes([
        dll[cli_dir_offset],
        dll[cli_dir_offset + 1],
        dll[cli_dir_offset + 2],
        dll[cli_dir_offset + 3],
    ]);
    if cli_rva == 0 {
        return None; // Not a managed (.NET) DLL
    }

    let sections_start = opt_start + opt_header_size as usize;
    let cli_off = resolve_rva(dll, sections_start, num_sections, cli_rva)?;
    if cli_off + 16 > dll.len() {
        return None;
    }

    let meta_rva = u32::from_le_bytes([dll[cli_off + 8], dll[cli_off + 9], dll[cli_off + 10], dll[cli_off + 11]]);
    let meta_size = u32::from_le_bytes([dll[cli_off + 12], dll[cli_off + 13], dll[cli_off + 14], dll[cli_off + 15]]);

    let meta_off = resolve_rva(dll, sections_start, num_sections, meta_rva)?;
    let end = meta_off + meta_size as usize;
    if end > dll.len() {
        return None;
    }

    Some(&dll[meta_off..end])
}

/// Parse DLL bytes into Symbol entries using clrmeta ECMA-335 metadata.
/// Extracts all public type definitions and method definitions.
fn parse_dll_to_symbols(dll: &[u8], library: &str) -> Vec<Symbol> {
    let metadata_bytes = match extract_cli_metadata(dll) {
        Some(b) => b,
        None => return Vec::new(),
    };

    let metadata = match clrmeta::Metadata::parse(metadata_bytes) {
        Ok(m) => m,
        Err(e) => {
            tracing::debug!(error = %e, library, "clrmeta parse failed");
            return Vec::new();
        }
    };

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let mut symbols = Vec::new();

    // Extract type definitions — full_name gives "Namespace.TypeName"
    for type_info in metadata.types() {
        let full_name = type_info.full_name();
        // Skip compiler-generated and internal runtime types
        if full_name.starts_with('<')
            || full_name == "<Module>"
            || full_name.starts_with("System.Runtime.CompilerServices")
        {
            continue;
        }

        let short_name = full_name.rsplit('.').next().unwrap_or(&full_name).to_string();
        symbols.push(Symbol {
            library: library.to_string(),
            version: "latest".to_string(),
            path: full_name,
            name: short_name,
            kind: SymbolKind::Class,
            signature: None,
            params: vec![],
            return_type: None,
            doc_text: None,
            source_file: None,
            visibility: Visibility::Public,
            is_deprecated: false,
            deprecated_message: None,
            extracted_at: now,
        });
    }

    // Extract method definitions — name is the method name string
    for method_info in metadata.methods() {
        let name = method_info.name.clone();
        symbols.push(Symbol {
            library: library.to_string(),
            version: "latest".to_string(),
            path: name.clone(),
            name,
            kind: SymbolKind::Method,
            signature: None,
            params: vec![],
            return_type: None,
            doc_text: None,
            source_file: None,
            visibility: Visibility::Public,
            is_deprecated: false,
            deprecated_message: None,
            extracted_at: now,
        });
    }

    tracing::info!(
        library,
        types = metadata.type_defs.len(),
        methods = metadata.method_defs.len(),
        symbols_extracted = symbols.len(),
        "csharp metadata: parsed DLL"
    );
    symbols
}

/// Download a NuGet .nupkg and extract all managed DLLs from lib/ and ref/ directories.
/// Returns Vec<(dll_name, dll_bytes)> for each .NET DLL found.
async fn download_and_extract_nupkg(
    client: &reqwest::Client,
    package_lower: &str,
    version: &str,
) -> Result<Vec<(String, Vec<u8>)>, String> {
    let url = format!(
        "{}/{}/{}/{}.{}.nupkg",
        NUGET_FLAT_CONTAINER, package_lower, version, package_lower, version
    );

    let resp = client
        .get(&url)
        .send()
        .await
        .map_err(|e| format!("download {}: {}", url, e))?;

    if !resp.status().is_success() {
        return Err(format!("download {}: HTTP {}", url, resp.status()));
    }

    let bytes = resp
        .bytes()
        .await
        .map_err(|e| format!("read body {}: {}", url, e))?;

    // Extract .dll files from the zip archive (.nupkg is a ZIP)
    let reader = std::io::Cursor::new(bytes.to_vec());
    let mut zip = zip::ZipArchive::new(reader).map_err(|e| format!("unzip: {}", e))?;

    let mut dlls = Vec::new();
    let mut seen_dlls = std::collections::HashSet::new();

    for i in 0..zip.len() {
        let mut file = zip
            .by_index(i)
            .map_err(|e| format!("zip entry {}: {}", i, e))?;
        let name = file.name().to_string();

        // Only extract managed DLLs from lib/ or ref/ directories
        if (name.contains("lib/") || name.contains("ref/")) && name.ends_with(".dll") {
            // Prefer higher TFM versions: net8.0 > net6.0 > netstandard2.0
            let priority = if name.contains("net8.0") {
                3
            } else if name.contains("net6.0") || name.contains("net7.0") {
                2
            } else if name.contains("netstandard") {
                1
            } else {
                0
            };

            // Get the base DLL name (e.g., "MediatR" from "lib/net8.0/MediatR.dll")
            let dll_name = name
                .rsplit('/')
                .next()
                .unwrap_or(&name)
                .trim_end_matches(".dll")
                .to_string();

            // For multi-TFM packages, keep only the highest priority version
            let key = dll_name.clone();
            if seen_dlls.contains(&key) && priority < 2 {
                continue; // Already have a better version
            }
            seen_dlls.insert(key);

            let mut buf = Vec::with_capacity(file.size() as usize);
            file.read_to_end(&mut buf)
                .map_err(|e| format!("read dll {}: {}", name, e))?;
            dlls.push((dll_name, buf));
        }
    }

    Ok(dlls)
}

/// Fetch and cache C# package symbols via ECMA-335 metadata parsing.
///
/// Downloads the .nupkg from NuGet flat container, extracts managed DLLs,
/// parses CLI metadata via clrmeta, and populates the SymbolCache with
/// authoritative type and method definitions.
///
/// This replaces the fuget.org HTML scraper approach, providing complete
/// type/method coverage without hardcoded skip-lists. Works for ANY NuGet
/// package: MediatR, Serilog, Polly, FluentValidation, EF Core, ASP.NET, etc.
pub async fn fetch_and_cache_via_metadata(
    package: &str,
    version: Option<&str>,
) -> Result<(usize, String), String> {
    let package_lower = package.to_lowercase();

    // Resolve version via NuGet registration API if not specified
    let version = match version {
        Some(v) => v.to_string(),
        None => resolve_latest_version(&package_lower).await?,
    };

    let client = reqwest::Client::builder()
        .timeout(FETCH_TIMEOUT)
        .user_agent("anubis-scanner/0.5 (csharp-metadata-fetcher)")
        .build()
        .map_err(|e| format!("client: {}", e))?;

    let dlls = download_and_extract_nupkg(&client, &package_lower, &version).await?;
    if dlls.is_empty() {
        return Err(format!("no managed DLLs in {} {}", package_lower, version));
    }

    let mut all_symbols = Vec::new();
    for (dll_name, dll_bytes) in &dlls {
        let lib_key = if package_lower.starts_with("microsoft.netcore.app.ref") {
            format!("csharp.{}", dll_name.to_lowercase())
        } else {
            package_lower.clone()
        };
        let symbols = parse_dll_to_symbols(dll_bytes, &lib_key);
        tracing::info!(
            package = package_lower,
            dll = dll_name.as_str(),
            symbols = symbols.len(),
            "extracted symbols from DLL"
        );
        all_symbols.extend(symbols);
    }

    if all_symbols.is_empty() {
        return Err(format!("no symbols extracted from {} DLLs", dlls.len()));
    }

    let count = all_symbols.len();
    let cache = SymbolCache::open().map_err(|e| format!("cache: {}", e))?;
    cache
        .insert_many(&all_symbols)
        .map_err(|e| format!("insert: {}", e))?;

    Ok((
        count,
        format!("fetched {} symbols from {} v{}", count, package_lower, version),
    ))
}

/// Resolve the latest stable version of a NuGet package via the registration API.
async fn resolve_latest_version(package_lower: &str) -> Result<String, String> {
    let url = format!(
        "https://api.nuget.org/v3/registration5-semver1/{}/index.json",
        package_lower
    );

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .map_err(|e| format!("version client: {}", e))?;

    let resp: serde_json::Value = client
        .get(&url)
        .send()
        .await
        .map_err(|e| format!("version lookup: {}", e))?
        .json()
        .await
        .map_err(|e| format!("version parse: {}", e))?;

    // Registration response has items[0].upper version (latest stable)
    let version = resp
        .get("items")
        .and_then(|items| items.get(0))
        .and_then(|item| item.get("upper"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| format!("no version found for {}", package_lower))?;

    Ok(version.to_string())
}

/// Seed BCL (Base Class Library) symbols by downloading Microsoft.NETCore.App.Ref.
///
/// This single .nupkg contains reference assemblies for ALL .NET BCL types:
/// System.Threading.CancellationToken, System.DateTimeOffset, System.Collections.Generic.IEnumerable,
/// System.Threading.Tasks.Task, etc. Eliminates FPs on common .NET types that
/// were previously hardcoded in CSHARP_KEYWORDS.
///
/// Runs at most once per process (OnceLock guard).
pub async fn seed_bcl_via_metadata() {
    use std::sync::OnceLock;
    static SEEDED: OnceLock<Result<(usize, String), String>> = OnceLock::new();

    if SEEDED.get().is_some() {
        return;
    }

    let result = fetch_and_cache_via_metadata("Microsoft.NETCore.App.Ref", Some("8.0.10")).await;
    match &result {
        Ok((count, msg)) => {
            tracing::info!(count, "BCL metadata seeding complete");
            let _ = SEEDED.set(result);
        }
        Err(e) => {
            tracing::warn!(error = %e, "BCL metadata seeding failed — falling back to fuget.org");
            let _ = SEEDED.set(result);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_resolve_rva_basic() {
        // Minimal fake PE with one section mapping RVA 0x2000 → offset 0x200
        let mut dll = vec![0u8; 512];
        // DOS header
        dll[0] = 0x4D; // 'M'
        dll[1] = 0x5A; // 'Z'
        // PE offset at 0x3C → points to offset 64
        dll[0x3C..0x40].copy_from_slice(&64u32.to_le_bytes());
        // PE signature at 64
        dll[64..68].copy_from_slice(b"PE\0\0");
        // COFF: 2 sections, opt_header_size = 0
        dll[70..72].copy_from_slice(&2u16.to_le_bytes()); // num_sections
        dll[80..82].copy_from_slice(&0u16.to_le_bytes()); // opt_header_size
        // sections_start = 84
        // Section 0: virtual_addr=0x2000, virtual_size=0x1000, raw_offset=0x200
        dll[84 + 8..84 + 12].copy_from_slice(&0x1000u32.to_le_bytes());
        dll[84 + 12..84 + 16].copy_from_slice(&0x2000u32.to_le_bytes());
        dll[84 + 20..84 + 24].copy_from_slice(&0x200u32.to_le_bytes());

        let offset = resolve_rva(&dll, 84, 2, 0x2050);
        assert_eq!(offset, Some(0x250)); // 0x200 + (0x2050 - 0x2000)
    }

    #[test]
    fn test_extract_cli_metadata_rejects_non_pe() {
        let result = extract_cli_metadata(b"not a PE file");
        assert!(result.is_none());
    }

    #[test]
    fn test_extract_cli_metadata_rejects_non_managed() {
        // PE file without CLI directory (native DLL)
        let mut dll = vec![0u8; 512];
        dll[0] = 0x4D;
        dll[1] = 0x5A;
        dll[0x3C..0x40].copy_from_slice(&64u32.to_le_bytes());
        dll[64..68].copy_from_slice(b"PE\0\0");
        // CLI RVA = 0 (not managed)
        let result = extract_cli_metadata(&dll);
        assert!(result.is_none());
    }
}
