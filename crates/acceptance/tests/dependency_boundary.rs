//! Prove mida-acceptance does not depend on production crates.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::process::Command;

const FORBIDDEN: &[&str] = &[
    "mida-core",
    "mida-pe",
    "mida-tracer",
    "mida-cli",
    "mida-packers-themida",
    "mida-disasm",
];

#[test]
fn acceptance_crate_excludes_production_deps() {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let workspace_root = manifest_dir
        .parent()
        .and_then(|p| p.parent())
        .expect("workspace root")
        .to_path_buf();

    let mut output = Command::new(env!("CARGO"))
        .current_dir(&workspace_root)
        .args([
            "metadata",
            "--format-version",
            "1",
            "--offline",
            "--manifest-path",
        ])
        .arg(workspace_root.join("Cargo.toml"))
        .output()
        .expect("spawn cargo metadata");

    if !output.status.success() {
        // Offline may fail if registry cache is cold; retry online once for local dev.
        output = Command::new(env!("CARGO"))
            .current_dir(&workspace_root)
            .args(["metadata", "--format-version", "1", "--manifest-path"])
            .arg(workspace_root.join("Cargo.toml"))
            .output()
            .expect("spawn cargo metadata retry");
    }
    assert!(
        output.status.success(),
        "cargo metadata failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_boundary(&output.stdout, &workspace_root);
}

fn assert_boundary(stdout: &[u8], workspace_root: &std::path::Path) {
    let meta: serde_json::Value =
        serde_json::from_slice(stdout).expect("parse cargo metadata JSON");

    let packages = meta["packages"].as_array().expect("packages");
    let mut by_id = BTreeMap::new();
    let mut by_name: BTreeMap<String, String> = BTreeMap::new();
    for p in packages {
        let id = p["id"].as_str().unwrap().to_string();
        let name = p["name"].as_str().unwrap().to_string();
        by_name.insert(name.clone(), id.clone());
        by_id.insert(id, p);
    }

    let acceptance_id = by_name
        .get("mida-acceptance")
        .expect("mida-acceptance package present")
        .clone();

    // Resolve transitive dependency package names via resolve nodes.
    let resolve = meta
        .get("resolve")
        .expect("resolve section present when not using --no-deps");
    let nodes = resolve["nodes"].as_array().expect("resolve.nodes");
    let mut deps_by_id: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for n in nodes {
        let id = n["id"].as_str().unwrap().to_string();
        let deps: Vec<String> = n["dependencies"]
            .as_array()
            .unwrap()
            .iter()
            .map(|d| d.as_str().unwrap().to_string())
            .collect();
        deps_by_id.insert(id, deps);
    }

    let mut stack = vec![acceptance_id.clone()];
    let mut seen = BTreeSet::new();
    let mut dep_names = BTreeSet::new();
    while let Some(id) = stack.pop() {
        if !seen.insert(id.clone()) {
            continue;
        }
        if let Some(p) = by_id.get(&id) {
            let name = p["name"].as_str().unwrap();
            if id != acceptance_id {
                dep_names.insert(name.to_string());
            }
        }
        if let Some(deps) = deps_by_id.get(&id) {
            for d in deps {
                stack.push(d.clone());
            }
        }
    }

    let mut violations = Vec::new();
    for forbid in FORBIDDEN {
        if dep_names
            .iter()
            .any(|n| n == forbid || n.starts_with("mida-packers-"))
        {
            if FORBIDDEN.contains(&dep_names.iter().find(|n| *n == forbid).unwrap().as_str())
                || dep_names.iter().any(|n| n.starts_with("mida-packers-"))
            {
                // refined below
            }
        }
        if dep_names.contains(*forbid) {
            violations.push((*forbid).to_string());
        }
    }
    for n in &dep_names {
        if n.starts_with("mida-packers-") {
            violations.push(n.clone());
        }
    }
    // Also forbid other mida-* production crates except mida-acceptance itself
    for n in &dep_names {
        if n.starts_with("mida-") && n != "mida-acceptance" {
            violations.push(n.clone());
        }
    }
    violations.sort();
    violations.dedup();

    let report = serde_json::json!({
        "schema_version": "mida.dependency-boundary/v1",
        "package": "mida-acceptance",
        "forbidden": FORBIDDEN,
        "resolved_dependency_names": dep_names.iter().cloned().collect::<Vec<_>>(),
        "violations": violations,
        "pass": violations.is_empty(),
    });

    // Write deliverable next to workspace when CARGO_MANIFEST_DIR parent is workspace.
    let out_path = workspace_root.join("dependency_boundary.json");
    std::fs::write(
        &out_path,
        serde_json::to_string_pretty(&report).unwrap() + "\n",
    )
    .expect("write dependency_boundary.json");

    assert!(
        violations.is_empty(),
        "mida-acceptance depends on forbidden crates: {violations:?}\nfull deps: {dep_names:?}"
    );
    let _ = output_is_valid(&report);
}

fn output_is_valid(v: &serde_json::Value) -> bool {
    v["pass"].as_bool() == Some(true)
}
