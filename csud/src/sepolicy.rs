// SPDX-License-Identifier: GPL-2.0-only

use anyhow::Result;
use std::fs;
use std::path::Path;
use crate::supercall;
use crate::defs;

fn hash_name(name: &str) -> u32 {
    let mut h: u32 = 0;
    for b in name.bytes() {
        h = h.wrapping_mul(31).wrapping_add(b as u32);
    }
    h
}

pub fn load_sepolicy_file(key: &str, path: &Path) -> Result<()> {
    let content = fs::read_to_string(path)?;

    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        if let Some(type_name) = line.strip_prefix("type ") {
            let type_name = type_name.trim();
            let context = format!("u:r:{}:s0", type_name);
            supercall::add_virt_type(key, type_name, &context)?;
        } else if let Some(domain) = line.strip_prefix("permissive ") {
            let domain = domain.trim();
            let source_hash = hash_name(domain);
            supercall::load_sepolicy_rule(key, defs::SEPOLICY_PERMISSIVE, source_hash, 0, 0, 0)?;
        } else if let Some(rest) = line.strip_prefix("allow ") {
            parse_allow_rule(key, rest)?;
        }
    }

    Ok(())
}

fn parse_allow_rule(key: &str, rule: &str) -> Result<()> {
    let parts: Vec<&str> = rule.splitn(4, ' ').collect();
    if parts.len() < 3 {
        return Ok(());
    }

    let source = parts[0].trim();
    let target = parts[1].trim();
    let class_name = if parts.len() >= 4 {
        parts[2].trim().trim_end_matches(':')
    } else {
        parts[2].trim()
    };

    let source_hash = hash_name(source);
    let target_hash = hash_name(target);
    let class_hash = hash_name(class_name) as u16;
    let perms = 0xFFFFFFFFu32;

    supercall::load_sepolicy_rule(key, defs::SEPOLICY_ALLOW, source_hash, target_hash, class_hash, perms)?;
    Ok(())
}

pub fn load_all_module_sepolicy(key: &str) -> Result<()> {
    let module_dir = Path::new(defs::MODULE_DIR);
    if !module_dir.exists() {
        return Ok(());
    }

    for entry in fs::read_dir(module_dir)? {
        let entry = entry?;
        let path = entry.path();
        if !path.is_dir() { continue; }
        if path.join("disable").exists() || path.join("remove").exists() { continue; }

        let sepolicy_file = path.join("sepolicy.rule");
        if sepolicy_file.exists() {
            if let Err(e) = load_sepolicy_file(key, &sepolicy_file) {
                eprintln!("csud: sepolicy for {:?} failed: {e}", path.file_name());
            }
        }
    }

    Ok(())
}
