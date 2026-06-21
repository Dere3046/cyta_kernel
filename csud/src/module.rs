// SPDX-License-Identifier: GPL-2.0-only

use anyhow::{ensure, Context, Result};
use std::collections::HashMap;
use std::fs;
use std::path::Path;
use std::process::Command;

use crate::defs;
use crate::utils;

pub fn read_module_prop(module_path: &Path) -> Result<HashMap<String, String>> {
    let prop_path = module_path.join("module.prop");
    let content = fs::read_to_string(&prop_path)
        .with_context(|| format!("read {}", prop_path.display()))?;

    let mut map = HashMap::new();
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some((k, v)) = line.split_once('=') {
            map.insert(k.trim().to_string(), v.trim().to_string());
        }
    }
    Ok(map)
}

pub fn validate_module_id(id: &str) -> Result<()> {
    ensure!(!id.is_empty(), "module id is empty");
    let bytes = id.as_bytes();
    ensure!(
        bytes[0].is_ascii_alphabetic(),
        "module id must start with a letter: {id}"
    );
    ensure!(
        bytes.len() >= 2,
        "module id too short: {id}"
    );
    for &b in bytes {
        ensure!(
            b.is_ascii_alphanumeric() || b == b'.' || b == b'_' || b == b'-',
            "invalid char in module id: {id}"
        );
    }
    Ok(())
}

pub fn install_module(zip_path: &str) -> Result<()> {
    ensure!(
        Path::new(zip_path).exists(),
        "zip not found: {zip_path}"
    );

    let tmp_dir = format!("{}/tmp_install", defs::CKSU_DIR);
    let tmp = Path::new(&tmp_dir);
    utils::ensure_clean_dir(tmp)?;

    let status = Command::new(defs::BUSYBOX_PATH)
        .args(["unzip", "-o", zip_path, "-d", &tmp_dir])
        .status()
        .context("unzip")?;
    ensure!(status.success(), "unzip failed");

    let props = read_module_prop(tmp)?;
    let id = props.get("id").context("module.prop missing 'id'")?;
    validate_module_id(id)?;

    let update_dir = format!("{}/{}", defs::MODULE_UPDATE_DIR, id);
    let module_dir = format!("{}/{}", defs::MODULE_DIR, id);

    utils::ensure_dir_exists(defs::MODULE_UPDATE_DIR)?;
    utils::ensure_dir_exists(defs::MODULE_DIR)?;

    let update_path = Path::new(&update_dir);
    utils::ensure_clean_dir(update_path)?;

    let entries = fs::read_dir(tmp)?;
    for entry in entries {
        let entry = entry?;
        let name = entry.file_name();
        let src = entry.path();
        let dst = update_path.join(&name);
        if src.is_dir() {
            copy_dir_recursive(&src, &dst)?;
        } else {
            fs::copy(&src, &dst)?;
        }
    }

    let mod_path = Path::new(&module_dir);
    utils::ensure_dir_exists(&module_dir)?;
    let src_prop = update_path.join("module.prop");
    let dst_prop = mod_path.join("module.prop");
    fs::copy(&src_prop, &dst_prop)?;

    utils::ensure_file_exists(&mod_path.join("update"))?;

    fs::remove_dir_all(tmp)?;

    println!("installed module: {id}");
    Ok(())
}

fn copy_dir_recursive(src: &Path, dst: &Path) -> Result<()> {
    fs::create_dir_all(dst)?;
    for entry in fs::read_dir(src)? {
        let entry = entry?;
        let s = entry.path();
        let d = dst.join(entry.file_name());
        if s.is_dir() {
            copy_dir_recursive(&s, &d)?;
        } else {
            fs::copy(&s, &d)?;
        }
    }
    Ok(())
}

pub fn uninstall_module(id: &str) -> Result<()> {
    validate_module_id(id)?;
    let dir = format!("{}/{}", defs::MODULE_DIR, id);
    ensure!(Path::new(&dir).exists(), "module not found: {id}");
    utils::ensure_file_exists(&Path::new(&dir).join("remove"))?;
    println!("marked for removal: {id}");
    Ok(())
}

pub fn enable_module(id: &str) -> Result<()> {
    validate_module_id(id)?;
    let dir = format!("{}/{}", defs::MODULE_DIR, id);
    ensure!(Path::new(&dir).exists(), "module not found: {id}");
    let disable = Path::new(&dir).join("disable");
    if disable.exists() {
        fs::remove_file(&disable)?;
    }
    println!("enabled: {id}");
    Ok(())
}

pub fn disable_module(id: &str) -> Result<()> {
    validate_module_id(id)?;
    let dir = format!("{}/{}", defs::MODULE_DIR, id);
    ensure!(Path::new(&dir).exists(), "module not found: {id}");
    utils::ensure_file_exists(&Path::new(&dir).join("disable"))?;
    println!("disabled: {id}");
    Ok(())
}

pub fn list_modules() -> Result<()> {
    let dir = Path::new(defs::MODULE_DIR);
    if !dir.exists() {
        println!("[]");
        return Ok(());
    }

    let mut modules = Vec::new();
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        if !entry.path().is_dir() {
            continue;
        }
        let path = entry.path();
        let props = match read_module_prop(&path) {
            Ok(p) => p,
            Err(_) => continue,
        };

        let id = props.get("id").cloned().unwrap_or_default();
        let name = props.get("name").cloned().unwrap_or_default();
        let version = props.get("version").cloned().unwrap_or_default();
        let author = props.get("author").cloned().unwrap_or_default();
        let enabled = !path.join("disable").exists();
        let update = path.join("update").exists();
        let remove = path.join("remove").exists();

        modules.push(format!(
            r#"  {{"id":"{}","name":"{}","version":"{}","author":"{}","enabled":{},"update":{},"remove":{}}}"#,
            id, name, version, author, enabled, update, remove
        ));
    }

    println!("[");
    let len = modules.len();
    for (i, m) in modules.iter().enumerate() {
        if i < len - 1 {
            println!("{m},");
        } else {
            println!("{m}");
        }
    }
    println!("]");
    Ok(())
}

pub fn prune_modules() -> Result<()> {
    let dir = Path::new(defs::MODULE_DIR);
    if !dir.exists() {
        return Ok(());
    }

    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }
        if path.join("remove").exists() {
            fs::remove_dir_all(&path)?;
            let update_path = Path::new(defs::MODULE_UPDATE_DIR).join(entry.file_name());
            if update_path.exists() {
                fs::remove_dir_all(&update_path)?;
            }
        }
    }
    Ok(())
}

pub fn handle_updated_modules() -> Result<()> {
    let update_dir = Path::new(defs::MODULE_UPDATE_DIR);
    if !update_dir.exists() {
        return Ok(());
    }

    for entry in fs::read_dir(update_dir)? {
        let entry = entry?;
        let src = entry.path();
        if !src.is_dir() {
            continue;
        }
        let id = entry.file_name();
        let dst = Path::new(defs::MODULE_DIR).join(&id);

        if dst.exists() {
            fs::remove_dir_all(&dst)?;
        }
        fs::rename(&src, &dst)?;

        let update_marker = dst.join("update");
        if update_marker.exists() {
            fs::remove_file(&update_marker)?;
        }
    }

    if update_dir.exists() {
        fs::remove_dir_all(update_dir)?;
    }
    Ok(())
}

pub fn load_system_prop() -> Result<()> {
    let dir = Path::new(defs::MODULE_DIR);
    if !dir.exists() {
        return Ok(());
    }

    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }
        if path.join("disable").exists() || path.join("remove").exists() {
            continue;
        }

        let prop_file = path.join("system.prop");
        if !prop_file.exists() {
            continue;
        }

        let content = fs::read_to_string(&prop_file)?;
        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if let Some((key, value)) = line.split_once('=') {
                let _ = Command::new("resetprop")
                    .args([key.trim(), value.trim()])
                    .status();
            }
        }
    }
    Ok(())
}
