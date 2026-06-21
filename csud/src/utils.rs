// SPDX-License-Identifier: GPL-2.0-only

use anyhow::{Context, Result};
use std::fs;
use std::path::Path;
use std::process::Command;

use crate::defs;

pub fn ensure_dir_exists(path: &str) -> Result<()> {
    let p = Path::new(path);
    if !p.exists() {
        fs::create_dir_all(p).with_context(|| format!("mkdir -p {path}"))?;
    }
    Ok(())
}

pub fn ensure_file_exists(path: &Path) -> Result<()> {
    if !path.exists() {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(path, "")?;
    }
    Ok(())
}

pub fn ensure_clean_dir(path: &Path) -> Result<()> {
    if path.exists() {
        fs::remove_dir_all(path)?;
    }
    fs::create_dir_all(path)?;
    Ok(())
}

pub fn get_script_envs(module_id: Option<&str>) -> Vec<(&'static str, String)> {
    let mut envs = vec![
        ("ASH_STANDALONE", "1".into()),
        ("CKSU", "true".into()),
        ("CKSU_VER", "2.0".into()),
        ("CKSU_VER_CODE", "200".into()),
        ("MAGISK_VER", "27.0".into()),
        ("MAGISK_VER_CODE", "27000".into()),
        (
            "PATH",
            format!(
                "{}:/sbin:/system/bin:/system/xbin:/vendor/bin",
                defs::BIN_DIR
            ),
        ),
    ];
    if let Some(id) = module_id {
        envs.push(("CKSU_MODULE", id.to_string()));
    }
    envs
}

pub fn exec_script(path: &Path, blocking: bool, module_id: Option<&str>) -> Result<()> {
    if !path.exists() {
        return Ok(());
    }

    let envs = get_script_envs(module_id);

    let mut cmd = Command::new(defs::BUSYBOX_PATH);
    cmd.arg("sh").arg(path);
    cmd.env_clear();
    for (k, v) in &envs {
        cmd.env(k, v);
    }

    if blocking {
        let status = cmd.status().with_context(|| format!("exec {}", path.display()))?;
        if !status.success() {
            anyhow::bail!("script {} exited with {}", path.display(), status);
        }
    } else {
        cmd.spawn().with_context(|| format!("spawn {}", path.display()))?;
    }

    Ok(())
}
