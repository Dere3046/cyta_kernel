// SPDX-License-Identifier: GPL-2.0-only

use anyhow::Result;
use std::fs;
use std::path::Path;

use crate::defs;
use crate::module;
use crate::sepolicy;
use crate::utils;

pub fn on_post_fs_data(key: &str) -> Result<()> {
    unsafe { libc::umask(0) };

    utils::ensure_dir_exists(defs::CKSU_DIR)?;
    utils::ensure_dir_exists(defs::BIN_DIR)?;
    utils::ensure_dir_exists(defs::MODULE_DIR)?;
    utils::ensure_dir_exists(defs::MODULE_UPDATE_DIR)?;

    let _ = fs::copy(defs::TMPFS_CSUD, defs::CSUD_PATH);
    if Path::new(defs::TMPFS_KEY).exists() {
        let _ = fs::copy(defs::TMPFS_KEY, defs::SUPERKEY_PATH);
    }

    if utils::is_safe_mode() {
        eprintln!("csud: safe mode detected, disabling all modules");
        disable_all_modules();
        return Ok(());
    }

    module::handle_updated_modules()?;
    module::prune_modules()?;

    if let Err(e) = sepolicy::load_all_module_sepolicy(key) {
        eprintln!("csud: sepolicy loading failed: {e}");
    }

    exec_common_scripts("post-fs-data.d", true);
    exec_module_scripts("post-fs-data", true);

    module::load_system_prop()?;

    utils::restorecon(Path::new(defs::MODULE_DIR))?;

    let _ = crate::supercall::auth_call(key, defs::CKSU_REPORT_EVENT, 0, 0);

    Ok(())
}

pub fn on_services(_key: &str) -> Result<()> {
    unsafe { libc::umask(0) };
    exec_common_scripts("service.d", false);
    exec_module_scripts("service", false);
    Ok(())
}

pub fn on_boot_completed(_key: &str) -> Result<()> {
    unsafe { libc::umask(0) };
    exec_common_scripts("boot-completed.d", false);
    exec_module_scripts("boot-completed", false);
    Ok(())
}

fn exec_common_scripts(dir_name: &str, blocking: bool) {
    let dir = Path::new(defs::CKSU_DIR).join(dir_name);
    let entries = match fs::read_dir(&dir) {
        Ok(e) => e,
        Err(_) => return,
    };

    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        if let Err(e) = utils::exec_script(&path, blocking, None) {
            eprintln!("csud: common script {} failed: {e}", path.display());
        }
    }
}

fn exec_module_scripts(stage: &str, blocking: bool) {
    let module_dir = Path::new(defs::MODULE_DIR);
    let entries = match fs::read_dir(module_dir) {
        Ok(e) => e,
        Err(_) => return,
    };

    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }
        if path.join("disable").exists() || path.join("remove").exists() {
            continue;
        }

        let script = path.join(format!("{stage}.sh"));
        if !script.exists() {
            continue;
        }

        let module_id = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("");

        if let Err(e) = utils::exec_script(&script, blocking, Some(module_id)) {
            eprintln!("csud: {stage}.sh for {module_id} failed: {e}");
        }
    }
}

fn disable_all_modules() {
    let module_dir = Path::new(defs::MODULE_DIR);
    if let Ok(entries) = fs::read_dir(module_dir) {
        for entry in entries.flatten() {
            let disable_path = entry.path().join("disable");
            let _ = fs::write(&disable_path, "");
        }
    }
}
