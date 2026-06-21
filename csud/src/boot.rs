// SPDX-License-Identifier: GPL-2.0-only
use anyhow::Result;
use std::path::Path;
use crate::defs;
use crate::utils;
use crate::module;

pub fn on_post_fs_data(_key: &str) -> Result<()> {
    utils::ensure_dir_exists(defs::CKSU_DIR)?;
    utils::ensure_dir_exists(defs::BIN_DIR)?;
    utils::ensure_dir_exists(defs::MODULE_DIR)?;
    utils::ensure_dir_exists(defs::MODULE_UPDATE_DIR)?;

    module::handle_updated_modules()?;
    module::prune_modules()?;

    exec_module_scripts("post-fs-data", true);

    module::load_system_prop()?;

    Ok(())
}

pub fn on_services(_key: &str) -> Result<()> {
    exec_module_scripts("service", false);
    Ok(())
}

pub fn on_boot_completed(_key: &str) -> Result<()> {
    exec_module_scripts("boot-completed", false);
    Ok(())
}

fn exec_module_scripts(stage: &str, blocking: bool) {
    let module_dir = Path::new(defs::MODULE_DIR);
    let entries = match std::fs::read_dir(module_dir) {
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

        let module_id = path.file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("");

        if let Err(e) = utils::exec_script(&script, blocking, Some(module_id)) {
            eprintln!("csud: {stage}.sh for {module_id} failed: {e}");
        }
    }
}
