// SPDX-License-Identifier: GPL-2.0-only
// Process management patterns derived from KernelSU (GPL-2.0)

use anyhow::{Context, Result};
use std::fs;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::Command;

use crate::defs;

pub fn ensure_dir_exists(path: &str) -> Result<()> {
    fs::create_dir_all(path).with_context(|| format!("mkdir {path}"))?;
    Ok(())
}

pub fn ensure_file_exists(path: &Path) -> Result<()> {
    if !path.exists() {
        fs::write(path, "").with_context(|| format!("touch {}", path.display()))?;
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

fn switch_cgroup(base: &str, pid: u32) {
    let procs = format!("{base}/cgroup.procs");
    let _ = fs::write(&procs, pid.to_string());
}

pub fn switch_cgroups() {
    let pid = std::process::id();
    switch_cgroup("/acct", pid);
    switch_cgroup("/dev/cg2_bpf", pid);
    switch_cgroup("/sys/fs/cgroup", pid);
    switch_cgroup("/dev/memcg/apps", pid);
}

pub fn get_script_envs(module_id: Option<&str>) -> Vec<(&'static str, String)> {
    let mut envs = vec![
        ("ASH_STANDALONE", "1".to_string()),
        ("CKSU", "true".to_string()),
        ("CKSU_VER_CODE", "200".to_string()),
        ("CKSU_VER", "2.0".to_string()),
        ("MAGISK_VER", "27.0".to_string()),
        ("MAGISK_VER_CODE", "27000".to_string()),
        (
            "PATH",
            format!(
                "{}:{}",
                std::env::var("PATH").unwrap_or_default(),
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
    let parent_dir = path.parent().unwrap_or(Path::new("/"));

    let mut cmd = Command::new(defs::BUSYBOX_PATH);
    unsafe {
        cmd.pre_exec(|| {
            libc::setpgid(0, 0);
            libc::umask(0);
            switch_cgroups();
            Ok(())
        });
    }
    cmd.current_dir(parent_dir)
        .arg("sh")
        .arg(path)
        .envs(get_script_envs(module_id));

    if blocking {
        let status = cmd.status().with_context(|| format!("exec {}", path.display()))?;
        if !status.success() {
            eprintln!("csud: script {} exited {:?}", path.display(), status.code());
        }
    } else {
        cmd.spawn().with_context(|| format!("spawn {}", path.display()))?;
    }
    Ok(())
}

pub fn is_safe_mode() -> bool {
    if let Ok(v) = android_getprop("persist.sys.safemode") {
        if v == "1" {
            return true;
        }
    }
    if let Ok(v) = android_getprop("ro.sys.safemode") {
        if v == "1" {
            return true;
        }
    }
    false
}

pub fn android_getprop(name: &str) -> Result<String> {
    let output = Command::new("/system/bin/getprop")
        .arg(name)
        .output()?;
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

pub fn restorecon(path: &Path) -> Result<()> {
    let _ = Command::new("/system/bin/restorecon")
        .arg("-R")
        .arg(path)
        .status();
    Ok(())
}
