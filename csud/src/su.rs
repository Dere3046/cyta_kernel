// SPDX-License-Identifier: GPL-2.0-only

use crate::defs;
use crate::utils;
use std::ffi::CString;

fn usage() {
    eprint!(
        "usage: su [--login] [--preserve-environment] [--mount-master]\n\
         \x20         [--shell SHELL] [--command COMMAND] [--help] [--version]\n\
         \x20         [-] [USER]\n"
    );
    std::process::exit(1);
}

fn add_env(envp: &mut Vec<CString>, key: &str, val: &str) {
    let s = format!("{key}={val}");
    if let Ok(c) = CString::new(s) {
        envp.push(c);
    }
}

fn switch_mnt_ns(pid: i32) -> anyhow::Result<()> {
    let ns_path = format!("/proc/{pid}/ns/mnt");
    let c_path = CString::new(ns_path)?;
    let fd = unsafe { libc::open(c_path.as_ptr(), libc::O_RDONLY) };
    if fd < 0 {
        anyhow::bail!("open mnt ns failed");
    }
    let ret = unsafe { libc::syscall(libc::SYS_setns, fd, libc::CLONE_NEWNS) };
    unsafe { libc::close(fd) };
    if ret < 0 {
        anyhow::bail!("setns failed");
    }
    Ok(())
}

pub fn main(args: &[String]) -> anyhow::Result<()> {
    if unsafe { libc::getuid() } != 0 {
        anyhow::bail!("permission denied");
    }

    utils::switch_cgroups();

    let mut shell = "/system/bin/sh".to_string();
    let mut command: Option<String> = None;
    let mut login = false;
    let mut preserve_env = false;
    let mut mount_master = false;
    let mut i = 0;

    while i < args.len() {
        match args[i].as_str() {
            "-c" => {
                if i + 1 < args.len() {
                    i += 1;
                    command = Some(args[i].clone());
                }
            }
            "-s" => {
                if i + 1 < args.len() {
                    i += 1;
                    shell = args[i].clone();
                }
            }
            "-l" | "--login" => login = true,
            "-p" | "--preserve-environment" => preserve_env = true,
            "-M" | "--mount-master" => mount_master = true,
            "-v" | "--version" => {
                println!("{}", env!("CARGO_PKG_VERSION"));
                return Ok(());
            }
            "-h" | "--help" => usage(),
            "-" => {
                login = true;
                if i + 1 < args.len() {
                    i += 1;
                }
            }
            _ => {}
        }
        i += 1;
    }

    if mount_master {
        let _ = switch_mnt_ns(1);
    }

    let arg0 = if login { "-sh" } else { "sh" };

    let mut envp: Vec<CString> = Vec::new();

    if !preserve_env {
        let uid = unsafe { libc::getuid() };
        let pw = unsafe { libc::getpwuid(uid).as_ref() };
        if let Some(pw) = pw {
            let home = unsafe { std::ffi::CStr::from_ptr(pw.pw_dir) };
            let name = unsafe { std::ffi::CStr::from_ptr(pw.pw_name) };
            add_env(&mut envp, "HOME", home.to_string_lossy().as_ref());
            add_env(&mut envp, "USER", name.to_string_lossy().as_ref());
            add_env(&mut envp, "LOGNAME", name.to_string_lossy().as_ref());
        }
        add_env(&mut envp, "SHELL", &shell);
    }

    if let Ok(old) = std::env::var("PATH") {
        add_env(&mut envp, "PATH", &format!("{old}:/data/adb/cksu/bin"));
    } else {
        add_env(&mut envp, "PATH", "/sbin:/system/bin:/system/xbin:/data/adb/cksu/bin");
    }

    if std::path::Path::new(defs::RC_PATH).exists() && std::env::var("ENV").is_err() {
        add_env(&mut envp, "ENV", defs::RC_PATH);
    }

    let prog = CString::new(shell)?;
    let a0 = CString::new(arg0)?;

    let mut argv: Vec<*const libc::c_char> = vec![a0.as_ptr()];
    if let Some(ref c) = command {
        argv.push(
            CString::new(b"-c".as_ref())
                .unwrap_or_else(|_| CString::new("").unwrap())
                .as_ptr(),
        );
        argv.push(
            CString::new(c.as_bytes())
                .unwrap_or_else(|_| CString::new("").unwrap())
                .as_ptr(),
        );
    }
    argv.push(std::ptr::null());

    let mut envp_ptrs: Vec<*const libc::c_char> = envp.iter().map(|e| e.as_ptr()).collect();
    envp_ptrs.push(std::ptr::null());

    unsafe {
        libc::umask(0o22);
        libc::execve(prog.as_ptr(), argv.as_ptr(), envp_ptrs.as_ptr());
    }

    anyhow::bail!("execvpe failed");
}
