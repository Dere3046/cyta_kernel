// SPDX-License-Identifier: GPL-2.0-only

use crate::utils;
use std::ffi::CString;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::Command;

fn usage() {
    eprint!(
        "usage: su [--login] [--preserve-environment] [--mount-master]\n\
         \x20         [--shell SHELL] [--command COMMAND] [--help] [--version]\n\
         \x20         [-] [USER]\n"
    );
    std::process::exit(1);
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
    let mut user: Option<String> = None;
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
                    user = Some(args[i].clone());
                }
            }
            arg if !arg.starts_with('-') => {
                user = Some(arg.to_string());
            }
            _ => {}
        }
        i += 1;
    }

    let mut cmd = Command::new(&shell);
    let shell_name = Path::new(&shell)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("sh");

    let arg0 = if login {
        format!("-{shell_name}")
    } else {
        shell_name.to_string()
    };

    unsafe {
        cmd.pre_exec(move || {
            unsafe { libc::umask(0o22) };
            if mount_master {
                let ns_path = CString::new("/proc/1/ns/mnt").unwrap();
                let fd = libc::open(ns_path.as_ptr(), libc::O_RDONLY);
                if fd >= 0 {
                    libc::syscall(libc::SYS_setns, fd, libc::CLONE_NEWNS);
                    libc::close(fd);
                }
            }
            Ok(())
        });
    }
    cmd.arg0(&arg0);

    if let Some(ref c) = command {
        cmd.args(["-c", c]);
    }

    if !preserve_env {
        cmd.env_remove("IFS");
        let uid = unsafe { libc::getuid() };
        let pw = unsafe { libc::getpwuid(uid).as_ref() };
        if let Some(pw) = pw {
            let pw_name = unsafe { std::ffi::CStr::from_ptr(pw.pw_name) };
            let home = unsafe { std::ffi::CStr::from_ptr(pw.pw_dir) };
            cmd.env("HOME", home.to_string_lossy().as_ref());
            cmd.env("USER", pw_name.to_string_lossy().as_ref());
            cmd.env("LOGNAME", pw_name.to_string_lossy().as_ref());
        }
        cmd.env("SHELL", &shell);
    }

    if let Ok(old_path) = std::env::var("PATH") {
        cmd.env("PATH", format!("{}:/data/adb/cksu/bin", old_path));
    } else {
        cmd.env("PATH", "/sbin:/system/bin:/system/xbin:/data/adb/cksu/bin");
    }

    if let Some(ref u) = user {
        cmd.env("USER", u);
    }

    let err = cmd.exec();
    anyhow::bail!("exec failed: {err}");
}
