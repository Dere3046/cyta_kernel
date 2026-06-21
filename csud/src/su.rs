// SPDX-License-Identifier: GPL-2.0-only
// Su mode patterns derived from KernelSU (GPL-2.0)

use crate::supercall;
use crate::utils;
use std::env;
use std::ffi::CString;
use std::os::unix::process::CommandExt;
use std::process::Command;

fn set_selinux_context(ctx: &str) {
    let _ = std::fs::write("/proc/thread-self/attr/current", ctx);
    let _ = std::fs::write("/proc/thread-self/attr/exec", ctx);
}

pub fn main(key: &str, args: &[String]) -> anyhow::Result<()> {
    if let Err(e) = supercall::grant_root(key) {
        eprintln!("su: auth failed: {e}");
        std::process::exit(1);
    }

    set_selinux_context("u:r:magisk:s0");
    utils::switch_cgroups();

    let mut shell = "/system/bin/sh".to_string();
    let mut command: Option<String> = None;
    let mut login = false;
    let mut mount_master = false;
    let mut i = 0;

    while i < args.len() {
        match args[i].as_str() {
            "-c" => {
                if i + 1 < args.len() {
                    command = Some(args[i + 1..].join(" "));
                    break;
                }
            }
            "-s" => {
                if i + 1 < args.len() {
                    i += 1;
                    shell = args[i].clone();
                }
            }
            "-l" | "--login" => login = true,
            "-M" | "--mount-master" => mount_master = true,
            _ => {}
        }
        i += 1;
    }

    if mount_master {
        let _ = switch_mnt_ns(1);
    }

    let shell_name = shell.rsplit('/').next().unwrap_or("sh");
    let arg0 = if login {
        format!("-{shell_name}")
    } else {
        shell_name.to_string()
    };

    let mut cmd = Command::new(&shell);
    unsafe {
        cmd.pre_exec(|| {
            libc::setpgid(0, 0);
            Ok(())
        });
    }
    cmd.arg0(&arg0);

    if let Some(c) = command {
        cmd.args(["-c", &c]);
    }

    cmd.env("PATH", "/sbin:/system/bin:/system/xbin:/data/adb/cksu/bin");
    cmd.env("HOME", "/data");
    cmd.env("SHELL", &shell);
    cmd.env("USER", "root");
    cmd.env("LOGNAME", "root");

    let err = cmd.exec();
    anyhow::bail!("exec failed: {err}");
}

fn switch_mnt_ns(pid: i32) -> anyhow::Result<()> {
    let ns_path = format!("/proc/{pid}/ns/mnt");
    let fd = unsafe { libc::open(CString::new(ns_path)?.as_ptr(), libc::O_RDONLY) };
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
