use crate::supercall;
use std::env;
use std::ffi::CString;
use std::os::unix::ffi::OsStrExt;

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

    let mut shell = "/system/bin/sh".to_string();
    let mut command: Option<String> = None;
    let mut login = false;
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
            _ => {}
        }
        i += 1;
    }

    if let Some(cmd) = command {
        let c_shell = CString::new(shell.as_bytes())?;
        let c_arg0 = if login {
            CString::new(format!("-{}", shell.rsplit('/').next().unwrap_or("sh")))?
        } else {
            CString::new(shell.rsplit('/').next().unwrap_or("sh").as_bytes())?
        };
        let c_flag = CString::new("-c")?;
        let c_cmd = CString::new(cmd.as_bytes())?;

        let argv = [c_arg0.as_ptr(), c_flag.as_ptr(), c_cmd.as_ptr(), std::ptr::null()];
        unsafe {
            libc::execv(c_shell.as_ptr(), argv.as_ptr());
        }
    } else {
        let c_shell = CString::new(shell.as_bytes())?;
        let c_arg0 = if login {
            CString::new(format!("-{}", shell.rsplit('/').next().unwrap_or("sh")))?
        } else {
            CString::new(shell.rsplit('/').next().unwrap_or("sh").as_bytes())?
        };

        let argv = [c_arg0.as_ptr(), std::ptr::null()];

        env::set_var("PATH", "/sbin:/system/bin:/system/xbin:/data/adb/cksu/bin");
        env::set_var("HOME", "/data");

        unsafe {
            libc::execv(c_shell.as_ptr(), argv.as_ptr());
        }
    }

    anyhow::bail!("execv failed");
}
