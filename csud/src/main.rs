mod boot;
mod defs;
mod module;
mod sepolicy;
mod su;
mod supercall;
mod utils;

use std::env;
use std::path::Path;

fn resolve_key(args: &[String]) -> (Option<String>, Vec<String>) {
    let mut key = None;
    let mut filtered = Vec::new();
    let mut skip_next = false;

    for (i, arg) in args.iter().enumerate() {
        if skip_next {
            skip_next = false;
            continue;
        }
        if arg == "-k" && i + 1 < args.len() {
            key = Some(args[i + 1].clone());
            skip_next = true;
            continue;
        }
        filtered.push(arg.clone());
    }

    if key.is_none() {
        key = env::var("CKSU_KEY").ok();
    }

    if key.is_none() {
        for path in [defs::TMPFS_KEY, defs::SUPERKEY_PATH] {
            if let Ok(content) = std::fs::read_to_string(path) {
                let k = content.trim().to_string();
                if !k.is_empty() {
                    key = Some(k);
                    break;
                }
            }
        }
    }

    (key, filtered)
}

fn usage() {
    eprintln!("csud -k <key> <command> [args...]");
    eprintln!();
    eprintln!("  root              grant root + shell");
    eprintln!("  su [args...]      su compatible mode");
    eprintln!("  hello             check module loaded");
    eprintln!("  allow <uid>       add uid to allowlist");
    eprintln!("  deny <uid>        remove uid");
    eprintln!("  list              show allowlist");
    eprintln!("  post-fs-data      boot stage");
    eprintln!("  services          boot stage");
    eprintln!("  boot-completed    boot stage");
    eprintln!("  module <sub>      install|uninstall|enable|disable|list");
}

fn main() {
    let args: Vec<String> = env::args().collect();

    let exe_name = args
        .first()
        .and_then(|a| Path::new(a).file_name())
        .and_then(|n| n.to_str())
        .unwrap_or("csud");

    if exe_name == "su" {
        let (key, remaining) = resolve_key(&args[1..]);
        let key = key.unwrap_or_else(|| {
            eprintln!("su: no key (use -k, CKSU_KEY, or {})", defs::SUPERKEY_PATH);
            std::process::exit(1);
        });
        if let Err(e) = su::main(&key, &remaining) {
            eprintln!("su: {e}");
            std::process::exit(1);
        }
        return;
    }

    let (key, cmd_args) = resolve_key(&args[1..]);
    let key = match key {
        Some(k) => k,
        None => {
            usage();
            std::process::exit(1);
        }
    };

    if cmd_args.is_empty() {
        usage();
        std::process::exit(1);
    }

    let cmd = cmd_args[0].as_str();
    let result = match cmd {
        "hello" => {
            match supercall::hello(&key) {
                Ok(ver) => {
                    println!("cksu v{}.{}", (ver >> 8) & 0xFF, ver & 0xFF);
                    Ok(())
                }
                Err(e) => Err(e),
            }
        }
        "root" => match supercall::grant_root(&key) {
            Ok(()) => {
                println!("uid={} gid={}", unsafe { libc::getuid() }, unsafe { libc::getgid() });
                su::main(&key, &[])
            }
            Err(e) => Err(e),
        },
        "su" => su::main(&key, &cmd_args[1..]),
        "allow" => {
            let uid: u32 = cmd_args.get(1).and_then(|s| s.parse().ok()).unwrap_or(0);
            supercall::add_uid(&key, uid).map(|_| println!("added {uid}"))
        }
        "deny" => {
            let uid: u32 = cmd_args.get(1).and_then(|s| s.parse().ok()).unwrap_or(0);
            supercall::remove_uid(&key, uid).map(|_| println!("removed {uid}"))
        }
        "list" => match supercall::get_list(&key) {
            Ok(uids) => {
                println!("allowlist ({}):", uids.len());
                for uid in &uids {
                    println!("  {uid}");
                }
                Ok(())
            }
            Err(e) => Err(e),
        },
        "post-fs-data" | "--post-fs-data" => boot::on_post_fs_data(&key),
        "services" | "--services" => boot::on_services(&key),
        "boot-completed" | "--boot-completed" => boot::on_boot_completed(&key),
        "module" => {
            let sub = cmd_args.get(1).map(|s| s.as_str()).unwrap_or("");
            match sub {
                "install" => {
                    let zip = cmd_args.get(2).map(|s| s.as_str()).unwrap_or("");
                    module::install_module(zip)
                }
                "uninstall" => {
                    let id = cmd_args.get(2).map(|s| s.as_str()).unwrap_or("");
                    module::uninstall_module(id)
                }
                "enable" => {
                    let id = cmd_args.get(2).map(|s| s.as_str()).unwrap_or("");
                    module::enable_module(id)
                }
                "disable" => {
                    let id = cmd_args.get(2).map(|s| s.as_str()).unwrap_or("");
                    module::disable_module(id)
                }
                "list" => module::list_modules(),
                _ => {
                    eprintln!("module subcommands: install|uninstall|enable|disable|list");
                    Ok(())
                }
            }
        }
        _ => {
            eprintln!("unknown command: {cmd}");
            usage();
            std::process::exit(1);
        }
    };

    if let Err(e) = result {
        eprintln!("csud: {e}");
        std::process::exit(1);
    }
}
