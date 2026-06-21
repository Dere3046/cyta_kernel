mod defs;
mod su;
mod supercall;

use std::env;
use std::path::Path;

fn get_key(args: &[String]) -> Option<(String, usize)> {
    for (i, arg) in args.iter().enumerate() {
        if arg == "-k" && i + 1 < args.len() {
            return Some((args[i + 1].clone(), i));
        }
    }
    if let Ok(k) = env::var("CKSU_KEY") {
        return Some((k, usize::MAX));
    }
    None
}

fn usage() {
    eprintln!("csud -k <key> <command> [args...]");
    eprintln!();
    eprintln!("  root              grant root + shell");
    eprintln!("  su [args...]      su compatible mode");
    eprintln!("  hello             check module loaded");
    eprintln!("  allow <uid>       add uid to allowlist");
    eprintln!("  deny <uid>        remove uid");
    eprintln!("  post-fs-data      boot stage");
    eprintln!("  services          boot stage");
    eprintln!("  boot-completed    boot stage");
    eprintln!("  module <cmd>      module management");
}

fn main() {
    let args: Vec<String> = env::args().collect();

    let exe_name = args
        .first()
        .and_then(|a| Path::new(a).file_name())
        .and_then(|n| n.to_str())
        .unwrap_or("csud");

    // Multi-call: argv[0] == "su"
    if exe_name == "su" {
        let (key, _) = match get_key(&args[1..]) {
            Some((k, idx)) => (k, idx),
            None => {
                if let Ok(k) = env::var("CKSU_KEY") {
                    (k, usize::MAX)
                } else {
                    eprintln!("su: set CKSU_KEY or use -k <key>");
                    std::process::exit(1);
                }
            }
        };
        let su_args: Vec<String> = args[1..]
            .iter()
            .filter(|a| *a != "-k")
            .cloned()
            .collect();
        if let Err(e) = su::main(&key, &su_args) {
            eprintln!("su: {e}");
            std::process::exit(1);
        }
        return;
    }

    // Normal csud mode
    let (key, key_idx) = match get_key(&args) {
        Some(v) => v,
        None => {
            usage();
            std::process::exit(1);
        }
    };

    let cmd_args: Vec<String> = args
        .iter()
        .enumerate()
        .filter(|(i, a)| {
            *i != 0
                && (key_idx == usize::MAX || *i != key_idx + 1)
                && a.as_str() != "-k"
        })
        .map(|(_, a)| a.clone())
        .collect();

    if cmd_args.is_empty() {
        usage();
        std::process::exit(1);
    }

    let cmd = cmd_args[0].as_str();
    let result = match cmd {
        "hello" => {
            let ver = supercall::hello();
            println!("cksu v{}.{}", (ver >> 8) & 0xFF, ver & 0xFF);
            Ok(())
        }
        "root" => {
            match supercall::grant_root(&key) {
                Ok(()) => {
                    println!("uid={} gid={}", unsafe { libc::getuid() }, unsafe {
                        libc::getgid()
                    });
                    su::main(&key, &[])
                }
                Err(e) => Err(e),
            }
        }
        "su" => su::main(&key, &cmd_args[1..]),
        "allow" => {
            let uid: u32 = cmd_args.get(1).and_then(|s| s.parse().ok()).unwrap_or(0);
            supercall::add_uid(&key, uid).map(|_| println!("added {uid}"))
        }
        "deny" => {
            let uid: u32 = cmd_args.get(1).and_then(|s| s.parse().ok()).unwrap_or(0);
            supercall::remove_uid(&key, uid).map(|_| println!("removed {uid}"))
        }
        "post-fs-data" | "services" | "boot-completed" => {
            println!("csud: {cmd} (not implemented yet)");
            Ok(())
        }
        "module" => {
            println!("csud: module management (not implemented yet)");
            Ok(())
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
