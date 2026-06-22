// SPDX-License-Identifier: GPL-2.0-only
use anyhow::{Context, Result};
use clap::Parser;
use myboot::compress::{get_decoder, is_compressed, parse_compress_format};
use myboot::cpio::{Cpio, CpioEntry};
use myboot::parser::BootImage;
use myboot::patcher::BootImagePatchOption;
use std::fs;
use std::io::{Cursor, Read};
use std::path::PathBuf;

const EMBEDDED_INIT_WRAPPER: &[u8] = include_bytes!("../assets/init_wrapper");
const KEY_PLACEHOLDER: &[u8] = b"CKSU_KEY_PLACEHOLDER_PAD_PAD_PAD_000";

#[derive(Parser)]
#[command(name = "cksu-patch", version, about = "Patch init_boot.img for CKSU")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(clap::Subcommand)]
enum Commands {
    Patch {
        input: PathBuf,
        #[arg(short, long)]
        output: PathBuf,
        #[arg(short, long)]
        key: String,
        #[arg(long)]
        ko: PathBuf,
    },
}

fn make_entry(data: &[u8], mode: u32) -> CpioEntry {
    CpioEntry {
        mode,
        uid: 0,
        gid: 0,
        rdev_major: 0,
        rdev_minor: 0,
        data: Some(data.to_vec()),
        symlink: None,
    }
}

fn inject_key(wrapper: &[u8], key: &str) -> Vec<u8> {
    let mut patched = wrapper.to_vec();
    if let Some(pos) = patched
        .windows(KEY_PLACEHOLDER.len())
        .position(|w| w == KEY_PLACEHOLDER)
    {
        let mut buf = vec![0u8; KEY_PLACEHOLDER.len()];
        let copy_len = key.len().min(buf.len());
        buf[..copy_len].copy_from_slice(&key.as_bytes()[..copy_len]);
        patched[pos..pos + KEY_PLACEHOLDER.len()].copy_from_slice(&buf);
    }
    patched
}

fn patch(input: &PathBuf, output: &PathBuf, key: &str, ko: &PathBuf) -> Result<()> {
    let data = fs::read(input).context("read input image")?;
    let boot = BootImage::parse(&data).context("parse boot image")?;

    let ramdisk_block = boot
        .blocks
        .ramdisk
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("no ramdisk found"))?;

    let ramdisk_raw = ramdisk_block.data;
    let fmt = parse_compress_format(ramdisk_raw);
    let ramdisk_data = if is_compressed(fmt) {
        let mut decoder = get_decoder(fmt, ramdisk_raw)?;
        let mut buf = Vec::new();
        decoder.read_to_end(&mut buf)?;
        buf
    } else {
        ramdisk_raw.to_vec()
    };

    let mut cpio = Cpio::load_from_data(&ramdisk_data).context("parse cpio")?;

    if cpio.exists("/init") {
        cpio.mv("/init", "/init.real")?;
    }

    let wrapper_patched = inject_key(EMBEDDED_INIT_WRAPPER, key);
    let ko_data = fs::read(ko).context("read cksu.ko")?;

    cpio.add("/init", make_entry(&wrapper_patched, 0o100755));
    cpio.add("/cksu.ko", make_entry(&ko_data, 0o100644));

    let mut cpio_out = Vec::new();
    cpio.dump(&mut cpio_out)?;

    let mut out_buf = Cursor::new(Vec::new());
    let mut patcher = BootImagePatchOption::new(&boot);
    patcher.replace_ramdisk(cpio_out);
    patcher.patch(&mut out_buf)?;

    fs::write(output, out_buf.into_inner())?;
    eprintln!("patched: {}", output.display());
    Ok(())
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Patch {
            input,
            output,
            key,
            ko,
        } => patch(&input, &output, &key, &ko),
    }
}
