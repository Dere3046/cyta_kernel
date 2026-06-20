// SPDX-License-Identifier: GPL-2.0-only
use anyhow::Result;
use clap::Parser;
use myboot::compress::{get_decoder, is_compressed};
use myboot::cpio::{Cpio, CpioEntry};
use myboot::parser::BootImage;
use myboot::patcher::BootImagePatchOption;
use std::fs;
use std::io::Cursor;
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "cksu-patch", about = "Patch init_boot.img for CKSU")]
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
        #[arg(long)]
        ko: PathBuf,
        #[arg(long)]
        loader: PathBuf,
        #[arg(long)]
        wrapper: PathBuf,
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

fn patch(input: &PathBuf, output: &PathBuf, ko: &PathBuf, loader: &PathBuf, wrapper: &PathBuf) -> Result<()> {
    let data = fs::read(input)?;
    let boot = BootImage::parse(&data)?;

    let ramdisk_block = boot.blocks.ramdisk
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("no ramdisk found"))?;

    let ramdisk_raw = ramdisk_block.data;
    let ramdisk_data = if is_compressed(ramdisk_raw) {
        let mut decoder = get_decoder(ramdisk_raw)?;
        let mut buf = Vec::new();
        std::io::Read::read_to_end(&mut decoder, &mut buf)?;
        buf
    } else {
        ramdisk_raw.to_vec()
    };

    let mut cpio = Cpio::load_from_data(&ramdisk_data)?;

    if cpio.exists("/init") {
        cpio.mv("/init", "/init.real")?;
    }

    let wrapper_data = fs::read(wrapper)?;
    let ko_data = fs::read(ko)?;
    let loader_data = fs::read(loader)?;

    cpio.add("/init", make_entry(&wrapper_data, 0o100755));
    cpio.add("/cksu.ko", make_entry(&ko_data, 0o100644));
    cpio.add("/lkmloader.ko", make_entry(&loader_data, 0o100644));

    let mut cpio_out = Vec::new();
    cpio.dump(&mut cpio_out)?;

    let mut out_buf = Cursor::new(Vec::new());
    BootImagePatchOption::new(&boot)
        .replace_ramdisk(cpio_out)
        .patch(&mut out_buf)?;

    fs::write(output, out_buf.into_inner())?;
    eprintln!("patched: {}", output.display());
    Ok(())
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Patch { input, output, ko, loader, wrapper } => {
            patch(&input, &output, &ko, &loader, &wrapper)
        }
    }
}
