// SPDX-License-Identifier: GPL-2.0-only
use anyhow::Result;
use clap::Parser;
use myboot::cpio::Cpio;
use myboot::parser::BootImage;
use myboot::patcher::BootImagePatchOption;
use std::fs;
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
        #[arg(short, long)]
        ko: PathBuf,
        #[arg(short, long)]
        loader: PathBuf,
        #[arg(short, long)]
        wrapper: PathBuf,
    },
}

fn patch(input: &PathBuf, output: &PathBuf, ko: &PathBuf, loader: &PathBuf, wrapper: &PathBuf) -> Result<()> {
    let data = fs::read(input)?;
    let img = BootImage::parse(&data)?;

    let ramdisk_data = img.blocks().get_ramdisk()
        .ok_or_else(|| anyhow::anyhow!("no ramdisk found"))?
        .dump();

    let mut cpio = Cpio::load_from_data(&ramdisk_data)?;

    if cpio.exists("/init") {
        cpio.mv("/init", "/init.real");
    }

    let wrapper_data = fs::read(wrapper)?;
    let ko_data = fs::read(ko)?;
    let loader_data = fs::read(loader)?;

    cpio.add("/init", &wrapper_data, 0o755);
    cpio.add("/cksu.ko", &ko_data, 0o644);
    cpio.add("/lkmloader.ko", &loader_data, 0o644);

    let new_ramdisk = cpio.dump();

    let mut out_data = Vec::new();
    BootImagePatchOption::new()
        .replace_ramdisk(&new_ramdisk, false)
        .patch(&data, &mut out_data)?;

    fs::write(output, out_data)?;
    println!("patched: {}", output.display());
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
