use std::fs;
use std::fs::File;
use std::io::BufReader;
use anyhow::Context;

fn main() -> anyhow::Result<()> {
    let v = fs::read("data/regulation.bin").context("Reading file")?;
    let _reg = fromformats::regulation::Regulation::from_encrypted_compressed(&v).context("Regulation")?;
    Ok(())
}