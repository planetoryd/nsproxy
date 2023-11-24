#![feature(custom_inner_attributes)]
#![feature(proc_macro_hygiene)]
#![feature(decl_macro)]
#![allow(async_fn_in_trait)]

pub mod flatpak;
pub mod tun2proxy;
pub mod data;
pub mod graph;
pub mod systemd;
pub mod managed;
pub mod sys;
pub mod paths;
pub mod probe;

use std::path::Path;

pub use anyhow::Result;
pub use libc::pid_t;
pub use fully_pub::fully_pub as public; // make everything pub

use thiserror::Error;

#[derive(Error, Debug)]
#[error("Only UTF8 file paths are supported")]
pub struct NonUTF8Error;

pub fn path_to_str(pa: &Path) -> Result<&str> {
    pa.to_str().ok_or(NonUTF8Error.into())
}

pub macro aok() {
    Ok::<(), anyhow::Error>(())
}