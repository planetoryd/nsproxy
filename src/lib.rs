#![feature(custom_inner_attributes)]
#![feature(proc_macro_hygiene)]
#![feature(decl_macro)]
#![feature(async_fn_in_trait)]
#![feature(impl_trait_projections)]
#![feature(associated_type_defaults)]
#![allow(async_fn_in_trait)]
#![feature(iterator_try_collect)]
#![feature(error_generic_member_access)]
#![feature(ip_bits)]
#![feature(iter_next_chunk)]
#![feature(array_try_map)]

pub mod data;
pub mod flatpak;
pub mod graph;
pub mod managed;
pub mod paths;
pub mod probe;
pub mod sys;
pub mod systemd;
pub mod watcher;

use std::{borrow::Cow, path::Path};

pub use anyhow::Result;
pub use fully_pub::fully_pub as public;
pub use libc::pid_t; // make everything pub

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

pub const PROBE_TUN: &str = "tunp";
pub const UID_HINT_VAR: &str = "NSPROXY_UID";
pub const DEFAULT_MTU: u32 = 9000;