#![feature(custom_inner_attributes)]
#![feature(proc_macro_hygiene)]

pub mod flatpak;
pub mod tun2proxy;
pub mod int_repr;
pub mod data;
pub mod graph;
pub mod systemd;
pub mod managed;
pub mod sys;
pub mod paths;

pub use anyhow::Result;
pub use libc::pid_t;
pub use fully_pub::fully_pub as public;