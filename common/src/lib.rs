#![feature(associated_type_defaults)]

use anyhow::Result;

pub trait Validate {
    fn validate(&self) -> Result<()>;
}
