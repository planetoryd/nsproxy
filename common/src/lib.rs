#![feature(associated_type_defaults)]

use anyhow::Result;

pub trait Validate {
    type Items<'k>  = () where Self: 'k;
    fn validate(&self) -> Result<()>;
    fn list<'k>(&'k mut self) -> Self::Items<'k> {
        unimplemented!()
    }
}

/// To keep things simple
impl<K: Validate> Validate for Option<K> {
    type Items<'k> = () where Self: 'k;
    fn validate(&self) -> Result<()> {
        if let Some(k) = self {
            k.validate()
        } else {
            Ok(())
        }
    }
    fn list<'k>(&'k mut self) -> Self::Items<'k> {
        ()
    }
}
