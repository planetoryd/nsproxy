use anyhow::Result;
use nsproxy_common::Validate;
use nsproxy_derive::Validate;

#[derive(Validate)]
struct S1 {
    f1: K,
    f2: K,
}

struct K;
impl Validate for K {
    fn validate(&self) -> Result<()> {
        Ok(())
    }
}
