use libc::c_int;
use nix::sched::CloneFlags;
use serde::{self, Deserialize, Deserializer, Serialize, Serializer};

type IntRep = c_int;
type Flags = CloneFlags;

pub fn serialize<S>(date: &Flags, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    date.bits().serialize(serializer)
}

pub fn deserialize<'de, D>(deserializer: D) -> Result<Flags, D::Error>
where
    D: Deserializer<'de>,
{
    let raw: IntRep = IntRep::deserialize(deserializer)?;
    Flags::from_bits(raw).ok_or(serde::de::Error::custom(format!(
        "Unexpected flags value {}",
        raw
    )))
}