#![feature(decl_macro)]
#![feature(ip_bits)]

use std::{
    collections::HashSet,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    ops::RangeInclusive,
};

use anyhow::Result;
pub use ipnetwork::{IpNetwork, IpNetworkError, Ipv4Network, Ipv6Network};
use rangemap::{RangeInclusiveSet, StepFns, StepLite};
use thiserror::Error;

#[derive(Debug)]
/// ID allocator implemented with range set
pub struct IDAlloc<T: Ord + Clone + StepLite>(pub RangeInclusiveSet<T>);

impl<T: Ord + Clone + StepLite> Default for IDAlloc<T> {
    fn default() -> Self {
        Self(Default::default())
    }
}

impl<T: Ord + Clone + StepFns<T> + StepLite> IDAlloc<T> {
    /// Find an empty slot in the specified domain
    pub fn alloc(&mut self, domain: &RangeInclusive<T>) -> Option<T> {
        if let Some(ra) = self.0.gaps(domain).next() {
            assert!(!ra.is_empty());
            let k = ra.start().to_owned();
            let id = k.clone()..=k.clone();
            self.0.insert(id.to_owned());
            Some(k)
        } else {
            None
        }
    }
    pub fn unset(&mut self, id: T) {
        self.0.remove(id.clone()..=id);
    }
    pub fn alloc_or(&mut self, domain: &RangeInclusive<T>) -> Result<T, IDAllocError> {
        self.alloc(domain).ok_or(IDAllocError)
    }
    pub fn set(&mut self, id: T) {
        self.0.insert(id.clone()..=id)
    }
    pub fn insert(&mut self, range: RangeInclusive<T>) {
        self.0.insert(range)
    }
}

#[derive(Error, Debug)]
#[error("failed to allocate new id")]
pub struct IDAllocError;

#[test]
fn allocs() {
    let mut ida = IDAlloc::default();
    let dom = i32::MIN..=i32::MAX;
    assert!(ida.0.is_empty());
    assert_eq!(ida.alloc(&dom), Some(0));
    assert_eq!(ida.alloc(&dom), Some(1));
    assert_eq!(ida.alloc(&dom), Some(2));
    ida.unset(1);
    assert_eq!(ida.alloc(&dom), Some(1));
    assert_eq!(ida.alloc(&dom), Some(3));
    ida.unset(3);
    assert_eq!(ida.alloc(&dom), Some(3));
    assert_eq!(ida.alloc(&dom), Some(4));
}

#[test]
fn rset() {
    let mut rset = RangeInclusiveSet::new();
    rset.insert(0..=0);
    rset.insert(1..=1);
    rset.insert(2..=2);
    dbg!(rset.gaps(&(0..=1)).collect::<Vec<_>>());
}

use derivative::Derivative;

wrapip!(Ipv4A, Ipv4Addr, addr, host, new);
wrapip!(Ipv6A, Ipv6Addr, addr, host, new);

pub macro wrapip($ty:ident, $inner:ty, $addr:ident, $host:ident, $fnew:ident) {
    #[derive(Clone, Copy, Debug, Derivative)]
    #[derivative(PartialEq, PartialOrd, Ord, Eq)]
    pub struct $ty {
        pub $addr: $inner,
        /// Length of the host part
        #[derivative(PartialEq = "ignore", PartialOrd = "ignore")]
        pub $host: u8,
    }
    impl StepLite for $ty {
        fn add_one(&self) -> Self {
            // Host part bits are discarded
            $ty {
                $addr: <$inner>::from_bits(
                    (self.$addr.to_bits() & !0 << self.$host) + (1 << self.$host),
                ),
                $host: self.$host,
            }
        }
        fn sub_one(&self) -> Self {
            $ty {
                $addr: <$inner>::from_bits(
                    (self.$addr.to_bits() & !0 << self.$host) - (1 << self.$host),
                ),
                $host: self.$host,
            }
        }
    }
    impl From<$inner> for $ty {
        fn from(val: $inner) -> $ty {
            $ty::$fnew(val, 0)
        }
    }
    impl $ty {
        pub fn $fnew($addr: $inner, $host: u8) -> Self {
            $ty { $addr, $host }
        }
    }
}

pub fn from_ipnet(
    set: &HashSet<IpNetwork>,
    prefix: u8,
    prefix6: u8,
) -> (IDAlloc<Ipv4A>, IDAlloc<Ipv6A>, u8, u8) {
    let host = 32 - prefix;
    let host6 = 128 - prefix6;
    let mut v4 = IDAlloc::default();
    let mut v6 = IDAlloc::default();
    for ip in set {
        match ip {
            // The entire subnet has been occupied
            IpNetwork::V4(p) => v4.insert(p.range(host)),
            IpNetwork::V6(p) => v6.insert(p.range(host6)),
        }
    }
    (v4, v6, host, host6)
}

pub trait NetRange {
    type R;
    fn range(self, host: u8) -> RangeInclusive<Self::R>;
}

impl NetRange for Ipv4Network {
    type R = Ipv4A;
    fn range(self, host: u8) -> RangeInclusive<Self::R> {
        Ipv4A::new(self.network(), host)..=Ipv4A::new(self.broadcast(), host)
    }
}

impl NetRange for Ipv6Network {
    type R = Ipv6A;
    fn range(self, host: u8) -> RangeInclusive<Self::R> {
        Ipv6A::new(self.network(), host)..=Ipv6A::new(self.broadcast(), host)
    }
}

impl TryFrom<Ipv4A> for Ipv4Network {
    type Error = IpNetworkError;
    fn try_from(value: Ipv4A) -> std::prelude::v1::Result<Self, Self::Error> {
        Ipv4Network::new(value.addr, 32 - value.host)
    }
}

impl TryFrom<Ipv6A> for Ipv6Network {
    type Error = IpNetworkError;
    fn try_from(value: Ipv6A) -> std::prelude::v1::Result<Self, Self::Error> {
        Ipv6Network::new(value.addr, 128 - value.host)
    }
}

#[test]
fn findspare() -> Result<()> {
    let set: HashSet<IpNetwork> = HashSet::from_iter([
        "100.64.0.2/24".parse()?,
        "100.67.0.3/24".parse()?,
        "100.68.0.3/24".parse()?,
    ]);
    let (mut v4, v6, host, h6) = from_ipnet(&set, 31, 127);
    let dom = Ipv4A::new("100.64.0.0".parse()?, host)..=Ipv4A::new("100.64.255.255".parse()?, h6);
    dbg!(v4.alloc(&dom));
    Ok(())
}

#[test]
fn findip() -> Result<()> {
    let set: HashSet<IpNetwork> = HashSet::from_iter([
        "100.64.0.2/24".parse()?, // Entire subnet considered occupied
        "100.67.0.3/24".parse()?,
        "100.68.0.3/24".parse()?,
    ]);
    let (mut v4, v6, host, h6) = from_ipnet(&set, 32, 128);
    let dom = Ipv4A::new("100.64.0.0".parse()?, host)..=Ipv4A::new("100.64.255.255".parse()?, h6);
    dbg!(v4.alloc(&dom)); // 100.64.1.0
    Ok(())
}

#[test]
fn findip2() -> Result<()> {
    let mut v4: IDAlloc<Ipv4A> = Default::default();
    v4.set(Ipv4A {
        addr: "100.64.0.0".parse()?,
        host: 0,
    });
    let dom = "100.64.0.0/16".parse::<Ipv4Network>()?.range(0);
    dbg!(v4.alloc(&dom));
    dbg!(v4.alloc(&dom));
    Ok(())
}
