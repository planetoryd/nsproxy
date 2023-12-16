use nsproxy::data::{PassFD, SocketC, TUNC};
use nsproxy_common::{ExactNS, UniqueFile};
use std::fmt::Display;

fn main() {
    println!(
        "{}",
        SocketC {
            addr: "/path".to_string(),
        }
    );
    println!(
        "{}",
        TUNC {
            layer: tun::Layer::L2,
            name: Some("tun0".to_owned())
        }
    );
    println!(
        "{}",
        PassFD {
            creation: TUNC {
                layer: tun::Layer::L2,
                name: Some("tun0".to_owned())
            },
            listener: "/run/sock".parse().unwrap(),
            receiver: nsproxy::data::FDRecver::Systemd("randomservice".to_owned())
        }
    );
    println!(
        "{}",
        ExactNS {
            unique: UniqueFile { dev: 2, ino: 3 },
            source: nsproxy_common::NSSource::Pid(3)
        }
    )
}
