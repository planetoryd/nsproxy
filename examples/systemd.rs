use std::{os::{
    fd::{AsRawFd, FromRawFd, IntoRawFd},
    unix::net::{UnixStream, UnixListener},
}, io::{Read, Write}};

use anyhow::Result;
use libsystemd::activation::IsType;
use nsproxy::path_to_str;
use passfd::FdPassingExt;
use systemd_zbus::Mode::Replace;

// Run with sudo
fn main() -> Result<()> {
    let mut args = std::env::args();
    let selfexe = std::env::current_exe()?;
    let selfex = path_to_str(&selfexe)?;
    args.next();
    if let Some(arg) = args.next() {
        match arg.as_str() {
            "probe" => {
                let (mut sa, sb) = UnixStream::pair()?;
                let fdx = UnixStream::connect("/run/recvfds.sock")?;
                fdx.send_fd(sb.as_raw_fd())?;
                let buf = b"test";
                sa.write_all(buf as &[_])?;
                println!("written");
            }
            "proxy" => {
                let mut fds = libsystemd::activation::receive_descriptors(true)?;
                dbg!(&fds);
                let fdx = fds.pop().unwrap();
                assert!(fdx.is_unix());
                let fdx = unsafe { UnixListener::from_raw_fd(fdx.into_raw_fd()) };
                let (conn, addr) = fdx.accept()?;
                let mut sb = unsafe { UnixStream::from_raw_fd(conn.recv_fd()?) };
                let mut text = String::new();
                sb.read_to_string(&mut text)?;
                dbg!(&text);
            }
            _ => unreachable!(),
        }
    } else {
        let mut service = ini::Ini::new();
        service
            .with_section(Some("Unit"))
            .set("Description", "the probe");
        service
            .with_section(Some("Service"))
            .set("ExecStart", format!("{} probe", &selfex));
        service.write_to_file("/etc/systemd/system/probe1.service")?;

        let mut socket = ini::Ini::new();
        socket
            .with_section(Some("Unit"))
            .set("Description", "to receive device FDs");
        socket
            .with_section(Some("Socket"))
            .set("ListenStream", "/run/recvfds.sock");
        socket.write_to_file("/etc/systemd/system/proxy1.socket")?;

        let mut service = ini::Ini::new();
        service
            .with_section(Some("Unit"))
            .set("Description", "the proxy")
            .set("Requires", "proxy1.socket")
            .set("After", "proxy1.socket");
        service
            .with_section(Some("Service"))
            .set("ExecStart", format!("{} proxy", &selfex));
        service.write_to_file("/etc/systemd/system/proxy1.service")?;

        let conn = zbus::blocking::Connection::system()?;
        let mg = systemd_zbus::ManagerProxyBlocking::new(&conn)?;
        mg.reload()?;
        mg.start_unit("probe1.service", Replace)?;
        mg.start_unit("proxy1.service", Replace)?;
    }

    Ok(())
}
