use std::os::unix::net::UnixStream;

use anyhow::Result;
use passfd::FdPassingExt;
use systemd_zbus::Mode::Replace;

fn main() -> Result<()> {
    let mut args = std::env::args();
    args.next();
    if let Some(arg) = args.next() {
        match arg.as_str() {
            "probe" => {
                let (sa, sb) = UnixStream::pair()?;
                let fdx = UnixStream::connect("/run/recvfds.sock")?;
                fdx.send_fd(fd)
            }
            "proxy" => {
                let fds = libsystemd::activation::receive_descriptors(true)?;
                dbg!(&fds);
            }
            _ => unreachable!(),
        }
    } else {
        let mut service = ini::Ini::new();
        service
            .with_section(Some("Unit"))
            .set("Description", "the probe");
        service.with_section(Some("Service")).set(
            "ExecStart",
            "/space/nsproxy-project/nsproxy/target/debug/examples/systemd probe",
        );
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
        service.with_section(Some("Service")).set(
            "ExecStart",
            "/space/nsproxy-project/nsproxy/target/debug/examples/systemd proxy",
        );
        service.write_to_file("/etc/systemd/system/proxy1.service")?;

        let conn = zbus::blocking::Connection::system()?;
        let mg = systemd_zbus::ManagerProxyBlocking::new(&conn)?;
        mg.start_unit("probe1.service", Replace)?;
        mg.start_unit("proxy1.service", Replace)?;
    }

    Ok(())
}
