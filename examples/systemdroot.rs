use std::{
    future::Future,
    io::{Read, Write},
    os::{
        fd::{AsRawFd, FromRawFd, IntoRawFd},
        unix::net::{UnixListener, UnixStream},
    },
};

use anyhow::Result;
use libsystemd::activation::IsType;
use nsproxy::{aok, path_to_str};
use passfd::FdPassingExt;
use systemd_zbus::{ManagerProxy, Mode::Replace};

#[tokio::main]
async fn main() -> Result<()> {
    let conn = zbus::Connection::system().await?;
    let mg = ManagerProxy::new(&conn).await?;
    dbg!(mg.start_unit("probe5.service", Replace).await?);
    // it prompts the user. conn doesnot fail
    Ok(())
}