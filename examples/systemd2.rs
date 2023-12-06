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

// Run with sudo
fn main() -> Result<()> {
    // let pre = asyncsingle(async { zbus::Connection::session().await })?;
    // asyncsingle(async move {
    //     let mg = ManagerProxy::new(&pre).await?;
    //     mg.reload().await?;
    //     println!("reloaded");
    //     aok!()

    // })?;

    let rt =  tokio::runtime::Builder::new_current_thread()
    .enable_all()
    .build()?;

    let pre = rt.block_on(async {
        zbus::Connection::session().await
    })?;

    println!("conn");

    rt.block_on(async {
        let mg = ManagerProxy::new(&pre).await?;
        mg.reload().await?;
        println!("reloaded");
        aok!()
    })?;

    // asyncsingle(async {
    //     let pre = zbus::Connection::session().await?;
    //     println!("conn");
    //     let mg = ManagerProxy::new(&pre).await?;
    //     mg.reload().await?;
    //     println!("reloaded");
    //     aok!()
    // });
    Ok(())
}

fn asyncsingle<F>(fut: F) -> F::Output
where
    F: Future + Send + 'static,
    F::Output: Send + 'static,
{
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(fut)
}
