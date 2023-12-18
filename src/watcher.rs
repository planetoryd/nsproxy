use anyhow::{anyhow, Ok, Result};
use futures::StreamExt;
use inotify::{Event, EventMask, WatchMask};
use std::result::Result as stdRes;
use std::{
    collections::HashSet,
    ffi::OsString,
    os::fd::AsRawFd,
    path::{Path, PathBuf},
};
use tokio::sync::mpsc::Sender;
use tokio::{fs, io::AsyncReadExt, sync::mpsc::UnboundedSender};

use crate::flatpak::FlatpakID;

#[derive(Default)]
pub struct FlatpakWatcher {
    seen_pid: HashSet<Pid>,
}

#[derive(Hash, PartialEq, Eq)]
pub struct Pid(pub u32);

pub struct FEvent {
    pub pid: u32,
    pub flatpak: FlatpakID,
}

impl FEvent {
    pub fn name(&self) -> String {
        format!("{}_{}", self.flatpak.0, self.pid)
    }
}

impl FlatpakWatcher {
    pub async fn daemon(mut self, uid: u32, sx: Sender<FEvent>) -> Result<()> {
        let flatpak_dir = PathBuf::from(format!("/run/user/{}/.flatpak/", uid));
        let mut inoti = inotify::Inotify::init()?;
        inoti
            .watches()
            .add(&flatpak_dir, WatchMask::CLOSE_NOWRITE)?;
        let mut buf = [0; 1024];
        let mut stream = inoti.into_event_stream(&mut buf)?;
        while let Some(event_or_error) = stream.next().await {
            // event that is triggered for each `flatpak run` (each run creates a new instance)
            // dir name is instance_id.
            // event: Event { wd: WatchDescriptor { id: 1, fd: (Weak) }, mask: CREATE | ISDIR, cookie: 0, name: Some("2005139353") }
            // pid file -> bwrap --args 41 com.github.tchx84.Flatseal
            match event_or_error {
                stdRes::Ok(ev) => {
                    self.process_ev(ev, &flatpak_dir, &sx).await?;
                }
                Err(e) => {
                    log::error!("fs watcher, {:?}", e);
                }
            }
        }
        Ok(())
    }
    async fn process_ev(
        &mut self,
        ev: Event<OsString>,
        flatpak_dir: &PathBuf,
        sx: &Sender<FEvent>,
    ) -> Result<()> {
        if let Some(name) = ev.name {
            let name = name.to_string_lossy().into_owned();
            if let Result::Ok(num) = name.parse::<u32>() {
                let p = Pid(num);
                if self.seen_pid.contains(&p) {
                    // skip
                } else {
                    if ev
                        .mask
                        .intersects(EventMask::ISDIR | EventMask::CLOSE_NOWRITE)
                    {
                        let mut instance_dir = flatpak_dir.clone();
                        instance_dir.push(name);

                        let mut info = instance_dir.clone();
                        info.push("info");

                        if !info.exists() {
                            return Ok(());
                        }

                        let mut info_file = tokio::fs::File::open(info).await?;
                        let mut instnace_info_str = String::new();
                        info_file.read_to_string(&mut instnace_info_str).await?;

                        self.seen_pid.insert(p);
                        let c = ini::Ini::load_from_str(&instnace_info_str).unwrap();
                        let s_app = c
                            .section(Some("Application"))
                            .ok_or(anyhow::anyhow!("flatpak section missing"))?;
                        let flatpak_id = s_app
                            .get("name")
                            .ok_or(anyhow::anyhow!("unexpected flatpak data. name missing"))?;
                        let flatpak_id = FlatpakID(flatpak_id.to_owned());
                        let pid_f = Self::read_pid_file_from_dir(&instance_dir).await?.unwrap();
                        let proc = procfs::process::Process::new(pid_f.parse()?)?;
                        let maint = proc.task_main_thread()?;
                        let children = maint.children()?;
                        anyhow::ensure!(children.len() >= 1);
                        let the_pid = children[0] as u32;

                        log::warn!(
                            "Found new flatpak process pid {} of {}",
                            the_pid,
                            flatpak_id.0
                        );

                        sx.send(FEvent {
                            pid: the_pid,
                            flatpak: flatpak_id,
                        })
                        .await
                        .map_err(|_| anyhow!("send fail"))?;
                    }
                }
            }
        }
        Ok(())
    }
    async fn read_pid_file_from_dir(dir_path: &Path) -> Result<Option<String>> {
        let mut pid_file_contents: Option<String> = None;
        let mut entries = fs::read_dir(dir_path).await?;
        while let Some(entry) = entries.next_entry().await? {
            if let Some(file_name) = entry.file_name().to_str() {
                if file_name.contains("pid") {
                    let file_path = entry.path();
                    pid_file_contents = Some(fs::read_to_string(file_path).await?);
                    break;
                }
            }
        }
        Ok(pid_file_contents)
    }
}
