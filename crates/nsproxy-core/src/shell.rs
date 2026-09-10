use std::{
    collections::{BTreeSet, HashMap, VecDeque},
    env::{current_dir, var},
    ffi::{CStr, CString, OsString},
    os::unix::{
        process::CommandExt,
        raw::{gid_t, uid_t},
    },
    path::{Path, PathBuf},
    str::FromStr,
};

use anyhow::{anyhow, bail};
use nix::sched::CloneFlags;
use nix::unistd::{Gid, chdir, execve, getegid, getresuid, setgroups, setresgid, setresuid};
use nsproxy_common::NSSource;
use nsproxy_common::UID_HINT_VAR;
use serde::{Deserialize, Serialize};
use tracing::{info, warn};
use uzers::{Group, os::unix::UserExt};

use crate::{
    env::{
        CommandEnv, ENV_CONTAINER, ENV_DBUS_SESSION_BUS_ADDRESS, ENV_DBUS_SYSTEM_BUS_ADDRESS,
        ENV_NS, ENV_PROFILE,
    },
    prelude::*,
    sys::{Clone3Result, NSEnter, clone3},
};

/// Dedicated to spawning a shell that maximally pleases the user
/// what the user wants the uid of the shell to be, what groups to have

#[derive(Default)]
pub struct ShellPrefs {
    gids: Vec<Group>,
    gids_raw: BTreeSet<u32>,
    pub uid: Option<uid_t>,
    /// Main GID
    pub gid: Option<gid_t>,
    /// This can also just be a program despite the struct's name
    pub shell: Option<PathBuf>,
    /// The user wants to drop in a root shell
    /// Defaults to false.
    pub wants_root: bool,
    pub cwd: Option<PathBuf>,
    /// This is different from .shell because this may be late resolved
    /// The PATHS can be different in the user shell
    pub prefer_shell: Option<String>,
    args: Vec<CString>,
    env: VecDeque<CString>,
}

#[derive(clap::Parser, Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ShellArgs {
    /// Defaults to your currrent log-in user
    #[arg(short, long)]
    pub uid: Option<u32>,
    /// Also comes with defaults
    #[arg(short, long)]
    pub gid: Option<u32>,
    /// Any executable name; will be resolved the same way 'which' does
    #[arg(short, long)]
    pub shell: Option<String>,
    #[arg(long)]
    pub cwd: Option<PathBuf>,
    /// By default, the gids are taken from log-in default supplemental groups
    /// You can override the entire vector.
    #[arg(long, value_delimiter = ',')]
    pub gids: Vec<u32>,
    /// Command arguments (execve argv, excluding the program path)
    #[arg(long, num_args = 1..)]
    pub args: Vec<String>,
}

#[derive(clap::Parser, Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct EnterArgs {
    /// Defaults to your current login user
    #[arg(short, long)]
    pub uid: Option<u32>,
    /// Also comes with defaults
    #[arg(short, long)]
    pub gid: Option<u32>,
    #[arg(long)]
    pub cwd: Option<PathBuf>,
    /// Override the entire supplemental-group vector.
    #[arg(long, value_delimiter = ',')]
    pub gids: Vec<u32>,
    /// Executable and argv, after the `--` delimiter.
    #[arg(trailing_var_arg = true, required = true)]
    pub command: Vec<String>,
}

impl ShellPrefs {
    pub fn take_args(&mut self, args: ShellArgs) {
        if let Some(uid) = args.uid {
            self.uid = Some(uid);
        }
        if let Some(gid) = args.gid {
            self.gid = Some(gid);
        }
        if let Some(shell) = args.shell {
            self.prefer_shell = Some(shell);
        }
        if let Some(cwd) = args.cwd {
            self.cwd = Some(cwd);
        }
        if !args.gids.is_empty() {
            self.gids_raw = args.gids.into_iter().collect();
        }
        if !args.args.is_empty() {
            self.args = args
                .args
                .into_iter()
                .map(|arg| CString::new(arg).unwrap())
                .collect();
        }
    }

    pub fn take_enter_args(&mut self, args: EnterArgs) {
        self.uid = args.uid;
        self.gid = args.gid;
        self.cwd = args.cwd;
        if !args.gids.is_empty() {
            self.gids_raw = args.gids.into_iter().collect();
        }
        let mut command = args.command.into_iter();
        self.prefer_shell = command.next();
        self.args = command
            .map(|arg| CString::new(arg).expect("command arguments cannot contain NUL bytes"))
            .collect();
    }
    /// Explicit environment with no inheritance
    pub fn set_env_explicit(&mut self, mut env: HashMap<String, String>) -> Result<()> {
        // Auto-set HOME if not explicitly provided and we have a uid
        if !env.contains_key("HOME") && self.uid.is_some() {
            if let Some(user) = uzers::get_user_by_uid(self.uid.unwrap()) {
                env.insert(
                    "HOME".to_string(),
                    user.home_dir().to_string_lossy().to_string(),
                );
            }
        }

        let mut vec: VecDeque<CString> = Default::default();
        for (k, v) in env {
            vec.push_back(CString::new(format!("{}={}", k, v))?);
        }
        self.env = vec;
        Ok(())
    }

    /// Set environment with inheritance - apply env as overrides to existing environment
    pub fn set_env_with_inheritance(&mut self, overrides: HashMap<String, String>) -> Result<()> {
        // Auto-set HOME if not explicitly provided and we have a uid
        let mut final_overrides = overrides;
        if !final_overrides.contains_key("HOME") && self.uid.is_some() {
            if let Some(user) = uzers::get_user_by_uid(self.uid.unwrap()) {
                final_overrides.insert(
                    "HOME".to_string(),
                    user.home_dir().to_string_lossy().to_string(),
                );
            }
        }

        // Apply overrides to existing environment
        for (k, v) in final_overrides {
            // Remove any existing entry for this key
            self.env.retain(|env_entry| {
                if let Ok(s) = env_entry.to_str() {
                    !s.starts_with(&format!("{}=", k))
                } else {
                    true
                }
            });
            // Add the new value
            self.env.push_back(CString::new(format!("{}={}", k, v))?);
        }
        Ok(())
    }
    pub fn set_nsproxy_env(&mut self, browser_profile: Option<String>) {
        warn!(
            "setting env variable for brwoser profile {:?}",
            &browser_profile
        );
        let val = browser_profile.unwrap_or("UNSPEC".to_string());
        unsafe {
            std::env::set_var(ENV_PROFILE, &val);
        }
        self.env
            .push_front(CString::from_str(&format!("{}={}", ENV_PROFILE, val)).unwrap());
    }
    pub fn set_container_env(&mut self, profile_name: Option<&str>) {
        warn!(
            "setting env variable for container profile {:?}",
            &profile_name
        );
        let val = profile_name.unwrap_or("UNSPEC");
        unsafe {
            std::env::set_var(ENV_CONTAINER, val);
        }
        self.env
            .push_front(CString::from_str(&format!("{}={}", ENV_CONTAINER, val)).unwrap());
    }
    pub fn set_ns_env(&mut self, ns: Option<&str>) {
        warn!("setting env variable for netns {:?}", &ns);
        unsafe {
            std::env::set_var(ENV_NS, ns.unwrap_or("UNSPEC"));
        }
        self.env.push_front(
            CString::from_str(&format!("{}={}", ENV_NS, ns.unwrap_or("UNSPEC"))).unwrap(),
        );
    }
    pub fn set_dbus_session_bus_env(&mut self, address: &str) {
        unsafe {
            std::env::set_var(ENV_DBUS_SESSION_BUS_ADDRESS, address);
        }
        self.env.retain(|env_entry| {
            if let Ok(s) = env_entry.to_str() {
                !s.starts_with(&format!("{}=", ENV_DBUS_SESSION_BUS_ADDRESS))
            } else {
                true
            }
        });
        self.env.push_front(
            CString::from_str(&format!("{}={}", ENV_DBUS_SESSION_BUS_ADDRESS, address)).unwrap(),
        );
    }

    pub fn set_dbus_system_bus_env(&mut self, address: &str) {
        unsafe {
            std::env::set_var(ENV_DBUS_SYSTEM_BUS_ADDRESS, address);
        }
        self.env.retain(|env_entry| {
            if let Ok(s) = env_entry.to_str() {
                !s.starts_with(&format!("{}=", ENV_DBUS_SYSTEM_BUS_ADDRESS))
            } else {
                true
            }
        });
        self.env.push_front(
            CString::from_str(&format!("{}={}", ENV_DBUS_SYSTEM_BUS_ADDRESS, address)).unwrap(),
        );
    }

    /// Remove DBUS_*_BUS_ADDRESS from the spawn environment.
    /// Call this after `adjust()` to enforce Block mode — `adjust()` captures
    /// the parent env (which may include the host bus address) before we can
    /// check the profile's DbusMode.
    pub fn strip_dbus_env(&mut self) {
        self.env.retain(|env_entry| {
            if let Ok(s) = env_entry.to_str() {
                !s.starts_with(&format!("{}=", ENV_DBUS_SESSION_BUS_ADDRESS))
                    && !s.starts_with(&format!("{}=", ENV_DBUS_SYSTEM_BUS_ADDRESS))
            } else {
                true
            }
        });
        unsafe {
            std::env::remove_var(ENV_DBUS_SESSION_BUS_ADDRESS);
            std::env::remove_var(ENV_DBUS_SYSTEM_BUS_ADDRESS);
        }
    }
    /// Preferences are fetched from processes up the tree as early as possible, before subsequent operations
    pub fn adjust(&mut self) -> Result<()> {
        if self.uid == None {
            if let Ok(id) = var(UID_HINT_VAR) {
                self.uid = Some(id.parse()?)
            } else if let Ok(id) = var("SUDO_UID") {
                self.uid = Some(id.parse()?)
            } else {
                let res = getresuid()?;
                if !res.real.is_root() {
                    self.uid = res.real.as_raw().into();
                } else if let Ok(kde) = var("KDE_SESSION_UID") {
                    self.uid = Some(kde.parse()?);
                } else {
                    if self.wants_root && res.real.is_root() {
                        self.uid = Some(0);
                    }
                }
            }
        }
        if let Some(user) = self.uid {
            let user = uzers::get_user_by_uid(user).unwrap();
            let gid_in = { user.primary_group_id() };
            let gids = user.groups();
            if self.gids.len() == 0
                && let Some(gids) = gids
            {
                self.gids = gids;
            }
            if self.gid.is_none() {
                self.gid = Some(gid_in);
            } else {
                // let egid = getegid();
                // if egid.as_raw() != 0 {
                //     self.gid = Some(egid.as_raw())
                // } else {
                //     if !self.wants_root {
                //         bail!("can not decide gid to use");
                //     }
                // }
            }
            let ushell = user.shell().to_owned();
            self.shell = ushell.into();
        }
        if self.cwd.is_none() {
            self.cwd = current_dir()?.into();
        }
        let cmd_env = CommandEnv::default();
        let envs = cmd_env.capture();
        let mut vec: VecDeque<CString> = Default::default();
        for (k, v) in envs {
            vec.push_back(CString::new(format!(
                "{}={}",
                k.to_str().unwrap(),
                v.to_str().unwrap()
            ))?);
        }
        self.env = vec;
        if self.gids_raw.is_empty() {
            for g in &self.gids {
                self.gids_raw.insert(g.gid());
            }
        }
        aok!()
    }
    pub fn spawn(mut self) -> Result<Clone3Result> {
        if let Some(name) = &self.prefer_shell {
            self.shell = Some(which::which(name)?);
        }
        if let Some(cmd) = &self.shell {
            let clone = clone3::<false>(false, false)?;
            match &clone {
                Clone3Result::IsChild { tx } => {
                    let cmd = CString::new(cmd.to_str().unwrap())?;
                    if self.args.is_empty() {
                        self.args.push(cmd.clone());
                    } else if self.args.first().map(|c| c.as_c_str()) != Some(cmd.as_c_str()) {
                        self.args.insert(0, cmd.clone());
                    }
                    self.drop_privs()?;

                    if let Some(cwd) = &self.cwd {
                        // in some pivot root situation new cwd is not created
                        // TODO: might be bad.
                        let _ = chdir(cwd);
                    }

                    execve(cmd.as_c_str(), &self.args, self.env.make_contiguous());
                }
                Clone3Result::Parent {
                    child_pid,
                    child_pidfd,
                    tx,
                } => {}
            }
            Ok(clone)
        } else {
            bail!("no shell or program specified");
        }
    }

    pub fn spawn_in_ns(
        mut self,
        ns_alive: &crate::NsAlive,
        fallback_netns: &Path,
    ) -> Result<Clone3Result> {
        if let Some(name) = &self.prefer_shell {
            self.shell = Some(which::which(name)?);
        }
        if let Some(cmd) = &self.shell {
            let clone = clone3::<false>(false, false)?;
            match &clone {
                Clone3Result::IsChild { tx } => {
                    if let Some(child_pid) = ns_alive.child_pid {
                        let ns_source = nsproxy_common::NSSource::Pid(child_pid as i32);
                        ns_source.enter(CloneFlags::CLONE_NEWNS)?;
                        ns_source.enter(CloneFlags::CLONE_NEWNET)?;
                    } else {
                        let ns = nsproxy_common::NSSource::Path(fallback_netns.to_path_buf());
                        ns.enter(CloneFlags::CLONE_NEWNET)?;
                    }

                    let cmd = CString::new(cmd.to_str().unwrap())?;
                    if self.args.is_empty() {
                        self.args.push(cmd.clone());
                    } else if self.args.first().map(|c| c.as_c_str()) != Some(cmd.as_c_str()) {
                        self.args.insert(0, cmd.clone());
                    }
                    self.drop_privs()?;

                    if let Some(cwd) = &self.cwd {
                        let _ = chdir(cwd);
                    }

                    execve(cmd.as_c_str(), &self.args, self.env.make_contiguous());
                }
                Clone3Result::Parent {
                    child_pid,
                    child_pidfd,
                    tx,
                } => {
                    let _ = (child_pid, child_pidfd, tx);
                }
            }
            Ok(clone)
        } else {
            bail!("no shell or program specified");
        }
    }

    // pub async fn spawn_and_block(mut self) -> Result<()> {
    //     if let Some(name) = &self.prefer_shell {
    //         self.shell = Some(which::which(name)?);
    //     }
    //     if let Some(cmd) = &self.shell {
    //         let mut cmd = std::process::Command::new(cmd);
    //         let uid = self.uid.ok_or(anyhow!("can not find suitable uid"))?;
    //         cmd.uid(uid);
    //         let gids: Vec<_> = self.gids_raw.iter().collect();
    //         warn!("spawn process with gids {:?}", &gids);
    //         if let Some(gid) = self.gid {
    //             cmd.gid(gid);
    //         }
    //         cmd.groups(&gids.iter().map(|k| **k).collect::<Vec<u32>>());
    //         if let Some(cwd) = &self.cwd {
    //             cmd.current_dir(cwd);
    //         }
    //         let mut acmd = tokio::process::Command::from(cmd);
    //         let mut c = acmd.spawn()?;
    //         c.wait().await;
    //     } else {
    //         warn!("no shell or program specified");
    //     }
    //     aok!()
    // }
    pub fn drop_privs(&self) -> Result<()> {
        info!("drop privs, gids to {:?}", self.gids_raw);
        setgroups(
            &self
                .gids_raw
                .iter()
                .map(|g| Gid::from_raw(*g))
                .collect::<Vec<_>>(),
        )?;
        let g = self.gid.unwrap().into();
        setresgid(g, g, g);
        if let Some(uid) = self.uid {
            let u = uid.into();
            setresuid(u, u, u)?;
        }

        Ok(())
    }
}
