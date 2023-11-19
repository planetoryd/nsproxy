use anyhow::Result;
use nsproxy::{paths::PathState, sys::UserNS};

fn main() -> Result<()> {
    let path = PathState::default()?;
    let usern = UserNS(&path);
    dbg!(usern.paths());
    let deinit = usern.deinit();
    dbg!(&deinit);
    let mut a = std::env::args();
    a.next();
    if a.next().is_none() {
        usern.init()?;
    }

    Ok(())
}
