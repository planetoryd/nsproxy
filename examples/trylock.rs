use std::time::Duration;

use fs4::FileExt;



fn main() -> anyhow::Result<()> {
    let f = std::fs::File::create("./random.file").unwrap();
    println!("wait");
    f.try_lock_exclusive()?;
    println!("locked");
    std::thread::sleep(Duration::from_secs(2000));
    Ok(())
}
