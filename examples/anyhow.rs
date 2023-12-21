use anyhow::{Result, bail};

fn main() -> Result<()> {
    // println!("{}", errrr());
    // println!("{}", errrr());
    if let Err(inn) = errrr(){
        println!("{}", inn); // This prints no backtrace
        println!("{:?}", inn); // This prints no backtrace
    }
    Ok(())
}

fn errrr() -> Result<()> {
    Err(std::io::Error::from_raw_os_error(2).into())
}

