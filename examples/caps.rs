use nix::unistd::{fork, ForkResult};

fn main() {
    let caps = capctl::CapState::get_current().unwrap();
    dbg!(&caps);

    match unsafe { fork() }.unwrap() {
        ForkResult::Child => {
            let caps = capctl::CapState::get_current().unwrap();
            dbg!(&caps);
        }
        _ => (),
    }
}
