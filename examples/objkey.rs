use std::collections::HashMap;

use nsproxy::data::UniqueFile;
use serde_json::to_string_pretty;

fn main() {
    // possible to serialze struct as keys ?
    let k = UniqueFile {
        ino: 2222,
        dev: 3444,
    };
    let mut m = HashMap::new();
    m.insert(k, 5);
    let sx = to_string_pretty(&m).unwrap();
    println!("{}", sx);
    let p: HashMap<UniqueFile, i32> = serde_json::from_str(&sx).unwrap();
    dbg!(p);
}
