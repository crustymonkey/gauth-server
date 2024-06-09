extern crate configparser;

use configparser::ini::Ini;
use std::path::Path;

pub fn get_config(path: &Path) -> Ini {
    let mut conf = Ini::new();

    conf.load(path).expect(&format!(
        "Failed to load config from path: {}",
        path.to_string_lossy()
    ));

    return conf;
}
