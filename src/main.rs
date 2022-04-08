extern crate chrono;
#[macro_use] extern crate log;

mod lib;

use anyhow::Result;
use clap::Parser;
use configparser::ini::Ini;
use iron::prelude::*;
use std::path::PathBuf;
use std::process::exit;
use lib::config::get_config;
use lib::handler::get_router_w_routes;
use lib::db::DB;

#[derive(Parser, Debug)]
#[clap(author="Jay Deiman", version, about="", long_about=None)]
struct Args {
    #[clap(short, long, parse(from_os_str),
        default_value="/etc/gauth/config.ini",
        name="PATH",
        help="The path to the config file",
    )]
    config: PathBuf,
    #[clap(short='a', long="create-api-key",
        default_value="",
        help="Supply a hostname to create an api key.  The new key will \
            be printed to stdout.")]
    host: String,
    #[clap(short='D', long)]
    debug: bool,
}

static LOGGER: GlobalLogger = GlobalLogger;

struct GlobalLogger;

/// This implements the logging to stderr from the `log` crate
impl log::Log for GlobalLogger {
    fn enabled(&self, meta: &log::Metadata) -> bool {
        return meta.level() <= log::max_level();
    }

    fn log(&self, record: &log::Record) {
        if self.enabled(record.metadata()) {
            let d = chrono::Local::now();
            eprintln!(
                "{} - {} - {}:{} {} - {}",
                d.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
                record.level(),
                record.file().unwrap(),
                record.line().unwrap(),
                record.target(),
                record.args(),
            );
        }
    }

    fn flush(&self) {}
}

/// Create a set of CLI args via the `clap` crate and return the matches
fn get_args() -> Args {
    return Args::parse();
}

/// Set the global logger from the `log` crate
fn setup_logging(args: &Args) {
    let l = if args.debug {
        log::LevelFilter::Debug
    } else {
        log::LevelFilter::Info
    };

    log::set_logger(&LOGGER).unwrap();
    log::set_max_level(l);
}

fn get_db_params(conf: &Ini) -> String {
    let ret = format!(
        "user={} password={} dbname={} sslmode={} host={} port={}",
        conf.get("db", "user").unwrap(),
        conf.get("db", "password").unwrap(),
        conf.get("db", "dbname").unwrap(),
        conf.get("db", "sslmode").unwrap(),
        conf.get("db", "host").unwrap(),
        conf.get("db", "port").unwrap(),
    );

    return ret;
}

fn create_api_key(db: &mut DB, host: &str) -> Result<String> {
    use rand::prelude::*;
    let key: String = thread_rng()
        .sample_iter(&rand::distributions::Alphanumeric)
        .take(32)
        .map(char::from)
        .collect();
    db.add_api_key(host, &key)?;

    return Ok(key);
}

fn main() {
    let args = get_args();
    setup_logging(&args);
    let conf = get_config(&args.config);
    let db_params = get_db_params(&conf);
    let mut db = DB::new(&db_params);

    if !args.host.is_empty() {
        debug!("Creating a new API key for host {}", &args.host);
        let key = create_api_key(
            &mut db,
            &args.host,
        ).unwrap();
        println!("New API key for {}: {}", &args.host, &key);
        exit(0);
    }

    let bind_str = format!(
        "{}:{}",
        conf.get("main", "bind_ip").unwrap(),
        conf.getint("main", "port").unwrap().unwrap(),
    );

    let routes = get_router_w_routes(conf, db).unwrap();

    Iron::new(routes).http(&bind_str).unwrap();

}