use anyhow::Result;
use configparser::ini::Ini;
use google_authenticator::GoogleAuthenticator;
use iron::{prelude::*, Handler, error, status};
use log::{error, debug};
use router::Router;
use std::sync::Arc;
use super::db::DB;
use params::{Map, Params, Value};

const API_SECTION: &str = "api_allowed";
const API_KEY: &str = "api_key";

pub struct AuthHandler {
    config: Arc<Ini>,
    db: Arc<DB>,
    func: Box<dyn Fn(&mut Request, Arc<Ini>, Arc<DB>) -> IronResult<Response>>,
}

impl AuthHandler {
    fn new(
        config: Arc<Ini>,
        db: Arc<DB>,
        func: Box<dyn Fn(&mut Request, Arc<Ini>, Arc<DB>) -> IronResult<Response>>,
    ) -> Self {
        return Self { config, db, func };
    }
}

impl Handler for AuthHandler {
    fn handle(&self, req: &mut Request) -> IronResult<Response> {
        /*
        let r = req.extensions.get::<Router>().unwrap();
        let api_key = r.find(API_KEY);
        */

        let map = req.get::<Params>().unwrap();
        let api_key = map.find(&[API_KEY]);

        debug!("API KEY: {:?}", api_key);

        // Check if there's an api_key in query params
        if api_key.is_none() {
            error!("No API key was supplied from {}", req.remote_addr.ip());
            return Err(IronError {
                error: Box::new(error::HttpError::Header),
                response: Response::with(
                    (status::Forbidden, "No API key supplied\n"),
                )
            });
        }

        // Now check if the API key is valid
        let api_key_str = match api_key.unwrap() {
            Value::String(s) => s.to_owned(),
            _ => {
                error!("Could not get string value for api_key");
                String::from("")
            },
        };
        debug!("API key str: {:?}", api_key_str);

        let conf_key = self.config.get(API_SECTION, &api_key_str);
        //let conf_key: Option<String> = None;
        if conf_key.is_none() {
            error!("Invalid API key supplied from {}", req.remote_addr.ip());
            return Err(IronError {
                error: Box::new(error::HttpError::Header),
                response: Response::with(
                    (status::Forbidden, "API key not found\n"),
                )
            });
        }

        debug!("Validated the API key for {}", conf_key.unwrap());
        return (*self.func)(req, self.config.clone(), self.db.clone());
    }
}

unsafe impl Send for AuthHandler {}
unsafe impl Sync for AuthHandler {}

pub fn get_router_w_routes(conf: Arc<Ini>, db: Arc<DB>) -> Result<Router> {
    let mut router = Router::new();

    router.get(
        "/create",
        AuthHandler::new(conf.clone(), db.clone(), Box::new(create)),
        "create",
    );

    router.get(
        "/verify",
        AuthHandler::new(conf.clone(), db.clone(), Box::new(verify)),
        "verify",
    );

    router.get(
        "/qr",
        AuthHandler::new(conf.clone(), db.clone(), Box::new(qr)),
        "qr",
    );

    return Ok(router);
}

/*
 * Below here are the actual handler functions for the requests
 */
fn create(req: &mut Request, conf: Arc<Ini>, db: Arc<DB>) -> IronResult<Response> {
    let g = GoogleAuthenticator::new();
    let params = req.get::<Params>().unwrap();
    let stmp = get_param_string(&params, "secret");

    let secret = match stmp {
        Some(s) => s,
        None => {
            let len = conf.getuint("auth", "secret_len")
                .unwrap().unwrap() as u8;
            g.create_secret(len)
        }
    };

    debug!("Got secret: {:?}", secret);

    return Ok(Response::with((status::Ok, "OK")));
}

fn verify(req: &mut Request, conf: Arc<Ini>, db: Arc<DB>) -> IronResult<Response> {
    return Ok(Response::with((status::Ok, "OK")));
}

fn qr(req: &mut Request, conf: Arc<Ini>, db: Arc<DB>) -> IronResult<Response> {
    return Ok(Response::with((status::Ok, "OK")));
}

fn get_param_string(params: &Map, search: &str) -> Option<String> {
    return match params.find(&[search]) {
        Some(val) => match val {
            Value::String(s) => Some(s.to_owned()),
            _ => None,
        },
        None => None,
    };
}