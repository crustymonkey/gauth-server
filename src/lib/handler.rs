use anyhow::Result;
use bodyparser::Json;
use configparser::ini::Ini;
use google_authenticator::{GoogleAuthenticator, ErrorCorrectionLevel::Medium};
use iron::{prelude::*, Handler, error, status, mime};
use json::object;
use router::Router;
use std::sync::{Arc, Mutex};
use super::{db::DB, error::InvalidReqBody};

// shortcut type
type Callback = Box<dyn Fn(&mut Request, Arc<Ini>, Arc<Mutex<DB>>)
    -> IronResult<Response>>;

pub struct AuthHandler {
    config: Arc<Ini>,
    db: Arc<Mutex<DB>>,
    func: Callback,  // Callback func
}

impl AuthHandler {
    fn new(
        config: Arc<Ini>,
        db: Arc<Mutex<DB>>,
        func: Callback,  // Callback func
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
        let body = match req.get::<Json>() {
            Ok(Some(b)) => b,
            _ => {
                error!("Unable to parse request body");
                return Err(IronError::new(
                    InvalidReqBody::new("Invalid JSON body"),
                    (status::BadRequest, "Invalid JSON request body")
                ));
            }
        };
        let api_key = body["api_key"].as_str();
        validate_params(&[api_key])?;
        let api_key = api_key.unwrap();

        debug!("API KEY: {:?}", api_key);
        {
            // I need a mutable reference to the database for operations
            let mut mdb = self.db.lock().unwrap();

            if !mdb.api_key_exists(api_key) {
                error!("Invalid api_key passed in: {}", api_key);
                return Err(IronError::new(
                    InvalidReqBody::new("Invalid api key"),
                    (status::BadRequest, "Invalid api key"),
                ));
            }
        }

        debug!("Validated the API key for the request");
        return (*self.func)(req, self.config.clone(), self.db.clone());
    }
}

unsafe impl Send for AuthHandler {}
unsafe impl Sync for AuthHandler {}

pub fn get_router_w_routes(conf: Arc<Ini>, db: Arc<Mutex<DB>>) -> Result<Router> {
    let mut router = Router::new();

    router.post(
        "/create",
        AuthHandler::new(conf.clone(), db.clone(), Box::new(create)),
        "create",
    );

    router.post(
        "/verify",
        AuthHandler::new(conf.clone(), db.clone(), Box::new(verify)),
        "verify",
    );

    router.post(
        "/qr",
        AuthHandler::new(conf.clone(), db.clone(), Box::new(qr)),
        "qr",
    );

    router.post(
        "/qr_url",
        AuthHandler::new(conf.clone(), db.clone(), Box::new(qr_url)),
        "qr_url",
    );

    return Ok(router);
}

/*
 * Below here are the actual handler functions for the requests
 */

 /// This consists of a reuqest to create a new secret. The request body
 /// should look like:
 /// ```
 /// {
 ///    "api_key": "abc123",
 ///    "ident": "key identifier"
 /// }
 /// ```
 /// 
 /// The response will be:
 /// ```
 /// {
 ///    "status": true
 /// }
 /// ```
fn create(req: &mut Request, conf: Arc<Ini>, db: Arc<Mutex<DB>>) -> IronResult<Response> {
    let g = GoogleAuthenticator::new();
    let body = match req.get::<Json>() {
        Ok(Some(b)) => b,
        _ => {
            error!("Unable to parse request body");
            return Err(IronError::new(
                InvalidReqBody::new("Invalid JSON body"),
                (status::BadRequest, "Invalid JSON request body")
            ));
        }
    };

    let ident = body["ident"].as_str();
    let len = conf.getuint("auth", "secret_len") .unwrap().unwrap() as u8;
    let secret = g.create_secret(len);

    validate_params(&[ident])?;

    // I need a mutable reference to the database for operations
    let mut mdb = db.lock().unwrap();

    if let Err(_) = mdb.create_secret(ident.unwrap(), &secret) {
        return Err(IronError::new(
            error::HttpError::Method,
            (status::InternalServerError, "Database error"),
        ));
    }

    debug!("Secret added to db: {:?}", secret);

    return Ok(Response::with(
        (get_json_ct(), status::Ok, object!{status: true}.dump())
    ));
}

/// This will verify that a code is valid for the given identity (hostname)
/// caller.  The request body should look like:
/// ```
/// {
///     "api_key": "abc123",
///     "ident": "key identifier",
///     "code": 123456
/// }
/// ```
/// 
/// The response will be:
/// ```
/// {
///     "status": true|false,
///     "verified": true|false
/// }
/// ```
fn verify(req: &mut Request, _conf: Arc<Ini>, db: Arc<Mutex<DB>>) -> IronResult<Response> {
    let g = GoogleAuthenticator::new();
    let body = match req.get::<Json>() {
        Ok(Some(b)) => b,
        _ => {
            error!("Unable to parse request body");
            return Err(IronError::new(
                InvalidReqBody::new("Invalid JSON body"),
                (status::BadRequest, "Invalid JSON request body")
            ));
        }
    };

    let ident = body["ident"].as_str();
    let code = body["code"].as_str();

    validate_params(&[ident, code])?;

    let secret = match get_secret(ident.unwrap(), db) {
        Ok(sec) => sec,
        Err(e) => return Err(e),
    };

    let ret = g.verify_code(&secret, code.unwrap(), 0, 0);

    return Ok(Response::with(
        (get_json_ct(), status::Ok, object!{status: true, verified: ret}.dump())
    ));
}

/// This will create and return an SVG format and return it as a string.
/// The request should look like:
/// ```
/// {
///     "api_key": "abc123",
///     "ident": "key identifier",
///     "name": "name for code, could be company name",
///     "title": "title for the code"
/// }
///
//// The response will look like:
/// ```
/// {
///     "status": true,
///     "qr_code": "SVG string"
/// }
/// ```
fn qr(req: &mut Request, conf: Arc<Ini>, db: Arc<Mutex<DB>>) -> IronResult<Response> {
    let goog = GoogleAuthenticator::new();
    let (_, name, title, secret, width, height) = 
        match get_qr_data(req, conf.clone(), db) {
            Ok(t) => t,
            Err(e) => return Err(e),
        };

    let ret = match goog.qr_code(
        &secret,
        &name,
        &title,
        width,
        height,
        Medium
    ) {
        Ok(s) => s,
        Err(e) => {
            error!("Error creating qr code: {}", e);
            return Err(IronError::new(
                error::HttpError::Method,
                (status::InternalServerError, "Failed to create qr code"),
            ));
        },
    };

    return Ok(Response::with(
        (get_json_ct(), status::Ok, object!{status: true, qr_code: ret}.dump())
    ));
}

/// This will create and return a URL string for a rendered qr code.
/// The request should look like:
/// ```
/// {
///     "api_key": "abc123",
///     "ident": "key identifier",
///     "name": "name for code, could be company name",
///     "title": "title for the code"
/// }
/// ```
/// 
/// The response will look like:
/// ```
/// {
///     "status": true,
///     "qr_code_url": "http://somewhere.com"
/// }
/// ```
fn qr_url(
    req: &mut Request,
    conf: Arc<Ini>,
    db: Arc<Mutex<DB>>,
) -> IronResult<Response> {
    let goog = GoogleAuthenticator::new();
    let (_, name, title, secret, width, height) = 
        match get_qr_data(req, conf.clone(), db) {
            Ok(t) => t,
            Err(e) => return Err(e),
        };

    let ret = goog.qr_code_url(
        &secret,
        &name,
        &title,
        width,
        height,
        Medium
    );

    return Ok(Response::with(
        (get_json_ct(), status::Ok, object!{status: true, qr_code_url: ret}.dump())
    ));
}

/*
 * Utility functions
 */

/// Simple helper function for getting the secret for a given ident from the
/// db
fn get_secret(ident: &str, db: Arc<Mutex<DB>>) -> Result<String, IronError> {
    // I need a mutable reference to the database for operations
    let mut mdb = db.lock().unwrap();

    let secret = match mdb.get_secret(ident) {
        Ok((_, sec)) => sec,
        Err(e) => {
            error!("Error getting secret: {}", e);
            return Err(IronError::new(
                error::HttpError::Method,
                (status::InternalServerError, "Database error"),
            ));
        },
    };

    return Ok(secret);
}

/// Helper function to get all the necessary data for qr code requests
fn get_qr_data(
    req: &mut Request,
    conf: Arc<Ini>,
    db: Arc<Mutex<DB>>,
) -> Result<(String, String, String, String, u32, u32), IronError> {
    let body = match req.get::<Json>() {
        Ok(Some(b)) => b,
        _ => {
            error!("Unable to parse request body");
            return Err(IronError::new(
                InvalidReqBody::new("Invalid JSON body"),
                (status::BadRequest, "Invalid JSON request body")
            ));
        }
    };

    let ident = body["ident"].as_str();
    let name = body["name"].as_str();
    let title = body["title"].as_str();

    validate_params(&[ident, name, title])?;

    let width = conf.getuint("auth", "default_width")
        .unwrap().unwrap() as u32;
    let height = conf.getuint("auth", "default_height")
        .unwrap().unwrap() as u32;

    let secret = match get_secret(ident.unwrap(), db) {
        Ok(sec) => sec,
        Err(e) => return Err(e),
    };

    return Ok((
        ident.unwrap().to_string(),
        name.unwrap().to_string(),
        title.unwrap().to_string(),
        secret,
        width,
        height,
    ));
}

/// Utility function used to return a JSON content type for responses
fn get_json_ct() -> mime::Mime {
    return "application/json".parse::<mime::Mime>().unwrap();
}

/// This is just a convenience function for validating that parameters are
/// correctly passed in
fn validate_params<T>(params: &[Option<T>]) -> Result<(), IronError> {
    for p in params.iter() {
        // Just go through the params and check for something being none,
        // which will be an error
        if p.is_none() {
            return Err(IronError::new(
                InvalidReqBody::new("Request parameters missing"),
                (status::BadRequest, "Request parameters missing"),
            ));
        }
    }

    return Ok(());
}