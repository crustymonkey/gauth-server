use std::error::Error;
use std::fmt;

#[derive(Debug)]
pub struct InvalidReqBody {
    error: String,
}

impl InvalidReqBody {
    pub fn new(error: &str) -> Self {
        return Self { error: error.to_string() };
    }
}

impl Error for InvalidReqBody {}
unsafe impl Send for InvalidReqBody {}
impl fmt::Display for InvalidReqBody {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        return write!(f, "{}", &self.error);
    }
}