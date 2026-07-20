#[derive(Debug)]
pub enum Error {
    ConnectionFailed(String),
    DataAccessError(u8),
    ParseError(String),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::ConnectionFailed(msg) => write!(f, "Connection failed: {}", msg),
            Error::DataAccessError(code) => write!(f, "Data access error: {}", code),
            Error::ParseError(msg) => write!(f, "Parse error: {}", msg),
        }
    }
}

impl std::error::Error for Error {}
