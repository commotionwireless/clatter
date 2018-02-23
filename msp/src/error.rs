//! The error types for MSP.
use std::result;
use std::fmt;
use std::error;
use nom;
use mdp;

#[derive(Debug)]
pub enum Error {
    ParseError(nom::ErrorKind),
    ParseIncomplete(nom::Needed),
    Mdp(mdp::error::Error),
    MspConnectTimeout,
    MspConnectError
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::ParseError(ref err) => err.fmt(f),
            Error::ParseIncomplete(i) => match i {
                nom::Needed::Unknown => {
                    write!(f, "Missing unknown amount of bytes while deserializing.")
                }
                nom::Needed::Size(s) => {
                    write!(f, "Missing {:?} bytes of data while deserializing.", s)
                }
            },
            Error::Mdp(ref err) => err.fmt(f),
            Error::MspConnectTimeout => write!(f, "MSP connection timed out."),
            Error::MspConnectError => write!(f, "MSP connection error."),
        }
    }
}

impl error::Error for Error {
    fn description(&self) -> &str {
        match *self {
            Error::ParseError(ref err) => err.description(),
            Error::ParseIncomplete(_) => "Missing bytes while deserializing.",
            Error::Mdp(ref err) => err.description(),
            Error::MspConnectTimeout => "MSP connection timed out.",
            Error::MspConnectError => "MSP connection error.",
        }
    }

    fn cause(&self) -> Option<&error::Error> {
        match *self {
            Error::ParseError(ref err) => Some(err),
            Error::ParseIncomplete(_) => None,
            Error::Mdp(ref err) => Some(err),
            Error::MspConnectTimeout => None,
            Error::MspConnectError => None
        }
    }
}

impl From<mdp::error::Error> for Error {
    fn from(err: mdp::error::Error) -> Error {
        Error::Mdp(err)
    }
}

impl From<Error> for () {
    fn from(_: Error) -> () {}
}

pub type Result<T> = result::Result<T, Error>;
