//! The error types for MSP.
use std::result;
use std::fmt;
use std::error;
use cookie_factory::GenError;
use nom;
use mdp;

#[derive(Debug)]
pub enum Error {
    ParseError(nom::ErrorKind),
    ParseIncomplete(nom::Needed),
    EncodeError(GenError),
    Mdp(mdp::error::Error),
    MspConnectTimeout,
    MspConnectError
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::ParseError(ref err) => fmt::Debug::fmt(err, f),
            Error::ParseIncomplete(i) => match i {
                nom::Needed::Unknown => {
                    write!(f, "Missing unknown amount of bytes while deserializing.")
                }
                nom::Needed::Size(s) => {
                    write!(f, "Missing {:?} bytes of data while deserializing.", s)
                }
            },
            Error::EncodeError(ref err) => fmt::Debug::fmt(err, f),
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
            Error::EncodeError(_) => "Error while serializing to buffer.",
            Error::Mdp(ref err) => err.description(),
            Error::MspConnectTimeout => "MSP connection timed out.",
            Error::MspConnectError => "MSP connection error.",
        }
    }

    fn cause(&self) -> Option<&error::Error> {
        match *self {
            Error::ParseError(_) => None,
            Error::ParseIncomplete(_) => None,
            Error::EncodeError(_) => None,
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

impl<'a> From<nom::Err<&'a [u8]>> for Error {
    fn from(err: nom::Err<&'a [u8]>) -> Error {
        match err {
            nom::Err::Incomplete(needed) => Error::ParseIncomplete(needed),
            nom::Err::Error(e) | nom::Err::Failure(e) => Error::ParseError(e.into_error_kind())
        }
    }
}

impl From<GenError> for Error {
    fn from(err: GenError) -> Error {
        Error::EncodeError(err)
    }
}

impl From<Error> for () {
    fn from(_: Error) -> () {}
}

pub type Result<T> = result::Result<T, Error>;
//
// Alias to provide an analogue to IResult, except for the encoding pipeline.
pub type GResult<T> = result::Result<T, GenError>;
