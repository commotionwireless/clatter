use std::io;
use std::result;
use std::fmt;
use std::error;
use nom;

#[derive(Debug)]
pub enum Error {
    Io(io::Error),
    ParseError(nom::ErrorKind),
    ParseIncomplete(nom::Needed),
    FrameNeedsDeserialized,
    FrameNeedsSerialized,
    PacketNeedsPlain,
    PacketNeedsEncrypted,
    PacketNeedsSigned,
    FrameFull,
    FrameTooLarge,
    PacketBadTtl(u8),
    PacketBadLen(usize),
    PayloadDeserializeEncrypted,
    Encrypt,
    Decrypt,
    Verify,
    ConvertPublicKey,
    ConvertPrivateKey,
    OverlayInvalidIP,
    RoutingTableInvalid,
    QueueCongestion
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::Io(ref err) => err.fmt(f),
            Error::ParseError(ref err) => err.fmt(f),
            Error::ParseIncomplete(i) => {
                match i {
                    nom::Needed::Unknown => {
                        write!(f, "Missing unknown amount of bytes while deserializing.")
                    }
                    nom::Needed::Size(s) => write!(f, "Missing {:?} bytes data while deserializing.", s),
                }
            },
            Error::FrameNeedsDeserialized => write!(f, "Function was passed an already serialized frame."),
            Error::FrameNeedsSerialized => write!(f, "Function was passed an already deserialized frame."),
            Error::PacketNeedsPlain => write!(f, "Function needs a plaintext frame but was passed some other type."),
            Error::PacketNeedsEncrypted => write!(f, "Function needs an encrypted frame but was passed some other type."),
            Error::PacketNeedsSigned => write!(f, "Function needs a signed frame but was passed some other type."),
            Error::FrameFull => write!(f, "The current frame cannot take the specified packet(s) and remain under the MTU."),
            Error::FrameTooLarge => write!(f, "The current frame is too large for the MTU."),
            Error::PacketBadTtl(n) => write!(f, "The packet's TTL of {:?} is not within the valid range.", n),
            Error::PacketBadLen(n) => write!(f, "The packet's data length of {:?} is not within the valid range.", n),
            Error::PayloadDeserializeEncrypted => write!(f, "Error deserializing a decrypted payload."),
            Error::Encrypt => write!(f, "Error encrypting payload."),
            Error::Decrypt => write!(f, "Error decrypting payload."),
            Error::Verify => write!(f, "Error verifying signed payload."),
            Error::ConvertPublicKey => write!(f, "Error transforming public signing key to crypto key."),
            Error::ConvertPrivateKey => write!(f, "Error transforming private signing key to crypto key."),
            Error::OverlayInvalidIP => write!(f, "Invalid Overlay IP address."),
            Error::RoutingTableInvalid => write!(f, "Invalid or corrupted routing table."),
            Error::QueueCongestion => write!(f, "Outgoing QoS queue is congested."),
        }
    }
}

impl error::Error for Error {
    fn description(&self) -> &str {
        match *self {
            Error::Io(ref err) => err.description(),
            Error::ParseError(ref err) => err.description(),
            Error::ParseIncomplete(_) => "Missing bytes while deserializing.",
            Error::FrameNeedsDeserialized => "Function was passed an already serialized frame.",
            Error::FrameNeedsSerialized => "Function was passed an already deserialized frame.",
            Error::PacketNeedsPlain => "Function needs a plaintext frame but was passed some other type.",
            Error::PacketNeedsEncrypted => "Function needs an encrypted frame but was passed some other type.",
            Error::PacketNeedsSigned => "Function needs a signed frame but was passed some other type.",
            Error::FrameFull => "The current frame cannot take the specified packet(s) and remain under the MTU.",
            Error::FrameTooLarge => "The current frame is too large for the MTU.",
            Error::PacketBadTtl(_) => "The packet's TTL is not within the valid range.",
            Error::PacketBadLen(_) => "The packet's data length is not within the valid range.",
            Error::PayloadDeserializeEncrypted => "Error deserializing a decrypted payload.",
            Error::Encrypt => "Error encrypting payload.",
            Error::Decrypt => "Error decrypting payload.",
            Error::Verify => "Error verifying signed payload.",
            Error::ConvertPublicKey => "Error transforming public signing key to crypto key.",
            Error::ConvertPrivateKey => "Error transforming private signing key to crypto key.",
            Error::OverlayInvalidIP => "Invalid Overlay IP address.",
            Error::RoutingTableInvalid => "Invalid or corrupted routing table.",
            Error::QueueCongestion => "Outgoing QoS queue is congested.",
        }
    }

    fn cause(&self) -> Option<&error::Error> {
        match *self {
            Error::Io(ref err) => Some(err),
            Error::ParseError(ref err) => Some(err),
            Error::ParseIncomplete(_) => None,
            Error::FrameNeedsDeserialized => None,
            Error::FrameNeedsSerialized => None,
            Error::PacketNeedsPlain => None,
            Error::PacketNeedsEncrypted => None,
            Error::PacketNeedsSigned => None,
            Error::FrameFull => None,
            Error::FrameTooLarge => None,
            Error::PacketBadTtl(_) => None,
            Error::PacketBadLen(_) => None,
            Error::PayloadDeserializeEncrypted => None,
            Error::Encrypt => None,
            Error::Decrypt => None,
            Error::Verify => None,
            Error::ConvertPublicKey => None,
            Error::ConvertPrivateKey => None,
            Error::OverlayInvalidIP => None,
            Error::RoutingTableInvalid => None,
            Error::QueueCongestion => None,
        }
    }
}

impl From<io::Error> for Error {
    fn from(err: io::Error) -> Error {
        Error::Io(err)
    }
}

pub type Result<T> = result::Result<T, Error>;
