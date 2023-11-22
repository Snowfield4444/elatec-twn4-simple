#[derive(Debug)]
/// Exceptions occurring during reader operations
pub enum Error {
    /// The reader issued a response that could not be processed as expected
    BadResponse(usize),
    /// The provided buffer was filled but more data awaits
    BufferFull,
    /// The supplied buffer is too small - the inner value is the required size
    BufferTooSmall(usize),
    /// A read of the serial port failed
    ///
    /// TODO make this properly bubble up <RX as hal::serial::Read>::Error somehow
    Read,
    /// A write to the serial port failed
    Write,
    /// The reader is still asleep and no bytes were waiting
    StillAsleep,
    /// An unspecified error occurred
    Other,
    /// The requested function is unimplemented
    Unimplemented,
    /// Communication with the reader succeeded, but the reader returned an error
    Reader(ReaderError),
    /// An attempt to manipulate hex bytes failed
    Hex(hex::Error),
}

#[derive(Debug)]
/// Error responses returned by the reader
pub enum ReaderError {
    /// ERR_NONE; the inner value contains the number of subsequent bytes read
    None(usize),
    /// ERR_UNKNOWN_FUNCTION
    UnknownFunction,
    /// ERR_MISSING_PARAMETER
    MissingParameter,
    /// ERR_UNUSED_PARAMETERS
    UnusedParameters,
    /// ERR_INVALID_FUNCTION
    InvalidFunction,
    /// ERR_PARSER
    Parser,
    /// Unknown/unrecognized; the inner value contains the (hex-decoded) error value
    Unknown(u8),
}

impl From<u8> for ReaderError {
    /// Convert a hex-decoded byte response into a ReaderError
    fn from(code: u8) -> Self {
        match code {
            0 => ReaderError::None(0),
            1 => ReaderError::UnknownFunction,
            2 => ReaderError::MissingParameter,
            3 => ReaderError::UnusedParameters,
            4 => ReaderError::InvalidFunction,
            5 => ReaderError::Parser,
            _ => ReaderError::Unknown(code),
        }
    }
}

impl From<hex::Error> for Error {
    /// Turn a hex conversion error into an Error
    fn from(e: hex::Error) -> Self {
        Error::Hex(e)
    }
}

impl From<nb::Error<Error>> for Error {
    /// Convert an `nb::Error` into an Error
    fn from(e: nb::Error<Error>) -> Error {
        match e {
            nb::Error::Other(e) => e,
            _ => Error::Other,
        }
    }
}
