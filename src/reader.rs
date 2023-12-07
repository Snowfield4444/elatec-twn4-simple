//! Basic implementation of a Simple Protocol client for [Elatec
//! TWN4](https://www.elatec-rfid.com/en/products/rfid-readerwriter-with-antenna/multi-frequency/twn4-multitech/)
//! family devices, based upon [embedded-hal](https://github.com/japaric/embedded-hal).

#![deny(missing_docs)]


extern crate byteorder;

extern crate embedded_hal as hal;
extern crate serialport;
extern crate simple_hex as hex;
extern crate alloc;
use commands::*;
use error::*;

use std::time::Duration;
use hal::serial;

/// Run modes for the reader
pub mod mode {
    /// The reader is active and ready to take commands
    pub struct Run;
    /// The reader is in a low-power state and can be awoken by LPCD, incoming data, or timeout
    pub struct Sleep;
    /// (Unimplemented) The reader is stopped, and can be awoken by incoming data.
    pub struct Stop;
}

#[derive(Debug)]
/// Elatec Multitech3-based RFID card reader
pub struct Multitech3<RX, TX>
where
    RX: serial::Read<u8>,
    TX: serial::Write<u8>,
{
    /// RX serial pin
    rx: RX,
    /// TX serial pin
    tx: TX,
}

/// Create a new instance of the reader accessed via the provided pins.
pub fn new<RX, TX>(rx: RX, tx: TX) -> Multitech3<RX, TX>
where
    RX: serial::Read<u8>,
    TX: serial::Write<u8>,
{
    Multitech3::<RX, TX> {
        rx,
        tx,
    }
}

impl<RX, TX> Multitech3<RX, TX>
where
    RX: serial::Read<u8>,
    TX: serial::Write<u8>,
{
    /// Execute a blocking read of a single byte from the serial port
    fn read_byte(&mut self) -> Result<u8, Error> {
        match block!(self.rx.read()) {
            Ok(c) => {
                //info!("read byte {:?}",c);
                Ok(c)
            },
            Err(_e) => Err(Error::Read),
        }
    }

    /// Execute a blocking read of a ASCII hex-encoded byte (i.e. two bytes) from the serial port
    fn read_hex_byte(&mut self) -> Result<u8, Error> {
        match hex::hex_byte_to_byte(self.read_byte()?, self.read_byte()?) {
            Ok(b) => Ok(b),
            Err(e) => Err(Error::Hex(e)),
        }
    }

    /// Read and return the status of the last operation
    fn read_err(&mut self) -> Result<ReaderError, Error> {
        Ok(ReaderError::from(self.read_hex_byte()?))
    }

    /// Read the status of the last operation and save the rest of the line in `buf`
    fn read_resp(&mut self, buf: &mut [u8]) -> Result<ReaderError, Error> {
        let err = self.read_err()?;
        match err {
            ReaderError::None(_) => {
                let mut i = 0;
                loop {
                    if i > buf.len() {
                        return Err(Error::BufferFull);
                    }

                    let c = match block!(self.rx.read()) {
                        Ok(c) => c,
                        Err(_e) => return Err(Error::Read),
                    };
                    if c == b'\r' {
                        break;
                    }
                    buf[i] = c;
                    i += 1;
                }
                Ok(ReaderError::None(i))
            }
            _ => Err(Error::Reader(err)),
        }
    }

    /// Read the results of the sleep operation and return a running reader object
    pub fn into_running(
        mut self,
    ) -> Result<(Multitech3<RX, TX>, WakeReason), (Self, Error)> {
        let mut resp_buf = [0u8; 2];
        match self.read_resp(&mut resp_buf) {
            Ok(resp) => match resp {
                ReaderError::None(_) => {
                    let reason_code = match hex::hex_byte_to_byte(resp_buf[0], resp_buf[1]) {
                        Ok(c) => c,
                        Err(e) => return Err((self, Error::Hex(e))),
                    };

                    Ok((
                        Multitech3::<RX, TX> {
                            rx: self.rx,
                            tx: self.tx,
                        },
                        WakeReason::from(reason_code),
                    ))
                }
                _ => Err((self, Error::Reader(resp))),
            },
            Err(e) => Err((self, e)),
        }
    }

    /// Write the commands to the serial port
    fn issue_cmd<C: SimpleCmd>(&mut self, buf: &mut [u8], cmd: &C) -> Result<(), Error> {
        let sz = cmd.get_cmd_hex(buf)?;
        // info!("buf {:x?}{:x?}",buf, b"\r");
        self.write_buf(&buf[..sz])?;
        self.write_buf(b"\r")?;
        Ok(())
    }

    /// Write the commands to the serial port
    fn issue_cmd_payload<C: SimpleCmd>(&mut self, buf: &mut Vec<u8>, payload: &str, cmd: &C) -> Result<(), Error> {
        let sz = cmd.get_cmd_hex_with_payload(buf, payload)?;
        
        self.write_buf(&buf[..sz])?;
        self.write_buf(b"\r")?;
        Ok(())
    }

    /// Write the entire contents of `buf` to the serial port
    fn write_buf(&mut self, buf: &[u8]) -> Result<(), Error> {
        //info!("buf {}",std::str::from_utf8(buf).unwrap());
        for c in buf.iter() {
            match block!(self.tx.write(*c)) {
                Ok(_) => {}
                Err(_) => return Err(Error::Write),
            }
        }
        Ok(())
    }

    /// Reset the reader; does not return a status
    pub fn reset(&mut self) -> Result<(), Error> {
        let cmd = Reset;
        self.issue_cmd(&mut [0u8; Reset::CMD_LEN], &cmd)
    }

    /// Put the reader to sleep; will wake on low-power card detect or timeout
    pub fn sleep(mut self, dur: Duration, opts: SleepFlags) -> Result<Multitech3<RX, TX>, Error> {
        let sleep_cmd = Sleep {
            period: dur,
            flags: opts,
        };
        match self.issue_cmd(&mut [0u8; Sleep::CMD_LEN], &sleep_cmd) {
            Ok(_) => Ok(Multitech3::<RX, TX> {
                rx: self.rx,
                tx: self.tx,
            }),
            Err(e) => Err(e),
        }
    }

    /// Return the number of ticks the reader has been powered on
    pub fn get_sys_ticks(&mut self) -> Result<u32, Error> {
        const RESP_LEN: usize = 8;
        let mut resp_buf = [0u8; RESP_LEN];
        let cmd = GetSysTicks;
        match self.issue_cmd(&mut [0u8; GetSysTicks::CMD_LEN], &cmd) {
            Ok(_) => {
                let resp = self.read_resp(&mut resp_buf)?;
                match resp {
                    ReaderError::None(n) => cmd.parse_response(&mut resp_buf[..n]),
                    _ => Err(Error::Reader(resp)),
                }
            }
            Err(e) => Err(e),
        }
    }

    /// Return the reader version string in `buf`
    pub fn get_version_string(&mut self, buf: &mut [u8]) -> Result<usize, Error> {
        let cmd = GetVersionString {
            max_resp_len: core::cmp::min(0xFF as usize, buf.len()) as u16,
        };
        match self.issue_cmd(&mut [0u8; GetVersionString::CMD_LEN], &cmd) {
            Ok(()) => {
                let resp = self.read_resp(buf)?;
                match resp {
                    ReaderError::None(n) => cmd.parse_response(&mut buf[..n]),
                    _ => Err(Error::Reader(resp)),
                }
            }
            Err(e) => Err(e),
        }
    }

    /// Execute a tag read operation and return the tag type and ID in `buf`
    ///
    /// This does no parsing of the tag information except to strip out TLV-esqe data sent during
    /// transmission. The data is returned in the form:
    ///
    /// > `[type: u8] [id_bit_cnt: u8] [tag_id: u8|...]`
    ///
    pub fn search_tag(&mut self, buf: &mut [u8]) -> Result<Option<usize>, Error> {
        let cmd = SearchTag;
        match self.issue_cmd(&mut [0u8; SearchTag::CMD_LEN], &cmd) {
            Ok(()) => {
                // because the card data might include b"\r", we cannot use read_resp and must
                // instead read byte-by-byte, at which point we don't need to use parse_response,
                // since we can just unpack it directly as we read the bytes.

                let rdr_resp = ReaderError::from(self.read_hex_byte()?);
                match rdr_resp {
                    ReaderError::None(_) => {}
                    _ => return Err(Error::Reader(rdr_resp)),
                };

                let result = self.read_hex_byte()?;
                if result != 1u8 {
                    return Ok(None);
                }

                if buf.len() < 2 {
                    return Err(Error::BufferTooSmall(2));
                }

                buf[0] = self.read_hex_byte()?; // tag type
                let bit_count = self.read_hex_byte()?; // id bit count

                if bit_count == 0 {
                    return Ok(None);
                } else {
                    buf[1] = bit_count;
                }

                let id_bytes = self.read_hex_byte()? as usize;

                if buf.len() < id_bytes + 2 {
                    return Err(Error::BufferTooSmall(id_bytes + 2));
                }

                let mut i = 0;
                loop {
                    if i == id_bytes {
                        break;
                    }
                    buf[i + 2] = self.read_hex_byte()?;
                    i += 1;
                }

                Ok(Some(id_bytes + 2))
            }
            Err(e) => Err(e),
        }
    }


}

mod iso15693;


#[derive(Debug)]
/// Reasons the reader has awoken from sleep
pub enum WakeReason {
    /// An unrecognized reason was returned during sleep
    Unknown,
    /// The USB input channel received at least one byte.
    USB,
    /// The input channel of COM1 received at least one byte.
    COM1,
    /// The input channel of COM2 received at least one byte.
    COM2,
    /// Sleep time ran out.
    Timeout,
    /// The presence of a transponder card was detected. (Supported by TWN4 MultiTech Nano only)
    LPCD,
}

impl From<u8> for WakeReason {
    /// Convert a hex-decoded sleep wake-up reason code into a WakeReason
    fn from(n: u8) -> Self {
        match n {
            1 => WakeReason::USB,
            2 => WakeReason::COM1,
            3 => WakeReason::COM2,
            4 => WakeReason::Timeout,
            5 => WakeReason::LPCD,
            _ => WakeReason::Unknown,
        }
    }
}



pub use commands::SleepFlags;
