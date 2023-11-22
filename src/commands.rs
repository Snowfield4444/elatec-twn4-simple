
use super::hex;
use super::error::Error;

use alloc::fmt::format;
use byteorder::{ByteOrder, LittleEndian};
use std::time::Duration;


fn copy_all_bytes(dest: &mut [u8], src: &[u8]) {
    dest[..src.len()].copy_from_slice(&src[..]);
}

fn check_bufsz(l: usize, b: &[u8]) -> Result<(), Error> {
    if b.len() < l {
        Err(Error::BufferTooSmall(l))
    } else {
        Ok(())
    }
}

/// Simple protocol commands
pub trait SimpleCmd {
    /// The maximum length of a simple command in hex-encoded bytes
    const CMD_LEN: usize;
    /// The type of value returned in the parsed command response
    type Response;

    /// Retrieve hex-encoded command bytes to be sent to the reader into `buf`
    fn get_cmd_hex(&self, buf: &mut [u8]) -> Result<usize, Error>;
    /// Parse the hex-encoded response (excl. response code) in `buf`
    fn parse_response(&self, _buf: &mut [u8]) -> Result<Self::Response, Error> {
        Err(Error::Unimplemented)
    }
    /// OPTIONAL: Retrieve hex-encoded command bytes to be sent to the reader into `buf`
    /// used for command were the payload differs read from specific address
    #[allow(unused_variables)]
    fn get_cmd_hex_with_payload(&self, buf: &mut Vec<u8>, payload:&str) -> Result<usize, Error> { Ok(0) }

}

/// Reset the firmware (including any running App)
pub struct Reset;

impl SimpleCmd for Reset {
    const CMD_LEN: usize = 2;
    type Response = ();

    fn get_cmd_hex(&self, buf: &mut [u8]) -> Result<usize, Error> {
        check_bufsz(Reset::CMD_LEN, buf)?;
        copy_all_bytes(buf, b"0001");
        Ok(2)
    }
}

bitflags! {
    /// Sleep mode flags used in the sleep command
    pub struct SleepFlags: u32 {
        /// Wake up on USB activity
        const WAKEUP_BY_USB_MSK = 0x1;
        /// Wake up on COM1 activity
        const WAKEUP_BY_COM1_MSK = 0x2;
        /// Wake up on COM2 activity
        const WAKEUP_BY_COM2_MSK = 0x4;
        /// Wake up after timeout
        const WAKEUP_BY_TIMEOUT_MSK = 0x10;
        /// Wake up on low-power card detect
        const WAKEUP_BY_LPCD_MSK = 0x20;
        /// Enter sleep mode
        const SLEEPMODE_SLEEP = 0x0000;
        /// Enter stop mode
        const SLEEPMODE_STOP = 0x0100;
    }
}

/// The device enters the sleep state for a specified time.
///
/// During sleep state, the device reduces the current consumption to a value, which depends on the mode of sleep.
pub struct Sleep {
    pub period: Duration,
    pub flags: SleepFlags,
}

impl SimpleCmd for Sleep {
    const CMD_LEN: usize = 20;
    type Response = ();

    fn get_cmd_hex(&self, buf: &mut [u8]) -> Result<usize, Error> {
        check_bufsz(Sleep::CMD_LEN, buf)?;

        copy_all_bytes(buf, b"0007");
        let mut u32_buf = [0u8; 4];
        if self.period != Duration::new(0, 0) {
            LittleEndian::write_u32(
                &mut u32_buf,
                self.period.as_secs() as u32 * 1000 + self.period.subsec_millis(),
                );
        }
        hex::bytes_to_hex(&u32_buf, &mut buf[4..12])?;
        LittleEndian::write_u32(&mut u32_buf, self.flags.bits());
        hex::bytes_to_hex(&u32_buf, &mut buf[12..20])?;
        Ok(Self::CMD_LEN)
    }
}

/// Retrieve number of system ticks, specified in multiple of 1 milliseconds, since startup of the firmware.
pub struct GetSysTicks;

impl SimpleCmd for GetSysTicks {
    const CMD_LEN: usize = 4;
    type Response = u32;

    fn get_cmd_hex(&self, buf: &mut [u8]) -> Result<usize, Error> {
        check_bufsz(GetSysTicks::CMD_LEN, buf)?;

        copy_all_bytes(buf, b"0003");
        Ok(GetSysTicks::CMD_LEN)
    }

    fn parse_response(&self, buf: &mut [u8]) -> Result<u32, Error> {
        if buf.len() != 8 {
            return Err(Error::BadResponse(buf.len()));
        }

        let mut result_buf = [0u8; 4];
        hex::hex_to_bytes(&buf, &mut result_buf)?;
        Ok(LittleEndian::read_u32(&result_buf))
    }
}

/// Retrieve version information.
pub struct GetVersionString {
    pub max_resp_len: u16,
}

impl SimpleCmd for GetVersionString {
    const CMD_LEN: usize = 6;
    type Response = usize;

    fn get_cmd_hex(&self, buf: &mut [u8]) -> Result<usize, Error> {
        check_bufsz(GetVersionString::CMD_LEN, buf)?;
        copy_all_bytes(buf, b"0004");
        hex::bytes_to_hex(&[0xFFu8], &mut buf[4..])?;
        Ok(GetVersionString::CMD_LEN)
    }

    fn parse_response(&self, buf: &mut [u8]) -> Result<usize, Error> {
        const MAX_RESP_LEN: usize = 0xFF;
        let mut resp_len = [0u8];
        hex::hex_to_bytes(&[buf[0], buf[1]], &mut resp_len)?;
        let resp_len = resp_len[0] as usize;

        if resp_len * 2 != buf.len() - 2 || resp_len > MAX_RESP_LEN {
            return Err(Error::BadResponse(resp_len));
        }

        let mut resp_buf = [0u8; MAX_RESP_LEN];
        hex::hex_to_bytes(&buf[2..], &mut resp_buf)?;
        copy_all_bytes(buf, &resp_buf[..resp_len]);
        Ok(resp_len)
    }
}

/// Use this function to search a transponder in the reading range of TWN4.
///
/// TWN4 is searching for all types of transponders, which have been specified via function
/// SetTagTypes (unimplemented in this library). If a transponder has been found, tag type,
/// length of ID and ID data itself are returned.
pub struct SearchTag;

impl SimpleCmd for SearchTag {
    const CMD_LEN: usize = 6;
    type Response = Option<usize>;

    fn get_cmd_hex(&self, buf: &mut [u8]) -> Result<usize, Error> {
        check_bufsz(SearchTag::CMD_LEN, buf)?;
        copy_all_bytes(buf, b"0500");
        hex::bytes_to_hex(&[0xFFu8], &mut buf[4..])?;
        Ok(SearchTag::CMD_LEN)
    }
}

/// Use this to send generate Generic Commands for ISO15693
/// Used to read and write operations for tags that support ISO15693
pub struct Iso15693GenericCommand;

impl SimpleCmd for Iso15693GenericCommand {
    const CMD_LEN: usize = 255;
    type Response = Option<usize>;

    /// NOt usable
    fn get_cmd_hex(&self, buf: &mut [u8]) -> Result<usize, Error> {
        panic!("Not usable")
    }

    //This has to be used for the commands to work
    fn get_cmd_hex_with_payload(&self, buf: &mut Vec<u8>, payload: &str) -> Result<usize, Error> {
        let cmd = format(format_args!("0D00{payload}FF"));
        println!("{}",cmd);
        buf.append(&mut cmd.as_bytes().to_vec());
        Ok(buf.len())
    }
}


