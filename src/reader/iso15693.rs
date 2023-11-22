use super::Multitech3;

#[macro_use]
use bitflags;
extern crate byteorder;
#[macro_use(block)]
use nb;
extern crate embedded_hal as hal;
extern crate simple_hex as hex;
extern crate alloc;
use commands::*;
use error::*;

use std::time::Duration;
use hal::serial;

/// Converts a slice of u8 bytes to a hexadecimal string.
///
/// #### Arguments
///
/// * `bytes` - A slice of u8 bytes to be converted to a hexadecimal string.
///
/// #### Returns
///
/// A string containing the hexadecimal representation of the input bytes.
pub fn u8_array_to_hex_string(bytes: &[u8]) -> String {
    let hex_chars: Vec<String> = bytes.iter().map(|byte| format!("{:02X}", byte)).collect();
    hex_chars.join("")
}

impl<RX, TX> Multitech3<RX, TX>
where
    RX: serial::Read<u8>,
    TX: serial::Write<u8>,
{
        /// Execute generic command for ISO15693
        pub fn iso15693_generic_command(&mut self, payload: &str, buf: &mut Vec<u8>) -> Result<Option<usize>, Error> {
            let cmd = Iso15693GenericCommand;
            //let mut buf = Vec::new();
            match self.issue_cmd_payload(buf, &payload, &cmd) {
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
    
                    let resp_bytes = self.read_hex_byte()? as usize;
    
                    if buf.len() < resp_bytes + 2 {
                        return Err(Error::BufferTooSmall(resp_bytes + 2));
                    }
    
                    let mut i = 0;
                    loop {
                        if i == resp_bytes {
                            break;
                        }
                        buf[i + 2] = self.read_hex_byte()?;
                        i += 1;
                    }
    
                    Ok(Some(resp_bytes + 2))
                }
                Err(e) => Err(e),
            }
        }
    
        
    
         /// Execute generic command with a write that has a bit different response for ISO15693
         fn iso15693_generic_write(&mut self, payload: &str, buf: &mut Vec<u8>) -> Result<bool, Error> {
            let cmd = Iso15693GenericCommand;
            //let mut buf = Vec::new();
            match self.issue_cmd_payload(buf, &payload, &cmd) {
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
                        return Ok(false);
                    }
    
                    Ok(true)
                }
                Err(e) => Err(e),
            }
        }


        /// Exposed method for iso15693_read (EM4425 read)
        pub fn em4425_read(&mut self, address:u8, buf: &mut Vec<u8>) -> Result<Option<usize>, Error> {
            let flags: String = "02".to_owned();
            const COMMAND: &str = "20";
            let address = format!("{:02x}", address);
            let data_len = u8_array_to_hex_string(&[1]);
            let cmd = flags + COMMAND + &data_len + &address;
            self.iso15693_generic_command(&cmd, buf)
        }

        /// Exposed method for iso15693_read (EM4425 read multiple blocks)
        pub fn em4425_read_multi(&mut self, address:u8, num_of_blocks:u8, buf: &mut Vec<u8>) -> Result<Option<usize>, Error> {
            let flags: String = "02".to_owned();
            const COMMAND: &str = "23";
            let address = format!("{:02x}", address);
            let num_of_blocks = format!("{:02x}", num_of_blocks);
            let data_len = u8_array_to_hex_string(&[2]);
            let cmd = flags + COMMAND + &data_len + &address + &num_of_blocks;
            self.iso15693_generic_command(&cmd, buf)
        }

        /// Exposed method for iso15693_write (EM4425 write)
        pub fn em4425_write_32bit(&mut self, address:u8, data: [u8;4], buf: &mut Vec<u8>) -> Result<bool, Error> {
        let flags: String = "02".to_owned();
        const COMMAND: &str = "21";
        let address = format!("{:02x}", address);
        let data = u8_array_to_hex_string(&data);
        let data_len = u8_array_to_hex_string(&[5]);
        let cmd = flags + COMMAND + &data_len + &address + &data;
        self.iso15693_generic_write(&cmd, buf)

        }

        /// Exposed method for iso15693_write (EM4425 write)
        pub fn em4425_write_64bit(&mut self, address:u8, data: [u8;8], buf: &mut Vec<u8>) -> Result<bool, Error> {
        let flags: String = "02".to_owned();
        const COMMAND: &str = "21";
        let address = format!("{:02x}", address);
        let data = u8_array_to_hex_string(&data);
        let data_len = u8_array_to_hex_string(&[9]);
        let cmd = flags + COMMAND + &data_len + &address + &data;
        self.iso15693_generic_write(&cmd, buf)
    }
}