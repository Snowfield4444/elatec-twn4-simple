use super::Multitech3;

extern crate byteorder;

extern crate alloc;
extern crate embedded_hal as hal;
extern crate simple_hex as hex;
use commands::*;
use error::*;

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
    pub fn iso15693_generic_command(
        &mut self,
        payload: &str,
        buf: &mut Vec<u8>,
        drop_first: bool
    ) -> Result<Option<usize>, Error> {
        let cmd = Iso15693GenericCommand;
        //let mut buf = Vec::new();
        //info!("buf: {:?}", buf.len());
        match self.issue_cmd_payload(buf, &payload, &cmd) {
            Ok(()) => {
                // Drop the first byte this is really flaky depending how the chip is configured if 32 bit it has to drop the first byte for 64 bit do not drop
                if drop_first {
                    self.read_byte()?;
                }

                let rdr_resp = ReaderError::from(self.read_hex_byte()?);
                match rdr_resp {
                    ReaderError::None(_) => {}
                    _ => return Err(Error::Reader(rdr_resp)),
                };

                let result = self.read_hex_byte()?;
                if result != 1u8 {
                    return Ok(None);
                }

                let resp_bytes = self.read_hex_byte()? as usize;

                buf.clear();
                for _ in 0..resp_bytes {
                    buf.push(self.read_hex_byte().unwrap());
                }

                Ok(Some(resp_bytes))
            }
            Err(e) => Err(e),
        }
    }

    /// Execute generic command with a write that has a bit different response for ISO15693
    fn iso15693_generic_write(
        &mut self,
        payload: &str,
        buf: &mut Vec<u8>,
        drop_first: bool,
    ) -> Result<bool, Error> {
        let cmd = Iso15693GenericCommand;
        //let mut buf = Vec::new();
        match self.issue_cmd_payload(buf, &payload, &cmd) {
            Ok(()) => {
                // Drop the first byte this is really flaky depending how the chip is configured if 32 bit it has to drop the first byte for 64 bit do not drop
                if drop_first {
                    self.read_byte()?;
                }
                // The response that we are looking for is 0001
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

        /// Execute generic command with a write that has a bit different response for ISO15693
        fn iso15693_generic_authenticate(
            &mut self,
            payload: &str,
            buf: &mut Vec<u8>,
            drop_first: bool,
        ) -> Result<bool, Error> {
            let cmd = Iso15693GenericCommand;
            //let mut buf = Vec::new();
            match self.issue_cmd_payload(buf, &payload, &cmd) {
                Ok(()) => {
                    // Drop the first byte this is really flaky depending how the chip is configured if 32 bit it has to drop the first byte for 64 bit do not drop
                    if drop_first {
                        self.read_byte()?;
                    }
                    // The response that we are looking for is 0001
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
    pub fn em4425_read(&mut self, address: u8, buf: &mut Vec<u8>) -> Result<Option<usize>, Error> {
        let flags: String = "02".to_owned();
        const COMMAND: &str = "20";
        let address = format!("{:02x}", address);
        let data_len = u8_array_to_hex_string(&[1]);
        let cmd = flags + COMMAND + &data_len + &address;
        self.iso15693_generic_command(&cmd, buf, false)
    }

    /// Exposed method for iso15693_read (EM4425 read multiple blocks)
    pub fn em4425_read_multi(
        &mut self,
        address: u8,
        num_of_blocks: u8,
        buf: &mut Vec<u8>,
    ) -> Result<Option<usize>, Error> {
        let flags: String = "02".to_owned();
        const COMMAND: &str = "23";
        let address = format!("{:02X}", address);
        let num_of_blocks = format!("{:02X}", num_of_blocks);
        let data_len = u8_array_to_hex_string(&[2]);
        let cmd = flags + COMMAND + &data_len + &address + &num_of_blocks;
        self.iso15693_generic_command(&cmd, buf, true)
    }

    /// Exposed method for iso15693_write (EM4425 write)
    pub fn em4425_write_32bit(
        &mut self,
        address: u8,
        data: [u8; 4],
        buf: &mut Vec<u8>,
    ) -> Result<bool, Error> {
        let flags: String = "02".to_owned();
        const COMMAND: &str = "21";
        let address = format!("{:02x}", address);
        let data = u8_array_to_hex_string(&data);
        let data_len = u8_array_to_hex_string(&[5]);
        let cmd = flags + COMMAND + &data_len + &address + &data;
        self.iso15693_generic_write(&cmd, buf, true)
    }

    /// Exposed method for iso15693_write (EM4425 write)
    pub fn em4425_write_64bit(
        &mut self,
        address: u8,
        data: [u8; 8],
        buf: &mut Vec<u8>,
    ) -> Result<bool, Error> {
        let flags: String = "02".to_owned();
        const COMMAND: &str = "21";
        let address = format!("{:02x}", address);
        let data = u8_array_to_hex_string(&data);
        let data_len = u8_array_to_hex_string(&[9]);
        let cmd = flags + COMMAND + &data_len + &address + &data;
        self.iso15693_generic_write(&cmd, buf, false)
    }

    /// Provide authenticate command for EM4425
    /// TESTING
    pub fn em4425_authenticate(&mut self, flags: String, data: String, buf: &mut Vec<u8>) -> Result<bool, Error> {
        const COMMAND: &str = "35";
        const CSI: &str = "00";
        let twn4_data_len = u8_array_to_hex_string(&[14]);
        let data_len = u8_array_to_hex_string(&[12]);

        //info!("data: {}", data);
        let cmd = flags + COMMAND + &twn4_data_len + CSI + &data_len + &data;
        self.iso15693_generic_authenticate(&cmd, buf, false)
    }

    /// Get extended info for EM4425
    pub fn em4425_get_ext_info(&mut self, buf: &mut Vec<u8>) -> Result<Option<usize>, Error> {
        let flags: String = "02".to_owned();
        const COMMAND: &str = "3B";
        let data_len = u8_array_to_hex_string(&[1]);
        let request_field = "6F";
        let cmd = flags + COMMAND + &data_len + request_field;
        self.iso15693_generic_command(&cmd, buf, true)
    }
}
