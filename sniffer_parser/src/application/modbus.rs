use std::net::IpAddr;

use log::debug;

use crate::serializable_packet::{application::SerializableModbusPacket, ParsedPacket, SerializablePacket};

pub fn handle_modbus_packet(
    source_ip: IpAddr,
    source_port: u16,
    dest_ip: IpAddr,
    dest_port: u16,
    packet: &[u8],
    parsed_packet: &mut ParsedPacket,
) {
    if let Ok(modbus_packet) = 
    ModbusPacket::parse(packet) {
        debug!(
            "Modbus Packet: ",

        );

        parsed_packet.set_application_layer_packet(Some(SerializablePacket::ModbusPacket(
            SerializableModbusPacket::from(&modbus_packet),
        )));
    } else {
        debug!("Malformed DNS Packet");
        parsed_packet.set_application_layer_packet(Some(SerializablePacket::MalformedPacket(
            "Malformed DNS Packet".to_string(),
        )));
    }

}

use std::convert::TryInto;


#[derive(Debug)]
pub enum ModbusError {
    InvalidLength,
    InvalidFunctionCode,
    InvalidCRC,
}

#[derive(Debug)]
pub struct ModbusPacket {
    pub address: u8,
    pub function_code: u8,
    pub data: Vec<u8>,
    pub crc: Option<u16>,
}

pub trait Parse {
    fn parse(payload: &[u8]) -> Result<ModbusPacket, ModbusError>;
}

impl Parse for ModbusPacket {
    fn parse(payload: &[u8]) -> Result<ModbusPacket, ModbusError> {
        // Check for minimal length (Address, Function Code, and CRC for RTU)
        if payload.len() < 4 {
            return Err(ModbusError::InvalidLength);
        }

        // Extract the fields (assuming RTU for simplicity)
        let address = payload[0];
        let function_code = payload[1];

        // Verify the function code is valid (standard Modbus function codes range from 1 to 127)
        if function_code == 0 || function_code > 127 {
            return Err(ModbusError::InvalidFunctionCode);
        }

        // Extract data and CRC
        let data_len = payload.len() - 4; // Minus Address, Function Code, and CRC
        let data = payload[2..2 + data_len].to_vec();
        let crc = u16::from_le_bytes(payload[payload.len() - 2..].try_into().unwrap());

        // For simplicity, we'll skip CRC validation here, but in a real implementation, you'd calculate and compare it.

        Ok(ModbusPacket {
            address,
            function_code,
            data,
            crc: Some(crc),
        })
    }
}

pub fn parse_modbus_rtu(payload: &[u8]) -> Result<ModbusPacket, ModbusError> {
    // Check for minimal length (Address, Function Code, and CRC for RTU)
    if payload.len() < 4 {
        return Err(ModbusError::InvalidLength);
    }

    // Extract the fields (assuming RTU for simplicity)
    let address = payload[0];
    let function_code = payload[1];

    // Verify the function code is valid (standard Modbus function codes range from 1 to 127)
    if function_code == 0 || function_code > 127 {
        return Err(ModbusError::InvalidFunctionCode);
    }

    // Extract data and CRC
    let data_len = payload.len() - 4; // Minus Address, Function Code, and CRC
    let data = payload[2..2 + data_len].to_vec();
    let crc = u16::from_le_bytes(payload[payload.len() - 2..].try_into().unwrap());

    // For simplicity, we'll skip CRC validation here, but in a real implementation, you'd calculate and compare it.

    Ok(ModbusPacket {
        address,
        function_code,
        data,
        crc: Some(crc),
    })
}

pub fn parse_modbus_tcp(payload: &[u8]) -> Result<ModbusPacket, ModbusError> {
    // Check for minimal length (Transaction ID, Protocol ID, Length, Unit ID, Function Code)
    if payload.len() < 8 {
        return Err(ModbusError::InvalidLength);
    }

    // Extract the fields
    let transaction_id = u16::from_be_bytes(payload[0..2].try_into().unwrap());
    let protocol_id = u16::from_be_bytes(payload[2..4].try_into().unwrap());
    let length = u16::from_be_bytes(payload[4..6].try_into().unwrap());
    let unit_id = payload[6];
    let function_code = payload[7];

    // Verify the function code is valid (standard Modbus function codes range from 1 to 127)
    if function_code == 0 || function_code > 127 {
        return Err(ModbusError::InvalidFunctionCode);
    }

    // Extract data
    let data = payload[8..].to_vec();

    Ok(ModbusPacket {
        address: unit_id,
        function_code,
        data,
        crc: None,
    })
}

pub fn parse_modbus_rtu_over_tcp(payload: &[u8]) -> Result<ModbusPacket, ModbusError> {
    if payload.len() < 8 {
        return Err(ModbusError::InvalidLength);
    }

    // Skipping the first 6 bytes for Transaction ID, Protocol ID, and Length
    parse_modbus_rtu(&payload[6..])
}


