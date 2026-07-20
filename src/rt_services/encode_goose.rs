use rasn::ber::encode;

use crate::{rt_services::types::IECGoosePduRasn, types::*};

pub fn encode_ethernet_header(header: &EthernetHeader, length: u16) -> Vec<u8> {
    // init buffer
    let buffer_len: usize = if header.tpid.is_some() && header.tci.is_some() {
        26
    } else {
        22
    };
    let mut buffer = vec![0u8; buffer_len];

    let mut new_pos: usize = 0;
    // Destination MAC address (6 bytes)
    buffer[new_pos..new_pos + 6].copy_from_slice(&header.dst_addr);
    new_pos += 6;

    // Source MAC address (6 bytes)
    buffer[new_pos..new_pos + 6].copy_from_slice(&header.src_addr);
    new_pos += 6;

    // VLAN tag (TPID and TCI) is optional
    if let (Some(tpid), Some(tci)) = (&header.tpid, &header.tci) {
        // Write TPID (2 bytes)
        buffer[new_pos..new_pos + 2].copy_from_slice(tpid);
        new_pos += 2;
        // Write TCI (2 bytes)
        buffer[new_pos..new_pos + 2].copy_from_slice(tci);
        new_pos += 2;
    }

    // EtherType is fixed to 0x88B8 for GOOSE
    buffer[new_pos..new_pos + 2].copy_from_slice(&header.ether_type);
    new_pos += 2;

    // APPID (2 bytes)
    buffer[new_pos..new_pos + 2].copy_from_slice(&header.appid);
    new_pos += 2;

    // Length (2 bytes)
    buffer[new_pos..new_pos + 2].copy_from_slice(&length.to_be_bytes());
    new_pos += 2;

    // Reserved 1 (2 bytes, set to 0)
    buffer[new_pos..new_pos + 2].copy_from_slice(&[0; 2]);
    new_pos += 2;

    // Reserved 2 (2 bytes, set to 0)
    buffer[new_pos..new_pos + 2].copy_from_slice(&[0; 2]);

    buffer
}

pub fn encode_goose(header: &EthernetHeader, pdu: &IECGoosePdu) -> Result<Vec<u8>, EncodeError> {
    // Encode the GOOSE PDU using rasn
    let pdu_bytes = encode(&IECGoosePduRasn::from(pdu))
        .map_err(|e| EncodeError::new(&format!("Failed to encode GOOSE PDU: {:?}", e), 0))?;

    // calculate length based in pdu_bytes
    let length = pdu_bytes.len() as u16 + 8; // 8 bytes for APPID, length, reserved1, reserved2 and 4 bytes for Ethernet header fields
    let ether_buffer = encode_ethernet_header(header, length);

    // Combine Ethernet header and GOOSE PDU into a single buffer
    Ok([ether_buffer, pdu_bytes].concat())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_ethernet_header_without_vlan() {
        let header = EthernetHeader {
            dst_addr: [0x01, 0x0C, 0xCD, 0x01, 0x00, 0x01],
            src_addr: [0x00, 0x1A, 0xB6, 0x03, 0x2F, 0x1C],
            tpid: None,
            tci: None,
            ether_type: [0x88, 0xB8],
            appid: [0x10, 0x01],
            length: [0x00, 0x00], // Not used in encoding, passed as parameter
        };

        let length: u16 = 140;
        let encoded = encode_ethernet_header(&header, length);

        let expected: &[u8] = &[
            // Destination MAC
            0x01, 0x0C, 0xCD, 0x01, 0x00, 0x01, // Source MAC
            0x00, 0x1A, 0xB6, 0x03, 0x2F, 0x1C, // EtherType
            0x88, 0xB8, // APPID
            0x10, 0x01, // Length
            0x00, 0x8C, // 140 in hex
            // Reserved1
            0x00, 0x00, // Reserved2
            0x00, 0x00,
        ];

        assert_eq!(
            encoded.len(),
            22,
            "Ethernet header without VLAN should be 22 bytes"
        );
        assert_eq!(
            encoded, expected,
            "Encoded Ethernet header does not match expected"
        );
    }

    #[test]
    fn test_encode_ethernet_header_with_vlan() {
        let header = EthernetHeader {
            dst_addr: [0x01, 0x0C, 0xCD, 0x01, 0x00, 0x01],
            src_addr: [0x00, 0x1A, 0xB6, 0x03, 0x2F, 0x1C],
            tpid: Some([0x81, 0x00]),
            tci: Some([0x00, 0x01]),
            ether_type: [0x88, 0xB8],
            appid: [0x10, 0x01],
            length: [0x00, 0x00], // Not used in encoding
        };

        let length: u16 = 140;
        let encoded = encode_ethernet_header(&header, length);

        let expected: &[u8] = &[
            // Destination MAC
            0x01, 0x0C, 0xCD, 0x01, 0x00, 0x01, // Source MAC
            0x00, 0x1A, 0xB6, 0x03, 0x2F, 0x1C, // VLAN TPID
            0x81, 0x00, // VLAN TCI
            0x00, 0x01, // EtherType
            0x88, 0xB8, // APPID
            0x10, 0x01, // Length
            0x00, 0x8C, // 140 in hex
            // Reserved1
            0x00, 0x00, // Reserved2
            0x00, 0x00,
        ];

        assert_eq!(
            encoded.len(),
            26,
            "Ethernet header with VLAN should be 26 bytes"
        );
        assert_eq!(
            encoded, expected,
            "Encoded Ethernet header with VLAN does not match expected"
        );
    }

    #[test]
    fn test_encode_ethernet_header_length_field() {
        let header = EthernetHeader {
            dst_addr: [0x01, 0x0C, 0xCD, 0x01, 0x00, 0x01],
            src_addr: [0x00, 0x1A, 0xB6, 0x03, 0x2F, 0x1C],
            tpid: Some([0x81, 0x00]),
            tci: Some([0x00, 0x01]),
            ether_type: [0x88, 0xB8],
            appid: [0x10, 0x01],
            length: [0x00, 0x00],
        };

        // Test different length values
        let test_lengths = vec![
            (140u16, [0x00, 0x8C]),
            (256u16, [0x01, 0x00]),
            (1500u16, [0x05, 0xDC]),
        ];

        for (length, expected_bytes) in test_lengths {
            let encoded = encode_ethernet_header(&header, length);

            // Length field is at positions 20-21 (with VLAN)
            assert_eq!(
                &encoded[20..22],
                &expected_bytes,
                "Length field mismatch for length {}",
                length
            );
        }
    }

    #[test]
    fn test_encode_ethernet_header_reserved_fields() {
        let header = EthernetHeader {
            dst_addr: [0x01, 0x0C, 0xCD, 0x01, 0x00, 0x01],
            src_addr: [0x00, 0x1A, 0xB6, 0x03, 0x2F, 0x1C],
            tpid: Some([0x81, 0x00]),
            tci: Some([0x00, 0x01]),
            ether_type: [0x88, 0xB8],
            appid: [0x10, 0x01],
            length: [0x00, 0x00],
        };

        let encoded = encode_ethernet_header(&header, 140);

        // Check Reserved1 (positions 22-23)
        assert_eq!(&encoded[22..24], &[0x00, 0x00], "Reserved1 should be zero");

        // Check Reserved2 (positions 24-25)
        assert_eq!(&encoded[24..26], &[0x00, 0x00], "Reserved2 should be zero");
    }

    #[test]
    fn test_encode_goose_pdu() {
        // Create a minimal IECGoosePdu or your equivalent struct

        let header = EthernetHeader {
            dst_addr: [0x01, 0x0C, 0xCD, 0x01, 0x00, 0x01],
            src_addr: [0x00, 0x1A, 0xB6, 0x03, 0x2F, 0x1C],
            tpid: Some([0x81, 0x00]),
            tci: Some([0x00, 0x01]),
            ether_type: [0x88, 0xB8],
            appid: [0x10, 0x01],
            length: [0x00, 0x00], // will be set during encoding
        };

        let data = vec![
            IECData::UInt(1),
            IECData::UInt(128),
            IECData::UInt(255),
            IECData::UInt(127),
            IECData::UInt(1),
            IECData::UInt(128),
            IECData::UInt(255),
            IECData::Boolean(true),
            IECData::Int(2147483647),
            IECData::Int(2147483648),
            IECData::VisibleString("test".to_string()),
        ];

        let pdu = IECGoosePdu {
            go_cb_ref: "IED1/LLN0$GO$gcb1".to_string(),
            time_allowed_to_live: 2000,
            dat_set: "IED1/LLN0$DATASET1".to_string(),
            go_id: "GOOSE1".try_into().unwrap(),
            t: Timestamp::from_bytes([0x20, 0x21, 0x06, 0x12, 0x0A, 0x30, 0x00, 0x00]),
            st_num: 1,
            sq_num: 42,
            simulation: false,
            conf_rev: 128,
            nds_com: false,
            num_dat_set_entries: data.len() as u32,
            all_data: data,
        };

        let result = encode_goose(&header, &pdu);
        assert!(result.is_ok());

        let encoded = result.unwrap();
        let len = encoded.len();

        // Replace this with your actual expected encoding:
        let expected: &[u8] = &[
            1, 12, 205, 1, 0, 1, 0, 26, 182, 3, 47, 28, 129, 0, 0, 1, 136, 184, 16, 1, 0, 140, 0,
            0, 0, 0, 97, 129, 129, 128, 17, 73, 69, 68, 49, 47, 76, 76, 78, 48, 36, 71, 79, 36,
            103, 99, 98, 49, 129, 2, 7, 208, 130, 18, 73, 69, 68, 49, 47, 76, 76, 78, 48, 36, 68,
            65, 84, 65, 83, 69, 84, 49, 131, 6, 71, 79, 79, 83, 69, 49, 132, 8, 32, 33, 6, 18, 10,
            48, 0, 0, 133, 1, 1, 134, 1, 42, 135, 1, 0, 136, 2, 0, 128, 137, 1, 0, 138, 1, 11, 171,
            47, 134, 1, 1, 134, 2, 0, 128, 134, 2, 0, 255, 134, 1, 127, 134, 1, 1, 134, 2, 0, 128,
            134, 2, 0, 255, 131, 1, 255, 133, 4, 127, 255, 255, 255, 133, 5, 0, 128, 0, 0, 0, 138,
            4, 116, 101, 115, 116,
        ];
        assert_eq!(len, 158, "Encoded length does not match expected length");

        assert_eq!(
            encoded, expected,
            "Encoded buffer does not match expected output"
        );
    }
}
