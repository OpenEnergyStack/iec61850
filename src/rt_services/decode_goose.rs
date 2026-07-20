use crate::{
    rt_services::types::IECGoosePduRasn,
    types::{DecodeError, IECGoosePdu},
};
use rasn::ber::decode;

/// Decodes a GOOSE PDU from the buffer using rasn.
/// Returns the decoded PDU.
///
/// # Parameters
/// - `buffer`: The input byte slice containing the encoded GOOSE PDU (just the PDU, not Ethernet headers)
///
/// # Returns
/// The decoded IECGoosePdu with all_data still in raw form
pub fn decode_goose_pdu(buffer: &[u8], pos: usize) -> Result<IECGoosePdu, DecodeError> {
    let pdu: IECGoosePduRasn = decode(&buffer[pos..])
        .map_err(|e| DecodeError::new(&format!("Failed to decode GOOSE PDU: {:?}", e), 0))?;

    Ok(IECGoosePdu::from(&pdu))
}

/// Checks if the given buffer contains a GOOSE frame by inspecting the EtherType field,
/// correctly handling the presence of a VLAN tag (0x81, 0x00).
///
/// This function returns `true` if the EtherType field in the buffer matches
/// the known GOOSE EtherTypes (0x88b8 or 0x88b9), whether or not a VLAN tag is present.
/// If a VLAN tag is present, the EtherType is checked at bytes 16-17; otherwise, at bytes 12-13.
pub fn is_goose_frame(buffer: &[u8]) -> bool {
    if buffer.len() < 14 {
        return false;
    }
    // Check for VLAN tag (0x81, 0x00)
    let ether_type_offset = if buffer[12..14] == [0x81, 0x00] {
        16 // EtherType is at 16 if VLAN tag is present
    } else {
        12 // Otherwise at 12
    };
    if buffer.len() < ether_type_offset + 2 {
        return false;
    }
    let ether_type = &buffer[ether_type_offset..ether_type_offset + 2];
    ether_type == [0x88, 0xb8] || ether_type == [0x88, 0xb9]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        rt_services::{encode_goose::encode_goose, ethernet_header::decode_ethernet_header},
        types::{EthernetHeader, IECData},
    };

    #[test]
    fn test_decode_goose_pdu_all_fields() {
        let buf: &[u8] = &[
            1, 12, 205, 1, 0, 1, 0, 26, 182, 3, 47, 28, 129, 0, 0, 1, 136, 184, 16, 1, 0, 140, 0,
            0, 0, 0, 97, 129, 129, 128, 17, 73, 69, 68, 49, 47, 76, 76, 78, 48, 36, 71, 79, 36,
            103, 99, 98, 49, 129, 2, 7, 208, 130, 18, 73, 69, 68, 49, 47, 76, 76, 78, 48, 36, 68,
            65, 84, 65, 83, 69, 84, 49, 131, 6, 71, 79, 79, 83, 69, 49, 132, 8, 32, 33, 6, 18, 10,
            48, 0, 0, 133, 1, 1, 134, 1, 42, 135, 1, 0, 136, 2, 0, 128, 137, 1, 0, 138, 1, 11, 171,
            47, 134, 1, 1, 134, 2, 0, 128, 134, 2, 0, 255, 134, 1, 127, 134, 1, 1, 134, 2, 0, 128,
            134, 2, 0, 255, 131, 1, 255, 133, 4, 127, 255, 255, 255, 133, 5, 0, 128, 0, 0, 0, 138,
            4, 116, 101, 115, 116,
        ];

        let mut header = EthernetHeader::default();
        let pos = decode_ethernet_header(&mut header, &buf);
        let goose_pdu = decode_goose_pdu(&buf, pos).unwrap();

        println!("Decoded GOOSE PDU: {:?}", goose_pdu.all_data[10]);

        // assert_eq!(pos, buf.len());
        assert_eq!(goose_pdu.go_cb_ref.to_string(), "IED1/LLN0$GO$gcb1");
        assert_eq!(goose_pdu.time_allowed_to_live, 2000);
        assert_eq!(goose_pdu.dat_set.to_string(), "IED1/LLN0$DATASET1");
        assert_eq!(goose_pdu.go_id.to_string(), "GOOSE1");
        assert_eq!(goose_pdu.t.fraction, 667648);
        assert_eq!(goose_pdu.t.seconds, 539035154);
        assert_eq!(goose_pdu.t.quality.accuracy_bits(), Some(0));
        assert_eq!(goose_pdu.t.quality.clock_failure, false);
        assert_eq!(goose_pdu.t.quality.clock_not_synchronized, false);
        assert_eq!(goose_pdu.t.quality.leap_second_known, false);
        assert_eq!(goose_pdu.t.quality.time_accuracy, 0);
        let data = goose_pdu.all_data;
        assert_eq!(goose_pdu.st_num, 1);
        assert_eq!(goose_pdu.sq_num, 42);
        assert_eq!(goose_pdu.simulation, false);
        assert_eq!(goose_pdu.conf_rev, 128);
        assert_eq!(goose_pdu.nds_com, false);
        assert_eq!(goose_pdu.num_dat_set_entries, 11);
        assert_eq!(data[0], IECData::UInt(1));
        assert_eq!(data[1], IECData::UInt(0x80));
        assert_eq!(data[2], IECData::UInt(0x000000FF));
        assert_eq!(data[3], IECData::UInt(0x0000007F));
        assert_eq!(data[4], IECData::UInt(0x00000001));
        assert_eq!(data[5], IECData::UInt(0x00000080));
        assert_eq!(data[6], IECData::UInt(0x000000FF));
        assert_eq!(data[7], IECData::Boolean(true));
        assert_eq!(data[8], IECData::Int(2147483647));
        assert_eq!(data[9], IECData::Int(2147483648));
        assert_eq!(data[10], IECData::VisibleString("test".to_string()));
    }

    #[test]
    fn test_is_goose_frame() {
        // GOOSE EtherType without VLAN tag (0x88b8 at bytes 12-13)
        let mut buf = [0u8; 60];
        buf[12] = 0x88;
        buf[13] = 0xb8;
        assert!(is_goose_frame(&buf));

        // GOOSE EtherType with VLAN tag (0x81, 0x00 at 12-13, 0x88b8 at 16-17)
        let mut buf_vlan = [0u8; 60];
        buf_vlan[12] = 0x81;
        buf_vlan[13] = 0x00;
        buf_vlan[16] = 0x88;
        buf_vlan[17] = 0xb8;
        assert!(is_goose_frame(&buf_vlan));

        // Not a GOOSE frame (wrong EtherType)
        let mut buf_wrong = [0u8; 60];
        buf_wrong[12] = 0x08;
        buf_wrong[13] = 0x00;
        assert!(!is_goose_frame(&buf_wrong));

        // Not a GOOSE frame (VLAN tag present, wrong EtherType)
        let mut buf_vlan_wrong = [0u8; 60];
        buf_vlan_wrong[12] = 0x81;
        buf_vlan_wrong[13] = 0x00;
        buf_vlan_wrong[16] = 0x08;
        buf_vlan_wrong[17] = 0x00;
        assert!(!is_goose_frame(&buf_vlan_wrong));

        // Buffer just too short for EtherType without VLAN
        let short_buf = [0u8; 13];
        assert!(!is_goose_frame(&short_buf));

        // Buffer just too short for EtherType with VLAN
        let mut short_vlan_buf = [0u8; 17];
        short_vlan_buf[12] = 0x81;
        short_vlan_buf[13] = 0x00;
        assert!(!is_goose_frame(&short_vlan_buf));
    }

    #[test]
    fn test_goose_decode_performance() {
        use std::time::Instant;

        let buf: &[u8] = &[
            1, 12, 205, 1, 0, 1, 0, 26, 182, 3, 47, 28, 129, 0, 0, 1, 136, 184, 16, 1, 0, 140, 0,
            0, 0, 0, 97, 129, 129, 128, 17, 73, 69, 68, 49, 47, 76, 76, 78, 48, 36, 71, 79, 36,
            103, 99, 98, 49, 129, 2, 7, 208, 130, 18, 73, 69, 68, 49, 47, 76, 76, 78, 48, 36, 68,
            65, 84, 65, 83, 69, 84, 49, 131, 6, 71, 79, 79, 83, 69, 49, 132, 8, 32, 33, 6, 18, 10,
            48, 0, 0, 133, 1, 1, 134, 1, 42, 135, 1, 0, 136, 2, 0, 128, 137, 1, 0, 138, 1, 11, 171,
            47, 134, 1, 1, 134, 2, 0, 128, 134, 2, 0, 255, 134, 1, 127, 134, 1, 1, 134, 2, 0, 128,
            134, 2, 0, 255, 131, 1, 255, 133, 4, 127, 255, 255, 255, 133, 5, 0, 128, 0, 0, 0, 138,
            4, 116, 101, 115, 116,
        ];

        let iterations = 10_000;

        let start = Instant::now();
        for _ in 0..iterations {
            let mut header = EthernetHeader::default();
            let pos = decode_ethernet_header(&mut header, &buf);
            let _ = decode_goose_pdu(&buf, pos);
        }
        let duration = start.elapsed();

        let avg_ns = duration.as_nanos() / iterations;
        let avg_us = avg_ns as f64 / 1000.0;

        println!("\n=== GOOSE Decode Performance ===");
        println!("Iterations: {}", iterations);
        println!("Total time: {:?}", duration);
        println!("Average per decode: {} ns ({:.3} μs)", avg_ns, avg_us);
        println!(
            "Theoretical max rate: {:.0} Hz ({:.1} kHz)",
            1_000_000.0 / avg_us,
            (1_000_000.0 / avg_us) / 1000.0
        );

        // GOOSE is much slower than SMV, typical rates are 50-1000 Hz
        // So we have much more relaxed requirements: < 1ms (1000 μs)
        assert!(
            avg_us < 1000.0,
            "Decode too slow: {:.3} μs (should be < 1000 μs for 1 kHz rate)",
            avg_us
        );
    }

    #[test]
    fn test_goose_encode_performance() {
        use crate::types::{EthernetHeader, IECData, IECGoosePdu, TimeQuality, Timestamp};
        use std::time::Instant;

        let header = EthernetHeader {
            dst_addr: [0x01, 0x0c, 0xcd, 0x01, 0x00, 0x01],
            src_addr: [0x00, 0x1a, 0xb6, 0x03, 0x2f, 0x1c],
            tpid: Some([0x81, 0x00]),
            tci: Some([0x00, 0x01]),
            ether_type: [0x88, 0xb8],
            appid: [0x10, 0x01],
            length: [0x00, 0x8c],
        };

        let pdu = IECGoosePdu {
            go_cb_ref: "IED1/LLN0$GO$gcb1".to_string(),
            time_allowed_to_live: 2000,
            dat_set: "IED1/LLN0$DATASET1".to_string(),
            go_id: "GOOSE1".to_string(),
            t: Timestamp {
                seconds: 539035154,
                fraction: 667648,
                quality: TimeQuality::default(),
            },
            st_num: 1,
            sq_num: 42,
            simulation: false,
            conf_rev: 128,
            nds_com: false,
            num_dat_set_entries: 11,
            all_data: vec![
                IECData::UInt(1),
                IECData::UInt(0x80),
                IECData::UInt(0xFF),
                IECData::UInt(0x7F),
                IECData::UInt(1),
                IECData::UInt(0x80),
                IECData::UInt(0xFF),
                IECData::Boolean(true),
                IECData::Int(2147483647),
                IECData::Int(2147483648),
                IECData::VisibleString("test".to_string()),
            ],
        };

        let iterations = 10_000;

        let start = Instant::now();
        for _ in 0..iterations {
            let _ = encode_goose(&header, &pdu);
        }
        let duration = start.elapsed();

        let avg_ns = duration.as_nanos() / iterations;
        let avg_us = avg_ns as f64 / 1000.0;

        println!("\n=== GOOSE Encode Performance ===");
        println!("Iterations: {}", iterations);
        println!("Total time: {:?}", duration);
        println!("Average per encode: {} ns ({:.3} μs)", avg_ns, avg_us);
        println!(
            "Theoretical max rate: {:.0} Hz ({:.1} kHz)",
            1_000_000.0 / avg_us,
            (1_000_000.0 / avg_us) / 1000.0
        );

        // Same requirement as decode
        assert!(
            avg_us < 1000.0,
            "Encode too slow: {:.3} μs (should be < 1000 μs for 1 kHz rate)",
            avg_us
        );
    }

    #[test]
    fn test_goose_roundtrip_performance() {
        use crate::types::{EthernetHeader, IECData, IECGoosePdu, TimeQuality, Timestamp};
        use std::time::Instant;

        let header = EthernetHeader {
            dst_addr: [0x01, 0x0c, 0xcd, 0x01, 0x00, 0x01],
            src_addr: [0x00, 0x1a, 0xb6, 0x03, 0x2f, 0x1c],
            tpid: Some([0x81, 0x00]),
            tci: Some([0x00, 0x01]),
            ether_type: [0x88, 0xb8],
            appid: [0x10, 0x01],
            length: [0x00, 0x8c],
        };

        let pdu = IECGoosePdu {
            go_cb_ref: "IED1/LLN0$GO$gcb1".to_string(),
            time_allowed_to_live: 2000,
            dat_set: "IED1/LLN0$DATASET1".to_string(),
            go_id: "GOOSE1".to_string(),
            t: Timestamp {
                seconds: 539035154,
                fraction: 667648,
                quality: TimeQuality::default(),
            },
            st_num: 1,
            sq_num: 42,
            simulation: false,
            conf_rev: 128,
            nds_com: false,
            num_dat_set_entries: 11,
            all_data: vec![
                IECData::UInt(1),
                IECData::UInt(0x80),
                IECData::UInt(0xFF),
                IECData::UInt(0x7F),
                IECData::UInt(1),
                IECData::UInt(0x80),
                IECData::UInt(0xFF),
                IECData::Boolean(true),
                IECData::Int(2147483647),
                IECData::Int(2147483648),
                IECData::VisibleString("test".to_string()),
            ],
        };

        let iterations = 10_000;

        let start = Instant::now();
        for _ in 0..iterations {
            let encoded = encode_goose(&header, &pdu).unwrap();
            let mut decoded_header = EthernetHeader::default();
            let pos = decode_ethernet_header(&mut decoded_header, &encoded);
            let _ = decode_goose_pdu(&encoded, pos);
        }
        let duration = start.elapsed();

        let avg_ns = duration.as_nanos() / iterations;
        let avg_us = avg_ns as f64 / 1000.0;

        println!("\n=== GOOSE Encode+Decode Roundtrip Performance ===");
        println!("Iterations: {}", iterations);
        println!("Total time: {:?}", duration);
        println!("Average per roundtrip: {} ns ({:.3} μs)", avg_ns, avg_us);
        println!(
            "Theoretical max rate: {:.0} Hz ({:.1} kHz)",
            1_000_000.0 / avg_us,
            (1_000_000.0 / avg_us) / 1000.0
        );

        // Roundtrip should still be fast enough for 500 Hz
        assert!(
            avg_us < 2000.0,
            "Roundtrip too slow: {:.3} μs (should be < 2000 μs for 500 Hz rate)",
            avg_us
        );
    }
}
