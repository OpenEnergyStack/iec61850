use crate::types::EthernetHeader;

/// Decodes an Ethernet header from the buffer at the specified position,
/// writing the result into the provided mutable reference.
///
/// # Parameters
/// - `header`: A mutable reference where the decoded EthernetHeader will be stored.
/// - `buffer`: The input byte slice containing the encoded Ethernet header.
///
/// # Returns
/// The next position in the buffer after reading the Ethernet header.
///
/// # Panics
/// Panics if the buffer does not contain enough bytes to decode the header.
pub fn decode_ethernet_header(header: &mut EthernetHeader, buffer: &[u8]) -> usize {
    let mut new_pos = 0;

    header
        .dst_addr
        .copy_from_slice(&buffer[new_pos..new_pos + 6]);
    new_pos += 6;

    header
        .src_addr
        .copy_from_slice(&buffer[new_pos..new_pos + 6]);
    new_pos += 6;

    // VLAN tag present
    if buffer[new_pos..new_pos + 2] == [0x81, 0x00] {
        let mut tpid = [0u8; 2];
        tpid.copy_from_slice(&buffer[new_pos..new_pos + 2]);
        header.tpid = Some(tpid);
        new_pos += 2;
        let mut tci = [0u8; 2];
        tci.copy_from_slice(&buffer[new_pos..new_pos + 2]);
        header.tci = Some(tci);
        new_pos += 2;
    } else {
        header.tpid = None;
        header.tci = None;
    }

    header
        .ether_type
        .copy_from_slice(&buffer[new_pos..new_pos + 2]);
    new_pos += 2;

    header.appid.copy_from_slice(&buffer[new_pos..new_pos + 2]);
    new_pos += 2;

    header.length.copy_from_slice(&buffer[new_pos..new_pos + 2]);
    new_pos += 2;

    new_pos += 2; // reserved 1
    new_pos += 2; // reserved 2

    new_pos
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decode_ethernet_header_without_vlan() {
        let buffer: Vec<u8> = vec![
            // Destination MAC: 01:0c:cd:01:00:01
            0x01, 0x0c, 0xcd, 0x01, 0x00, 0x01, // Source MAC: 00:1a:b6:03:2f:1c
            0x00, 0x1a, 0xb6, 0x03, 0x2f, 0x1c, // EtherType: 0x88b8 (GOOSE)
            0x88, 0xb8, // APPID: 0x1001
            0x10, 0x01, // Length: 0x008c (140 bytes)
            0x00, 0x8c, // Reserved1: 0x0000
            0x00, 0x00, // Reserved2: 0x0000
            0x00, 0x00,
        ];

        let mut header = EthernetHeader::default();
        let pos = decode_ethernet_header(&mut header, &buffer);

        // Check destination MAC
        assert_eq!(header.dst_addr, [0x01, 0x0c, 0xcd, 0x01, 0x00, 0x01]);

        // Check source MAC
        assert_eq!(header.src_addr, [0x00, 0x1a, 0xb6, 0x03, 0x2f, 0x1c]);

        // Check no VLAN tags
        assert_eq!(header.tpid, None);
        assert_eq!(header.tci, None);

        // Check EtherType (GOOSE)
        assert_eq!(header.ether_type, [0x88, 0xb8]);

        // Check APPID
        assert_eq!(header.appid, [0x10, 0x01]);

        // Check Length
        assert_eq!(header.length, [0x00, 0x8c]);

        // Check position (12 MAC + 2 EtherType + 2 APPID + 2 Length + 4 Reserved = 22)
        assert_eq!(pos, 22);
    }

    #[test]
    fn test_decode_ethernet_header_with_vlan() {
        let buffer: Vec<u8> = vec![
            // Destination MAC: 01:0c:cd:01:00:01
            0x01, 0x0c, 0xcd, 0x01, 0x00, 0x01, // Source MAC: 00:1a:b6:03:2f:1c
            0x00, 0x1a, 0xb6, 0x03, 0x2f, 0x1c, // VLAN TPID: 0x8100
            0x81, 0x00, // VLAN TCI: 0x0001
            0x00, 0x01, // EtherType: 0x88b8 (GOOSE)
            0x88, 0xb8, // APPID: 0x1001
            0x10, 0x01, // Length: 0x008c (140 bytes)
            0x00, 0x8c, // Reserved1: 0x0000
            0x00, 0x00, // Reserved2: 0x0000
            0x00, 0x00,
        ];

        let mut header = EthernetHeader::default();
        let pos = decode_ethernet_header(&mut header, &buffer);

        // Check destination MAC
        assert_eq!(header.dst_addr, [0x01, 0x0c, 0xcd, 0x01, 0x00, 0x01]);

        // Check source MAC
        assert_eq!(header.src_addr, [0x00, 0x1a, 0xb6, 0x03, 0x2f, 0x1c]);

        // Check VLAN tags present
        assert_eq!(header.tpid, Some([0x81, 0x00]));
        assert_eq!(header.tci, Some([0x00, 0x01]));

        // Check EtherType (GOOSE)
        assert_eq!(header.ether_type, [0x88, 0xb8]);

        // Check APPID
        assert_eq!(header.appid, [0x10, 0x01]);

        // Check Length
        assert_eq!(header.length, [0x00, 0x8c]);

        // Check position (12 MAC + 4 VLAN + 2 EtherType + 2 APPID + 2 Length + 4 Reserved = 26)
        assert_eq!(pos, 26);
    }

    #[test]
    fn test_decode_ethernet_header_from_real_goose_frame() {
        // Real GOOSE frame from your test data
        let buffer: Vec<u8> = vec![
            1, 12, 205, 1, 0, 1, 0, 26, 182, 3, 47, 28, 129, 0, 0, 1, 136, 184, 16, 1, 0, 140, 0,
            0, 0, 0,
        ];

        let mut header = EthernetHeader::default();
        let pos = decode_ethernet_header(&mut header, &buffer);

        // Check destination MAC: 01:0c:cd:01:00:01
        assert_eq!(header.dst_addr, [0x01, 0x0c, 0xcd, 0x01, 0x00, 0x01]);

        // Check source MAC: 00:1a:b6:03:2f:1c
        assert_eq!(header.src_addr, [0x00, 0x1a, 0xb6, 0x03, 0x2f, 0x1c]);

        // Check VLAN present: TPID=0x8100, TCI=0x0001
        assert_eq!(header.tpid, Some([0x81, 0x00]));
        assert_eq!(header.tci, Some([0x00, 0x01]));

        // Check EtherType: 0x88b8 (GOOSE)
        assert_eq!(header.ether_type, [0x88, 0xb8]);

        // Check APPID: 0x1001
        assert_eq!(header.appid, [0x10, 0x01]);

        // Check Length: 0x008c (140 bytes)
        assert_eq!(header.length, [0x00, 0x8c]);

        // Position should be at byte 26 (start of GOOSE PDU)
        assert_eq!(pos, 26);
    }

    #[test]
    #[should_panic]
    fn test_decode_ethernet_header_buffer_too_short() {
        let buffer: Vec<u8> = vec![0x01, 0x02, 0x03]; // Too short
        let mut header = EthernetHeader::default();
        decode_ethernet_header(&mut header, &buffer);
    }
}
