use crate::types::{EncodeError, EthernetHeader, Sample, SavAsdu, SavPdu};

/// Calculates the encoded length of an unsigned integer value
/// Takes into account the extra 0x00 byte needed when MSB is set
fn unsigned_integer_length(value: &[u8]) -> usize {
    // For unsigned integers, strip leading zeros (but not 0xFF like signed integers)
    let mut start = 0;
    while start < value.len() - 1 && value[start] == 0x00 {
        start += 1;
    }
    let minimal = &value[start..];

    // If MSB is set, we need to prepend a zero byte
    if !minimal.is_empty() && (minimal[0] & 0x80) != 0 {
        minimal.len() + 1
    } else {
        minimal.len()
    }
}

/// Sampled Value data set is reduced to 4 byte value + 4 byte quality per sample
fn samples_length(samples: &[Sample]) -> usize {
    samples.len() * (4 + 4) // Each sample has 4 bytes for value and 4 bytes for quality
}

/// Calculates the encoded length of a single ASDU
/// Returns the size in bytes of the ASDU data (without the 0x30 wrapper tag/length)
fn asdu_length(asdu: &SavAsdu) -> usize {
    let mut length = 0;

    // svID (tag 0x80)
    length += 1 + 1 + asdu.msv_id.len(); // tag + length + value

    // datSet (optional, tag 0x81)
    if let Some(ref dat_set) = asdu.dat_set {
        length += 1 + 1 + dat_set.len();
    }

    // smpCnt (tag 0x82) - Unsigned16
    let smp_cnt_len = unsigned_integer_length(&asdu.smp_cnt.to_be_bytes());
    length += 1 + 1 + smp_cnt_len; // tag + length + value

    // confRev (tag 0x83) - Unsigned32
    let conf_rev_len = unsigned_integer_length(&asdu.conf_rev.to_be_bytes());
    length += 1 + 1 + conf_rev_len;

    // refrTm (optional, tag 0x84)
    if asdu.refr_tm.is_some() {
        length += 1 + 1 + 8; // tag + length + 8 bytes
    }

    // smpSynch (tag 0x85) - Unsigned8
    let smp_synch_len = unsigned_integer_length(&asdu.smp_synch.to_be_bytes());
    length += 1 + 1 + smp_synch_len;

    // smpRate (optional, tag 0x86) - Unsigned16
    if let Some(smp_rate) = asdu.smp_rate {
        let smp_rate_len = unsigned_integer_length(&smp_rate.to_be_bytes());
        length += 1 + 1 + smp_rate_len;
    }

    // Sample values (tag 0x87)
    let samples_data_len = samples_length(&asdu.all_data);
    let samples_len_field = size_length(samples_data_len);
    length += 1 + samples_len_field + samples_data_len; // tag + length + data

    // smpMod (optional, tag 0x88) - Unsigned16
    if let Some(smp_mod) = asdu.smp_mod {
        let smp_mod_len = unsigned_integer_length(&smp_mod.to_be_bytes());
        length += 1 + 1 + smp_mod_len;
    }

    // gmIdentity (optional, tag 0x89)
    if asdu.gm_identity.is_some() {
        length += 1 + 1 + 8;
    }

    length
}

/// Calculates the encoded length of the PDU (without the 0x60 wrapper tag/length)
fn pdu_length(pdu: &SavPdu) -> usize {
    let mut length = 0;

    // noASDU (tag 0x80) - Unsigned16
    let no_asdu_len = unsigned_integer_length(&pdu.no_asdu.to_be_bytes());
    length += 1 + 1 + no_asdu_len; // tag + length + value

    // Security (optional, tag 0x81) - ANY OPTIONAL type
    if let Some(security_data) = &pdu.security {
        let security_len = security_data.len();
        let security_len_field = size_length(security_len);
        length += 1 + security_len_field + security_len; // tag + length + data
    }

    // ASDUs wrapper (tag 0xA2)
    let mut asdus_data_len = 0;
    for asdu in &pdu.sav_asdu {
        let asdu_data_len = asdu_length(asdu);
        let asdu_len_field = size_length(asdu_data_len);
        asdus_data_len += 1 + asdu_len_field + asdu_data_len; // tag + length + data
    }
    let asdus_len_field = size_length(asdus_data_len);
    length += 1 + asdus_len_field + asdus_data_len;

    length
}

/// Calculates the required buffer size for encoding an SMV packet
///
/// # Parameters
/// - `header`: The Ethernet header
/// - `pdu`: The SavPdu to encode
///
/// # Returns
/// The total size in bytes needed for the complete packet
fn smv_size(header: &EthernetHeader, pdu: &SavPdu) -> usize {
    // Ethernet header size
    let header_size = if header.tpid.is_some() && header.tci.is_some() {
        26 // With VLAN: 6 (dst) + 6 (src) + 4 (VLAN) + 2 (type) + 2 (appid) + 2 (length) + 4 (reserved)
    } else {
        22 // Without VLAN: 6 (dst) + 6 (src) + 2 (type) + 2 (appid) + 2 (length) + 4 (reserved)
    };

    // Calculate PDU size using pdu_length()
    let pdu_data_len = pdu_length(pdu);
    let pdu_len_field = size_length(pdu_data_len);
    let total_pdu_size = 1 + pdu_len_field + pdu_data_len; // tag 0x60 + length field + data

    header_size + total_pdu_size
}

/// Returns the number of bytes required to encode the length field in ASN.1 BER format.
///
/// This function determines how many bytes are needed to represent the given length value
/// according to BER rules:
/// - 1 byte for values < 128 (short form)
/// - 2 bytes for values < 256 (0x81 + 1 byte)
/// - 3 bytes for values < 65536 (0x82 + 2 bytes)
/// - 4 bytes for larger values (0x83 + 3 bytes)
fn size_length(value: usize) -> usize {
    if value < 128 {
        1
    } else if value < 256 {
        2
    } else if value < 65535 {
        3
    } else {
        4
    }
}

/// Encodes an ASN.1 BER element (tag, length, value) into the buffer at the given position.
///
/// # Parameters
/// - `tag`: The ASN.1 tag to write.
/// - `value`: The value bytes to encode.
/// - `buffer`: The output buffer.
/// - `buffer_index`: The position in the buffer to start writing.
///
/// # Returns
/// Result with the new position in the buffer after writing, or EncodeError.
fn encode_ber(
    tag: u8,
    value: &[u8],
    buffer: &mut [u8],
    buffer_index: usize,
) -> Result<usize, EncodeError> {
    // Calculate required space: tag + length + value
    let length_field_size = size_length(value.len());
    let total_size = 1 + length_field_size + value.len();

    if buffer.len() < buffer_index + total_size {
        return Err(EncodeError::new(
            "Buffer does not have enough capacity to encode the BER element.",
            buffer_index,
        ));
    }

    // Write tag and length
    let mut pos = encode_tag_length(tag, value.len(), buffer, buffer_index)?;
    // Write value
    buffer[pos..pos + value.len()].copy_from_slice(value);
    pos += value.len();

    Ok(pos)
}

/// Encodes an unsigned integer in ASN.1 BER format with a leading zero byte to ensure positive interpretation.
///
/// # Parameters
/// - `tag`: A `u8` representing the ASN.1 tag for the unsigned integer type.
/// - `value`: A slice of `u8` containing the unsigned integer in big-endian format.
/// - `buffer`: A mutable slice of `u8` where the encoded data will be written.
/// - `buffer_index`: The starting position in the buffer to write the encoded data.
///
/// # Returns
/// Result with the new position in the buffer after writing the encoded unsigned integer, or EncodeError.
fn encode_unsigned_integer(
    tag: u8,
    value: &[u8],
    buffer: &mut [u8],
    buffer_index: usize,
) -> Result<usize, EncodeError> {
    // For unsigned integers, strip leading zeros but NOT leading 0xFF bytes
    // (unlike signed integers where 0xFF is sign extension)
    let mut start = 0;
    while start < value.len() - 1 && value[start] == 0x00 {
        start += 1;
    }
    let minimal = &value[start..];

    // If MSB is set, prepend a zero byte to ensure positive interpretation
    if !minimal.is_empty() && (minimal[0] & 0x80) != 0 {
        let mut prepend = [0u8; 1 + 8];
        prepend[0] = 0x00;
        prepend[1..1 + minimal.len()].copy_from_slice(minimal);
        encode_ber(tag, &prepend[..1 + minimal.len()], buffer, buffer_index)
    } else {
        encode_ber(tag, minimal, buffer, buffer_index)
    }
}

/// Encodes an ASN.1 octet string using BER rules.
///
/// # Parameters
/// - `tag`: The ASN.1 tag to write.
/// - `value`: A slice of `u8` containing the octet string to encode.
/// - `buffer`: A mutable slice of `u8` where the encoded data will be written.
/// - `buffer_index`: The starting position in the buffer to write the encoded data.
///
/// # Returns
/// Result with the new position in the buffer after writing the encoded octet string, or EncodeError.
fn encode_octet_string(
    tag: u8,
    value: &[u8],
    buffer: &mut [u8],
    buffer_index: usize,
) -> Result<usize, EncodeError> {
    encode_ber(tag, value, buffer, buffer_index)
}

/// # Parameters
/// - `tag`: A `u8` representing the tag to be written to the buffer.
/// - `value`: A `String` reference containing the string to encode.
/// - `buffer`: A mutable slice of `u8` where the encoded data will be written.
/// - `buffer_index`: The starting position in the buffer to write the encoded data.
///
/// # Returns
/// Result with the new position in the buffer after writing the encoded string, or EncodeError.
fn encode_string(
    tag: u8,
    value: &str,
    buffer: &mut [u8],
    buffer_index: usize,
) -> Result<usize, EncodeError> {
    let bytes = value.as_bytes();
    encode_ber(tag, bytes, buffer, buffer_index)
}

/// Encodes an ASN.1 tag and its length field using BER rules.
///
/// This function writes the tag and the length field into the provided buffer at `buffer_index`.
/// The length is encoded in short or long form depending on its value:
/// - For values < 128, the length is encoded in a single byte.
/// - For values < 256, the length is encoded as 0x81 followed by one byte.
/// - For values < 65536, the length is encoded as 0x82 followed by two bytes (big-endian).
/// - For larger values, the length is encoded as 0x83 followed by three bytes (big-endian).
///
/// # Parameters
/// - `tag`: The ASN.1 tag to write.
/// - `value`: The length value to encode.
/// - `buffer`: The output buffer.
/// - `buffer_index`: The position in the buffer to start writing.
///
/// # Returns
/// Result with the new position in the buffer after writing the tag and length, or EncodeError.
fn encode_tag_length(
    tag: u8,
    value: usize,
    buffer: &mut [u8],
    buffer_index: usize,
) -> Result<usize, EncodeError> {
    let required = 1 + size_length(value); // 1 for tag, rest for length field

    if buffer.len() < buffer_index + required {
        return Err(EncodeError::new(
            "Buffer too small to write tag and length.",
            buffer_index,
        ));
    }

    let mut new_pos = buffer_index;
    buffer[new_pos] = tag;
    new_pos += 1;

    // Now encode the length field as before
    if value < 128 {
        buffer[new_pos] = value as u8;
        new_pos += 1;
    } else if value < 256 {
        buffer[new_pos] = 0x81;
        new_pos += 1;
        buffer[new_pos] = value as u8;
        new_pos += 1;
    } else if value < 65535 {
        buffer[new_pos] = 0x82;
        new_pos += 1;
        buffer[new_pos] = (value >> 8) as u8;
        new_pos += 1;
        buffer[new_pos] = (value & 0xff) as u8;
        new_pos += 1;
    } else {
        if value >= 1 << 24 {
            return Err(EncodeError::new(
                "Value exceeds the maximum range for three-byte encoding (2^24 - 1).",
                buffer_index,
            ));
        }
        buffer[new_pos] = 0x83;
        new_pos += 1;
        buffer[new_pos] = (value >> 16) as u8;
        new_pos += 1;
        buffer[new_pos] = ((value >> 8) & 0xff) as u8;
        new_pos += 1;
        buffer[new_pos] = (value & 0xff) as u8;
        new_pos += 1;
    }

    Ok(new_pos)
}

/// Encodes a sample (value + quality) as ASN.1 BER sequence
fn encode_sample(buffer: &mut [u8], mut pos: usize, sample: &Sample) -> Result<usize, EncodeError> {
    let scaled = (sample.value / sample.scale_factor).round();

    if scaled < i32::MIN as f32 || scaled > i32::MAX as f32 {
        return Err(EncodeError::new(
            "Sample value is out of range for 32-bit signed integer after scaling.",
            pos,
        ));
    }

    let value_int32 = scaled as i32;

    let bytes = value_int32.to_be_bytes();
    buffer[pos..pos + 4].copy_from_slice(&bytes);
    pos += 4;

    // Encodes the quality as a BIT STRING with 32 bits as defined in IEC 61850-9-2
    let quality_u32 = sample.quality.to_sv();
    let quality_bytes = quality_u32.to_be_bytes();
    buffer[pos..pos + 4].copy_from_slice(&quality_bytes);
    pos += 4;

    Ok(pos)
}

/// Encodes all samples in the ASDU
fn encode_samples(
    buffer: &mut [u8],
    mut pos: usize,
    samples: &[Sample],
) -> Result<usize, EncodeError> {
    let len = samples_length(samples);
    pos = encode_tag_length(0x87, len, buffer, pos)?;
    for sample in samples {
        pos = encode_sample(buffer, pos, sample)?;
    }

    Ok(pos)
}

/// Encodes a single SavAsdu
fn encode_sav_asdu(
    buffer: &mut [u8],
    mut pos: usize,
    asdu: &SavAsdu,
) -> Result<usize, EncodeError> {
    let len = asdu_length(asdu);

    pos = encode_tag_length(0x30, len, buffer, pos)?; // Placeholder for SEQUENCE tag
                                                      // svID (tag 0x80) - Visible String
    pos = encode_string(0x80, &asdu.msv_id, buffer, pos)?;

    // Optional datSet (tag 0x81)
    if let Some(ref dat_set) = asdu.dat_set {
        pos = encode_string(0x81, dat_set, buffer, pos)?;
    }

    // smpCnt (tag 0x82) - Unsigned16
    pos = encode_unsigned_integer(0x82, &asdu.smp_cnt.to_be_bytes(), buffer, pos)?;

    // confRev (tag 0x83) - Unsigned32
    pos = encode_unsigned_integer(0x83, &asdu.conf_rev.to_be_bytes(), buffer, pos)?;

    // Optional refrTm (tag 0x84) - 8 bytes
    if let Some(ref refr_tm) = asdu.refr_tm {
        pos = encode_octet_string(0x84, refr_tm, buffer, pos)?;
    }

    // smpSynch (tag 0x85) - Unsigned8
    pos = encode_unsigned_integer(0x85, &asdu.smp_synch.to_be_bytes(), buffer, pos)?;

    // Optional smpRate (tag 0x86) - Unsigned16
    if let Some(smp_rate) = asdu.smp_rate {
        pos = encode_unsigned_integer(0x86, &smp_rate.to_be_bytes(), buffer, pos)?;
    }

    // Sample values (tag 0x87) - SEQUENCE of samples
    pos = encode_samples(buffer, pos, &asdu.all_data)?;

    // Optional smpMod (tag 0x88) - Unsigned16
    if let Some(smp_mod) = asdu.smp_mod {
        pos = encode_unsigned_integer(0x88, &smp_mod.to_be_bytes(), buffer, pos)?;
    }

    // Optional gmIdentity (tag 0x89) - 8 bytes
    if let Some(ref gm_identity) = asdu.gm_identity {
        pos = encode_octet_string(0x89, gm_identity, buffer, pos)?;
    }

    Ok(pos)
}

/// Encodes the complete SMV PDU (without Ethernet header)
fn encode_sav_pdu(buffer: &mut [u8], mut pos: usize, pdu: &SavPdu) -> Result<usize, EncodeError> {
    // Calculate lengths for all components
    let data_len = pdu_length(pdu);

    // Calculate ASDUs length
    let mut asdus_len = 0;
    for asdu in &pdu.sav_asdu {
        let asdu_data_len = asdu_length(asdu);
        let asdu_len_field = size_length(asdu_data_len);
        asdus_len += 1 + asdu_len_field + asdu_data_len;
    }

    // Wrap entire PDU in tag 0x60
    pos = encode_tag_length(0x60, data_len, buffer, pos)?;

    // noASDU (tag 0x80) - Number of ASDUs
    pos = encode_unsigned_integer(0x80, &pdu.no_asdu.to_be_bytes(), buffer, pos)?;

    // Security (optional, tag 0x81) - ANY OPTIONAL type
    if let Some(security_data) = &pdu.security {
        pos = encode_octet_string(0x81, security_data, buffer, pos)?;
    }

    // Wrap ASDUs in SEQUENCE tag (0xA2)
    pos = encode_tag_length(0xA2, asdus_len, buffer, pos)?;

    // Encode all ASDUs
    for asdu in &pdu.sav_asdu {
        pos = encode_sav_asdu(buffer, pos, asdu)?;
    }

    Ok(pos)
}

/// Encodes an Ethernet header for IEC 61850 protocols (GOOSE/SMV)
///
/// # Parameters
/// - `header`: The EthernetHeader structure to encode
/// - `length`: The length field value (payload + 8 bytes for APPID, length, reserved fields)
///
/// # Returns
/// A byte vector containing the encoded Ethernet header (22 bytes without VLAN, 26 with VLAN)
fn encode_ethernet_header(buffer: &mut [u8], header: &EthernetHeader, length: u16) -> usize {
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

    // EtherType (0x88B8 for GOOSE, 0x88BA for SMV)
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
    new_pos += 2;

    new_pos
}

/// Encodes a complete SMV packet with preallocated buffer (convenience wrapper)
///
/// This version calculates the exact size needed, allocates a single buffer,
/// and writes directly using encode_*_buff functions without intermediate allocations.
///
/// # Parameters
/// - `buffer`: A mutable slice of u8 where the encoded packet will be written
/// - `header`: The Ethernet header to use
/// - `pdu`: The SavPdu to encode
///
/// # Returns
/// The encoded packet as a byte vector, or an EncodeError if encoding fails
#[allow(dead_code)]
pub fn encode_smv(header: &EthernetHeader, pdu: &SavPdu) -> Result<Vec<u8>, EncodeError> {
    let size = smv_size(header, pdu);
    let mut buffer = vec![0u8; size];

    let required_size = smv_size(header, pdu);

    if buffer.len() < required_size {
        return Err(EncodeError::BufferTooSmall {
            required: required_size,
            available: buffer.len(),
        });
    }

    // Calculate PDU length for Ethernet header
    let pdu_data_len = pdu_length(pdu);
    let pdu_len_field = size_length(pdu_data_len);
    let pdu_total_len = 1 + pdu_len_field + pdu_data_len;
    let length = pdu_total_len as u16 + 8;

    // Encode Ethernet header directly into buffer
    let pos = encode_ethernet_header(&mut buffer, header, length);

    // Set simulation bit in reserved1 field if needed
    let reserved1_offset = if header.tpid.is_some() && header.tci.is_some() {
        22
    } else {
        18
    };

    if pdu.sim {
        buffer[reserved1_offset] = 0x80;
    }

    // Encode PDU directly into buffer
    encode_sav_pdu(&mut buffer, pos, pdu)?;

    Ok(buffer)
}

#[cfg(test)]
mod tests {
    use crate::{
        rt_services::{
            decode_smv::decode_smv,
            encode_smv::{encode_smv, smv_size},
            ethernet_header::decode_ethernet_header,
        },
        types::{
            EthernetHeader, Quality, Sample, SavAsdu, SavDataSetConfig, SavPdu, SavValueConfig,
            Validity,
        },
    };

    const QUALITY: Quality = Quality {
        validity: Validity::Good,
        overflow: false,
        out_of_range: true,
        bad_reference: false,
        oscillatory: false,
        failure: true,
        old_data: false,
        inconsistent: true,
        inaccurate: false,
        source_substituted: true,
        test: false,
        operator_blocked: true,
    };

    #[test]
    fn test_encode_decode_roundtrip_simple() {
        // Create a simple SMV packet
        let header = EthernetHeader {
            dst_addr: [0x01, 0x0c, 0xcd, 0x04, 0x00, 0x01],
            src_addr: [0x00, 0x1a, 0xb6, 0x03, 0x2f, 0x1c],
            tpid: None,
            tci: None,
            ether_type: [0x88, 0xba], // SMV EtherType
            appid: [0x40, 0x01],
            length: [0x00, 0x00], // Will be calculated
        };

        let samples = vec![
            Sample::new(1.0, QUALITY, 0.001),
            Sample::new(-20.0, QUALITY, 0.01),
        ];

        let asdu = SavAsdu {
            msv_id: "TestSV01".to_string(),
            dat_set: None,
            smp_cnt: 100,
            conf_rev: 1,
            refr_tm: None,
            smp_synch: 1,
            smp_rate: Some(4000),
            all_data: samples.clone(),
            smp_mod: None,
            gm_identity: None,
        };

        let pdu = SavPdu {
            sim: false,
            no_asdu: 1,
            security: None,
            sav_asdu: vec![asdu],
        };

        // Encode
        let encoded = encode_smv(&header, &pdu).expect("Encoding failed");

        // Decode
        let mut decoded_header = EthernetHeader::default();
        let pos = decode_ethernet_header(&mut decoded_header, &encoded);
        let config =
            SavDataSetConfig::new(vec![SavValueConfig::new(0.001), SavValueConfig::new(0.01)]);
        let decoded_pdu = decode_smv(&encoded, pos, &config).expect("Decoding failed");

        // Verify header
        assert_eq!(decoded_header.dst_addr, header.dst_addr);
        assert_eq!(decoded_header.src_addr, header.src_addr);
        assert_eq!(decoded_header.ether_type, [0x88, 0xba]);
        assert_eq!(decoded_header.appid, header.appid);

        // Verify PDU
        assert_eq!(decoded_pdu.sim, pdu.sim);
        assert_eq!(decoded_pdu.no_asdu, pdu.no_asdu);
        assert_eq!(decoded_pdu.security, pdu.security);
        assert_eq!(decoded_pdu.sav_asdu.len(), 1);

        // Verify ASDU
        let decoded_asdu = &decoded_pdu.sav_asdu[0];
        let original_asdu = &pdu.sav_asdu[0];
        assert_eq!(decoded_asdu.msv_id, original_asdu.msv_id);
        assert_eq!(decoded_asdu.dat_set, original_asdu.dat_set);
        assert_eq!(decoded_asdu.smp_cnt, original_asdu.smp_cnt);
        assert_eq!(decoded_asdu.conf_rev, original_asdu.conf_rev);
        assert_eq!(decoded_asdu.refr_tm, original_asdu.refr_tm);
        assert_eq!(decoded_asdu.smp_synch, original_asdu.smp_synch);
        assert_eq!(decoded_asdu.smp_rate, original_asdu.smp_rate);
        assert_eq!(decoded_asdu.smp_mod, original_asdu.smp_mod);
        assert_eq!(decoded_asdu.gm_identity, original_asdu.gm_identity);

        // Verify samples
        assert_eq!(decoded_asdu.all_data.len(), samples.len());
        for (i, (decoded_sample, original_sample)) in
            decoded_asdu.all_data.iter().zip(samples.iter()).enumerate()
        {
            assert_eq!(
                decoded_sample.value, original_sample.value,
                "Sample {} value mismatch",
                i
            );
            assert_eq!(
                decoded_sample.quality.to_u16(),
                original_sample.quality.to_u16(),
                "Sample {} quality mismatch",
                i
            );
        }
    }

    #[test]
    fn test_length_calculation_exact_sample() {
        // Test with simple packet (no optional fields)
        let header = EthernetHeader {
            dst_addr: [0x01, 0x0c, 0xcd, 0x04, 0x00, 0x01],
            src_addr: [0x00, 0x1a, 0xb6, 0x03, 0x2f, 0x1c],
            tpid: None,
            tci: None,
            ether_type: [0x88, 0xba],
            appid: [0x40, 0x01],
            length: [0x00, 0x00],
        };

        let samples = vec![
            Sample::new(1.0, QUALITY, 0.001),
            Sample::new(-20.0, QUALITY, 0.01),
        ];

        let asdu = SavAsdu {
            msv_id: "TestSV01".to_string(),
            dat_set: None,
            smp_cnt: 100,
            conf_rev: 1,
            refr_tm: None,
            smp_synch: 1,
            smp_rate: Some(4000),
            all_data: samples,
            smp_mod: None,
            gm_identity: None,
        };

        let pdu = SavPdu {
            sim: false,
            no_asdu: 1,
            security: None,
            sav_asdu: vec![asdu],
        };

        // Calculate expected size
        let calculated_size = smv_size(&header, &pdu);

        // Encode with preallocated buffer
        let encoded = encode_smv(&header, &pdu).expect("Encoding failed");

        // Verify exact match (no truncation needed)
        assert_eq!(
            encoded.len(),
            calculated_size,
            "Length mismatch: calculated {}, actual {}",
            calculated_size,
            encoded.len()
        );
    }

    #[test]
    fn test_length_calculation_exact_with_optional_fields() {
        // Test with all optional fields present
        let header = EthernetHeader {
            dst_addr: [0x01, 0x0c, 0xcd, 0x04, 0x00, 0x01],
            src_addr: [0x00, 0x1a, 0xb6, 0x03, 0x2f, 0x1c],
            tpid: Some([0x81, 0x00]),
            tci: Some([0x00, 0x01]),
            ether_type: [0x88, 0xba],
            appid: [0x40, 0x01],
            length: [0x00, 0x00],
        };

        let samples = vec![
            Sample::new(1.0, QUALITY, 0.001),
            Sample::new(-20.0, QUALITY, 0.01),
        ];

        let asdu = SavAsdu {
            msv_id: "LongSvIdentifier01".to_string(),
            dat_set: Some("DataSet01".to_string()),
            smp_cnt: 5000,
            conf_rev: 123456,
            refr_tm: Some([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]),
            smp_synch: 2,
            smp_rate: Some(4800),
            all_data: samples.clone(),
            smp_mod: Some(1),
            gm_identity: Some([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11]),
        };

        let pdu = SavPdu {
            sim: true,
            no_asdu: 1,
            security: Some(vec![0x00; 10]),
            sav_asdu: vec![asdu],
        };

        let calculated_size = smv_size(&header, &pdu);
        let encoded = encode_smv(&header, &pdu).expect("Encoding failed");

        assert_eq!(
            encoded.len(),
            calculated_size,
            "Length mismatch with optional fields: calculated {}, actual {}",
            calculated_size,
            encoded.len()
        );

        // Decode and verify all fields
        let mut decoded_header = EthernetHeader::default();
        let pos = decode_ethernet_header(&mut decoded_header, &encoded);
        let config =
            SavDataSetConfig::new(vec![SavValueConfig::new(0.001), SavValueConfig::new(0.01)]);
        let decoded_pdu = decode_smv(&encoded, pos, &config).expect("Decoding failed");

        // Verify header including VLAN tags
        assert_eq!(decoded_header.dst_addr, header.dst_addr);
        assert_eq!(decoded_header.src_addr, header.src_addr);
        assert_eq!(decoded_header.tpid, header.tpid);
        assert_eq!(decoded_header.tci, header.tci);
        assert_eq!(decoded_header.ether_type, header.ether_type);
        assert_eq!(decoded_header.appid, header.appid);

        // Verify PDU fields
        assert_eq!(decoded_pdu.sim, pdu.sim);
        assert_eq!(decoded_pdu.no_asdu, pdu.no_asdu);
        assert_eq!(decoded_pdu.security, pdu.security);
        assert_eq!(decoded_pdu.sav_asdu.len(), 1);

        // Verify ASDU with all optional fields
        let decoded_asdu = &decoded_pdu.sav_asdu[0];
        let original_asdu = &pdu.sav_asdu[0];
        assert_eq!(decoded_asdu.msv_id, original_asdu.msv_id);
        assert_eq!(decoded_asdu.dat_set, original_asdu.dat_set);
        assert_eq!(decoded_asdu.smp_cnt, original_asdu.smp_cnt);
        assert_eq!(decoded_asdu.conf_rev, original_asdu.conf_rev);
        assert_eq!(decoded_asdu.refr_tm, original_asdu.refr_tm);
        assert_eq!(decoded_asdu.smp_synch, original_asdu.smp_synch);
        assert_eq!(decoded_asdu.smp_rate, original_asdu.smp_rate);
        assert_eq!(decoded_asdu.smp_mod, original_asdu.smp_mod);
        assert_eq!(decoded_asdu.gm_identity, original_asdu.gm_identity);

        // Verify all samples
        assert_eq!(decoded_asdu.all_data.len(), samples.len());
        for (i, (decoded_sample, original_sample)) in
            decoded_asdu.all_data.iter().zip(samples.iter()).enumerate()
        {
            assert_eq!(
                decoded_sample.value, original_sample.value,
                "Sample {} value mismatch",
                i
            );
            assert_eq!(
                decoded_sample.quality.to_u16(),
                original_sample.quality.to_u16(),
                "Sample {} quality mismatch",
                i
            );
        }
    }

    #[test]
    fn test_length_calculation_exact_multiple_asdus() {
        // Test with multiple ASDUs
        let header = EthernetHeader {
            dst_addr: [0x01, 0x0c, 0xcd, 0x04, 0x00, 0x01],
            src_addr: [0x00, 0x1a, 0xb6, 0x03, 0x2f, 0x1c],
            tpid: None,
            tci: None,
            ether_type: [0x88, 0xba],
            appid: [0x40, 0x01],
            length: [0x00, 0x00],
        };

        let asdu1 = SavAsdu {
            msv_id: "SV01".to_string(),
            dat_set: None,
            smp_cnt: 100,
            conf_rev: 1,
            refr_tm: None,
            smp_synch: 1,
            smp_rate: Some(4000),
            all_data: vec![
                Sample::new(0.1, QUALITY, 0.001),
                Sample::new(2.0, QUALITY, 0.01),
            ],
            smp_mod: None,
            gm_identity: None,
        };

        let asdu2 = SavAsdu {
            msv_id: "SV02".to_string(),
            dat_set: Some("DS02".to_string()),
            smp_cnt: 200,
            conf_rev: 2,
            refr_tm: Some([0x00; 8]),
            smp_synch: 2,
            smp_rate: Some(8000),
            all_data: vec![
                Sample::new(0.3, QUALITY, 0.001),
                Sample::new(4.0, QUALITY, 0.01),
                Sample::new(5.0, QUALITY, 0.01),
            ],
            smp_mod: Some(1),
            gm_identity: Some([0xFF; 8]),
        };

        let pdu = SavPdu {
            sim: false,
            no_asdu: 2,
            security: None,
            sav_asdu: vec![asdu1, asdu2],
        };

        let calculated_size = smv_size(&header, &pdu);
        let encoded = encode_smv(&header, &pdu).expect("Encoding failed");

        assert_eq!(
            encoded.len(),
            calculated_size,
            "Length mismatch with multiple ASDUs: calculated {}, actual {}",
            calculated_size,
            encoded.len()
        );
    }

    #[test]
    fn test_length_calculation_exact_large_packet() {
        // Test with a large packet (8 ASDUs x 32 samples)
        let header = EthernetHeader {
            dst_addr: [0x01, 0x0c, 0xcd, 0x04, 0x00, 0x01],
            src_addr: [0x00, 0x1a, 0xb6, 0x03, 0x2f, 0x1c],
            tpid: None,
            tci: None,
            ether_type: [0x88, 0xba],
            appid: [0x40, 0x01],
            length: [0x00, 0x00],
        };

        let mut asdus = Vec::new();
        for i in 0..8 {
            let mut samples = Vec::new();
            for j in 0..32 {
                samples.push(Sample::new((i * 1000 + j * 100) as f32, QUALITY, 0.001));
            }

            asdus.push(SavAsdu {
                msv_id: format!("SV{:02}", i),
                dat_set: Some(format!("DS{:02}", i)),
                smp_cnt: (i * 100) as u16,
                conf_rev: 1,
                refr_tm: Some([i as u8; 8]),
                smp_synch: 1,
                smp_rate: Some(4000),
                all_data: samples,
                smp_mod: Some(1),
                gm_identity: Some([i as u8; 8]),
            });
        }

        let pdu = SavPdu {
            sim: false,
            no_asdu: 8,
            security: None,
            sav_asdu: asdus,
        };

        let calculated_size = smv_size(&header, &pdu);
        let encoded = encode_smv(&header, &pdu).expect("Encoding failed");

        assert_eq!(
            encoded.len(),
            calculated_size,
            "Length mismatch with large packet: calculated {}, actual {}",
            calculated_size,
            encoded.len()
        );
    }

    #[test]
    fn test_roundtrip_with_vlan() {
        // Test VLAN tag encoding/decoding
        let header = EthernetHeader {
            dst_addr: [0x01, 0x0c, 0xcd, 0x04, 0x00, 0x01],
            src_addr: [0x00, 0x1a, 0xb6, 0x03, 0x2f, 0x1c],
            tpid: Some([0x81, 0x00]),
            tci: Some([0x20, 0x05]), // Priority 1, VLAN ID 5
            ether_type: [0x88, 0xba],
            appid: [0x40, 0x01],
            length: [0x00, 0x00],
        };

        let asdu = SavAsdu {
            msv_id: "VLAN_TEST".to_string(),
            dat_set: None,
            smp_cnt: 100,
            conf_rev: 1,
            refr_tm: None,
            smp_synch: 1,
            smp_rate: Some(4000),
            all_data: vec![
                Sample::new(1.0, QUALITY, 0.001),
                Sample::new(20.0, QUALITY, 0.01),
            ],
            smp_mod: None,
            gm_identity: None,
        };

        let pdu = SavPdu {
            sim: false,
            no_asdu: 1,
            security: None,
            sav_asdu: vec![asdu],
        };

        let encoded = encode_smv(&header, &pdu).expect("Encoding failed");
        let mut decoded_header = EthernetHeader::default();
        let pos = decode_ethernet_header(&mut decoded_header, &encoded);
        let config =
            SavDataSetConfig::new(vec![SavValueConfig::new(0.001), SavValueConfig::new(0.01)]);
        let result = decode_smv(&encoded, pos, &config);

        assert!(result.is_ok(), "Decoding failed: {:?}", result.err());
        assert_eq!(decoded_header.tpid, header.tpid);
        assert_eq!(decoded_header.tci, header.tci);
    }

    #[test]
    fn test_roundtrip_with_simulation_bit() {
        // Test simulation bit
        let header = EthernetHeader {
            dst_addr: [0x01, 0x0c, 0xcd, 0x04, 0x00, 0x01],
            src_addr: [0x00, 0x1a, 0xb6, 0x03, 0x2f, 0x1c],
            tpid: None,
            tci: None,
            ether_type: [0x88, 0xba],
            appid: [0x40, 0x01],
            length: [0x00, 0x00],
        };

        let asdu = SavAsdu {
            msv_id: "SIM_TEST".to_string(),
            dat_set: None,
            smp_cnt: 50,
            conf_rev: 1,
            refr_tm: None,
            smp_synch: 1,
            smp_rate: Some(4000),
            all_data: vec![Sample::new(500.0, QUALITY, 0.001)],
            smp_mod: None,
            gm_identity: None,
        };

        let pdu = SavPdu {
            sim: true, // Simulation bit set
            no_asdu: 1,
            security: None,
            sav_asdu: vec![asdu],
        };

        let encoded = encode_smv(&header, &pdu).expect("Encoding failed");
        let mut decoded_header = EthernetHeader::default();
        let pos = decode_ethernet_header(&mut decoded_header, &encoded);
        let config = SavDataSetConfig::new(vec![SavValueConfig::new(0.001)]);
        let result = decode_smv(&encoded, pos, &config);

        assert!(result.is_ok(), "Decoding failed: {:?}", result.err());
        // Verify simulation bit in reserved1 field
        let reserved1_offset = 18; // Without VLAN: 6 + 6 + 2 + 2 + 2
        assert_eq!(
            encoded[reserved1_offset], 0x80,
            "Simulation bit should be set"
        );
    }

    #[test]
    fn test_roundtrip_with_security() {
        // Test security field
        let header = EthernetHeader {
            dst_addr: [0x01, 0x0c, 0xcd, 0x04, 0x00, 0x01],
            src_addr: [0x00, 0x1a, 0xb6, 0x03, 0x2f, 0x1c],
            tpid: None,
            tci: None,
            ether_type: [0x88, 0xba],
            appid: [0x40, 0x01],
            length: [0x00, 0x00],
        };

        let asdu = SavAsdu {
            msv_id: "SEC_TEST".to_string(),
            dat_set: None,
            smp_cnt: 75,
            conf_rev: 1,
            refr_tm: None,
            smp_synch: 1,
            smp_rate: Some(4000),
            all_data: vec![Sample::new(750.0, QUALITY, 0.001)],
            smp_mod: None,
            gm_identity: None,
        };

        let pdu = SavPdu {
            sim: false,
            no_asdu: 1,
            security: Some(vec![0x00; 10]), // Security enabled
            sav_asdu: vec![asdu],
        };

        let encoded = encode_smv(&header, &pdu).expect("Encoding failed");
        let mut decoded_header = EthernetHeader::default();
        let pos = decode_ethernet_header(&mut decoded_header, &encoded);
        let config = SavDataSetConfig::new(vec![SavValueConfig::new(0.001)]);
        let result = decode_smv(&encoded, pos, &config);

        assert!(result.is_ok(), "Decoding failed: {:?}", result.err());
    }

    #[test]
    fn test_roundtrip_all_optional_fields() {
        // Test with ALL optional fields present
        let header = EthernetHeader {
            dst_addr: [0x01, 0x0c, 0xcd, 0x04, 0x00, 0x01],
            src_addr: [0x00, 0x1a, 0xb6, 0x03, 0x2f, 0x1c],
            tpid: Some([0x81, 0x00]),
            tci: Some([0x60, 0x0A]), // Priority 3, VLAN ID 10
            ether_type: [0x88, 0xba],
            appid: [0x40, 0x01],
            length: [0x00, 0x00],
        };

        let samples = vec![
            Sample::new(10.0, QUALITY, 0.001),
            Sample::new(-20.0, QUALITY, 0.001),
            Sample::new(30.0, QUALITY, 0.001),
            Sample::new(-32.768, QUALITY, 0.001),
            Sample::new(32.767, QUALITY, 0.001),
        ];

        let asdu = SavAsdu {
            msv_id: "FULL_ASDU_TEST_ID".to_string(),
            dat_set: Some("DataSet_Full_Test".to_string()),
            smp_cnt: 12345,
            conf_rev: 987654,
            refr_tm: Some([0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF]),
            smp_synch: 2,
            smp_rate: Some(4800),
            all_data: samples,
            smp_mod: Some(1),
            gm_identity: Some([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22]),
        };

        let pdu = SavPdu {
            sim: true,
            no_asdu: 1,
            security: Some(vec![0x00; 10]),
            sav_asdu: vec![asdu],
        };

        let encoded = encode_smv(&header, &pdu).expect("Encoding failed");
        let mut decoded_header = EthernetHeader::default();
        let pos = decode_ethernet_header(&mut decoded_header, &encoded);
        let config = SavDataSetConfig::new(vec![
            SavValueConfig::new(0.001),
            SavValueConfig::new(0.001),
            SavValueConfig::new(0.001),
            SavValueConfig::new(0.001),
            SavValueConfig::new(0.001),
        ]);
        let result = decode_smv(&encoded, pos, &config);

        assert!(result.is_ok(), "Decoding failed: {:?}", result.err());
        // Verify header
        assert_eq!(decoded_header.tpid, header.tpid);
        assert_eq!(decoded_header.tci, header.tci);
    }

    #[test]
    fn test_roundtrip_multiple_asdus() {
        // Test multiple ASDUs with different configurations
        let header = EthernetHeader {
            dst_addr: [0x01, 0x0c, 0xcd, 0x04, 0x00, 0x01],
            src_addr: [0x00, 0x1a, 0xb6, 0x03, 0x2f, 0x1c],
            tpid: None,
            tci: None,
            ether_type: [0x88, 0xba],
            appid: [0x40, 0x01],
            length: [0x00, 0x00],
        };

        let pdu = SavPdu {
            sim: false,
            no_asdu: 3,
            security: None,
            sav_asdu: vec![
                SavAsdu {
                    msv_id: "ASDU_01".to_string(),
                    dat_set: None,
                    smp_cnt: 100,
                    conf_rev: 1,
                    refr_tm: None,
                    smp_synch: 1,
                    smp_rate: Some(4000),
                    all_data: vec![
                        Sample::new(1.00, QUALITY, 0.01),
                        Sample::new(2.00, QUALITY, 0.01),
                    ],
                    smp_mod: None,
                    gm_identity: None,
                },
                SavAsdu {
                    msv_id: "ASDU_02_Full".to_string(),
                    dat_set: Some("DataSet02".to_string()),
                    smp_cnt: 200,
                    conf_rev: 2,
                    refr_tm: Some([0x11; 8]),
                    smp_synch: 2,
                    smp_rate: Some(8000),
                    all_data: vec![
                        Sample::new(1.00, QUALITY, 0.01),
                        Sample::new(2.00, QUALITY, 0.01),
                    ],
                    smp_mod: Some(1),
                    gm_identity: Some([0x22; 8]),
                },
                SavAsdu {
                    msv_id: "ASDU_03".to_string(),
                    dat_set: Some("DS3".to_string()),
                    smp_cnt: 300,
                    conf_rev: 3,
                    refr_tm: None,
                    smp_synch: 1,
                    smp_rate: None,
                    all_data: vec![
                        Sample::new(1.00, QUALITY, 0.01),
                        Sample::new(2.00, QUALITY, 0.01),
                    ],
                    smp_mod: Some(2),
                    gm_identity: None,
                },
            ],
        };

        let encoded = encode_smv(&header, &pdu).expect("Encoding failed");
        let mut decoded_header = EthernetHeader::default();
        let pos = decode_ethernet_header(&mut decoded_header, &encoded);
        // Just verify decoding succeeds without error
        let config =
            SavDataSetConfig::new(vec![SavValueConfig::new(0.01), SavValueConfig::new(0.01)]);
        decode_smv(&encoded, pos, &config).expect("Decoding failed");
    }

    #[test]
    fn test_roundtrip_extreme_values() {
        // Test extreme and boundary values
        let header = EthernetHeader {
            dst_addr: [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF],
            src_addr: [0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
            tpid: None,
            tci: None,
            ether_type: [0x88, 0xba],
            appid: [0xFF, 0xFF],
            length: [0x00, 0x00],
        };

        let samples = vec![
            Sample::new(i32::MAX as f32, QUALITY, 1.0), // Max positive i32, max quality
            Sample::new(i32::MIN as f32, QUALITY, 1.0), // Min negative i32, min quality
        ];

        let pdu = SavPdu {
            sim: true,
            no_asdu: 1,
            security: Some(vec![0x00; 10]),
            sav_asdu: vec![SavAsdu {
                msv_id: "X".to_string(), // Minimal 1-char ID
                dat_set: Some("Y".to_string()),
                smp_cnt: 65535,       // Max u16
                conf_rev: 4294967295, // Max u32
                refr_tm: Some([0xFF; 8]),
                smp_synch: 255,        // Max u8
                smp_rate: Some(65535), // Max u16
                all_data: samples.clone(),
                smp_mod: Some(65535), // Max u16
                gm_identity: Some([0x00; 8]),
            }],
        };

        let encoded = encode_smv(&header, &pdu).expect("Encoding failed");
        let mut decoded_header = EthernetHeader::default();
        let pos = decode_ethernet_header(&mut decoded_header, &encoded);
        let config =
            SavDataSetConfig::new(vec![SavValueConfig::new(1.0), SavValueConfig::new(1.0)]);
        let decoded_pdu = decode_smv(&encoded, pos, &config).expect("Decoding failed");

        // Verify header with extreme values
        assert_eq!(decoded_header.dst_addr, header.dst_addr);
        assert_eq!(decoded_header.src_addr, header.src_addr);
        assert_eq!(decoded_header.ether_type, header.ether_type);
        assert_eq!(decoded_header.appid, header.appid);

        // Verify PDU fields
        assert_eq!(decoded_pdu.sim, pdu.sim);
        assert_eq!(decoded_pdu.no_asdu, pdu.no_asdu);
        assert_eq!(decoded_pdu.security, pdu.security);
        assert_eq!(decoded_pdu.sav_asdu.len(), 1);

        // Verify ASDU with extreme values
        let decoded_asdu = &decoded_pdu.sav_asdu[0];
        let original_asdu = &pdu.sav_asdu[0];
        assert_eq!(decoded_asdu.msv_id, original_asdu.msv_id, "msv_id mismatch");
        assert_eq!(
            decoded_asdu.dat_set, original_asdu.dat_set,
            "dat_set mismatch"
        );
        assert_eq!(
            decoded_asdu.smp_cnt, original_asdu.smp_cnt,
            "smp_cnt mismatch"
        );
        assert_eq!(
            decoded_asdu.conf_rev, original_asdu.conf_rev,
            "conf_rev mismatch"
        );
        assert_eq!(
            decoded_asdu.refr_tm, original_asdu.refr_tm,
            "refr_tm mismatch"
        );
        assert_eq!(
            decoded_asdu.smp_synch, original_asdu.smp_synch,
            "smp_synch mismatch"
        );
        assert_eq!(
            decoded_asdu.smp_rate, original_asdu.smp_rate,
            "smp_rate mismatch"
        );
        assert_eq!(
            decoded_asdu.smp_mod, original_asdu.smp_mod,
            "smp_mod mismatch"
        );
        assert_eq!(
            decoded_asdu.gm_identity, original_asdu.gm_identity,
            "gm_identity mismatch"
        );

        // Verify all extreme value samples
        assert_eq!(decoded_asdu.all_data.len(), samples.len());
        for (i, (decoded_sample, original_sample)) in
            decoded_asdu.all_data.iter().zip(samples.iter()).enumerate()
        {
            assert_eq!(
                decoded_sample.value, original_sample.value,
                "Sample {} value mismatch: expected {}, got {}",
                i, original_sample.value, decoded_sample.value
            );
            assert_eq!(
                decoded_sample.quality.to_u16(),
                original_sample.quality.to_u16(),
                "Sample {} quality mismatch: expected {:#06x}, got {:#06x}",
                i,
                original_sample.quality.to_u16(),
                decoded_sample.quality.to_u16()
            );
        }
    }

    #[test]
    fn test_roundtrip_large_packet() {
        // Test large realistic packet (8 ASDUs x 12 samples each)
        let header = EthernetHeader {
            dst_addr: [0x01, 0x0c, 0xcd, 0x04, 0x00, 0x01],
            src_addr: [0x00, 0x1a, 0xb6, 0x03, 0x2f, 0x1c],
            tpid: Some([0x81, 0x00]),
            tci: Some([0x40, 0x14]), // Priority 2, VLAN ID 20
            ether_type: [0x88, 0xba],
            appid: [0x40, 0x00],
            length: [0x00, 0x00],
        };

        let pdu = SavPdu {
            sim: false,
            no_asdu: 8,
            security: Some(vec![0x00; 10]),
            sav_asdu: {
                let mut asdus = Vec::new();
                for i in 0..8 {
                    let mut samples = Vec::new();
                    for j in 0..12 {
                        let value = (i * 1000 + j * 100) as f32;
                        samples.push(Sample::new(value, QUALITY, 0.1));
                    }

                    asdus.push(SavAsdu {
                        msv_id: format!("IED{}/MSVCB{:02}", i + 1, i),
                        dat_set: Some(format!("IED{}/LLN0$Dataset{}", i + 1, i)),
                        smp_cnt: (i * 80) as u16,
                        conf_rev: (i + 1) as u32,
                        refr_tm: Some([i as u8; 8]),
                        smp_synch: (i % 3) as u8,
                        smp_rate: Some(4000 + (i * 800) as u16),
                        all_data: samples,
                        smp_mod: Some((i % 2) as u16),
                        gm_identity: Some([(i * 16) as u8; 8]),
                    });
                }
                asdus
            },
        };

        let encoded = encode_smv(&header, &pdu).expect("Encoding failed");
        let mut decoded_header = EthernetHeader::default();
        let pos = decode_ethernet_header(&mut decoded_header, &encoded);
        // Just verify decoding succeeds for large packet (8 ASDUs x 12 samples)
        let config = SavDataSetConfig::new(vec![
            SavValueConfig::new(0.01),
            SavValueConfig::new(0.01),
            SavValueConfig::new(0.01),
            SavValueConfig::new(0.01),
            SavValueConfig::new(0.01),
            SavValueConfig::new(0.01),
            SavValueConfig::new(0.01),
            SavValueConfig::new(0.01),
            SavValueConfig::new(0.01),
            SavValueConfig::new(0.01),
            SavValueConfig::new(0.01),
            SavValueConfig::new(0.01),
        ]);
        decode_smv(&encoded, pos, &config).expect("Decoding failed");
    }
}
