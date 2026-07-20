use crate::types::{DecodeError, Quality, Sample, SavAsdu, SavDataSetConfig, SavPdu};

/// Decodes an octet string (raw bytes) from the buffer at the specified position and length.
///
/// # Parameters
/// - `val`: A mutable reference where the decoded bytes will be stored.
/// - `buffer`: The input byte slice containing the encoded data.
/// - `buffer_index`: The starting position in the buffer to read the octet string from.
/// - `length`: The number of bytes to read for the octet string.
///
/// # Returns
/// The next position in the buffer after reading the octet string.
///
/// # Panics
/// Panics if the requested range (buffer_index..buffer_index+length) exceeds the buffer length.
fn decode_octet_string(
    val: &mut [u8],
    buffer: &[u8],
    buffer_index: usize,
    length: usize,
) -> Result<usize, DecodeError> {
    if buffer_index + length > buffer.len() {
        return Err(DecodeError::new(
            &format!(
                "Attempt to read {} bytes exceeds buffer length {}",
                length,
                buffer.len()
            ),
            buffer_index,
        ));
    }
    val[0..length].copy_from_slice(&buffer[buffer_index..buffer_index + length]);
    Ok(buffer_index + length)
}

/// Decodes an ASN.1 BER encoded 8-bit unsigned integer from the buffer at the specified position and length.
///
/// # Parameters
/// - `val`: A mutable reference where the decoded u16 will be stored.
/// - `buffer`: The input byte slice containing the encoded integer.
/// - `buffer_index`: The starting position in the buffer to read the integer from.
/// - `length`: The number of bytes used for the encoded integer in the buffer.
///
/// # Returns
/// The next position in the buffer after reading the integer.
///
/// # Panics
/// Panics if the requested range (buffer_index..buffer_index+length) exceeds the buffer length.
fn decode_unsigned_8(
    val: &mut u8,
    buffer: &[u8],
    buffer_index: usize,
    length: usize,
) -> Result<usize, DecodeError> {
    let mut value_bytes = [0u8; 1];
    decompress_integer(&mut value_bytes, buffer, buffer_index, length)?;
    *val = u8::from_be_bytes(value_bytes);
    Ok(buffer_index + length)
}

/// Decompresses an ASN.1 BER encoded integer from the buffer into the provided value slice,
/// restoring it to its full width (e.g., i32, i64) with correct sign extension.
///
/// # Parameters
/// - `value`: The output buffer (e.g., 4 or 8 bytes) to store the decompressed integer (big-endian).
/// - `buffer`: The input byte slice containing the encoded integer.
/// - `buffer_index`: The starting position in the buffer to read the integer from.
/// - `length`: The number of bytes used for the encoded integer in the buffer.
///
/// # Panics
/// Panics if the requested range (buffer_index..buffer_index+length) exceeds the buffer length,
/// or if `length` is greater than `value.len()`.
fn decompress_integer(
    value: &mut [u8],
    buffer: &[u8],
    buffer_index: usize,
    length: usize,
) -> Result<(), DecodeError> {
    if buffer_index + length > buffer.len() {
        return Err(DecodeError::new(
            &format!(
                "Attempt to read {} bytes exceeds buffer length {}",
                length,
                buffer.len()
            ),
            buffer_index,
        ));
    }

    // Handle unsigned integers with leading 0x00 byte (for MSB set prevention)
    // If the encoded value has a leading 0x00 and the next byte has MSB set,
    // and the length is exactly one more than our target size, skip the leading 0x00
    let (actual_start, actual_length) = if length == value.len() + 1
        && length >= 2
        && buffer[buffer_index] == 0x00
        && (buffer[buffer_index + 1] & 0x80) != 0
    {
        // Skip the leading 0x00 byte for unsigned integers
        (buffer_index + 1, length - 1)
    } else if length > value.len() {
        return Err(DecodeError::new(
            &format!(
                "Mismatch value length {} vs buffer length {}",
                value.len(),
                length
            ),
            buffer_index,
        ));
    } else {
        (buffer_index, length)
    };

    // Determine fill byte for sign extension (0xFF for negative, 0x00 for positive)
    let fill = if buffer[actual_start] & 0x80 == 0x80 {
        0xFF
    } else {
        0x00
    };

    // Fill the leading bytes with the sign extension
    let fill_length = value.len() - actual_length;
    for item in value.iter_mut().take(fill_length) {
        *item = fill;
    }

    // Copy the encoded integer bytes into the lower part of the output buffer
    value[fill_length..].copy_from_slice(&buffer[actual_start..actual_start + actual_length]);
    Ok(())
}

/// Decodes an ASN.1 BER encoded 32-bit unsigned integer from the buffer at the specified position and length.
///
/// # Parameters
/// - `val`: A mutable reference where the decoded u32 will be stored.
/// - `buffer`: The input byte slice containing the encoded integer.
/// - `buffer_index`: The starting position in the buffer to read the integer from.
/// - `length`: The number of bytes used for the encoded integer in the buffer.
///
/// # Returns
/// The next position in the buffer after reading the integer.
///
/// # Panics
/// Panics if the requested range (buffer_index..buffer_index+length) exceeds the buffer length.
fn decode_unsigned_32(
    val: &mut u32,
    buffer: &[u8],
    buffer_index: usize,
    length: usize,
) -> Result<usize, DecodeError> {
    let mut value_bytes = [0u8; 4];
    decompress_integer(&mut value_bytes, buffer, buffer_index, length)?;
    *val = u32::from_be_bytes(value_bytes);
    Ok(buffer_index + length)
}

/// Decodes an ASN.1 BER encoded 16-bit unsigned integer from the buffer at the specified position and length.
///
/// # Parameters
/// - `val`: A mutable reference where the decoded u16 will be stored.
/// - `buffer`: The input byte slice containing the encoded integer.
/// - `buffer_index`: The starting position in the buffer to read the integer from.
/// - `length`: The number of bytes used for the encoded integer in the buffer.
///
/// # Returns
/// The next position in the buffer after reading the integer.
///
/// # Panics
/// Panics if the requested range (buffer_index..buffer_index+length) exceeds the buffer length.
fn decode_unsigned_16(
    val: &mut u16,
    buffer: &[u8],
    buffer_index: usize,
    length: usize,
) -> Result<usize, DecodeError> {
    let mut value_bytes = [0u8; 2];
    decompress_integer(&mut value_bytes, buffer, buffer_index, length)?;
    *val = u16::from_be_bytes(value_bytes);
    Ok(buffer_index + length)
}

/// Decodes a UTF-8 string from the buffer at the specified position and length.
///
/// # Parameters
/// - `val`: A mutable reference where the decoded string will be stored.
/// - `buffer`: The input byte slice containing the encoded data.
/// - `buffer_index`: The starting position in the buffer to read the string from.
/// - `length`: The number of bytes to read for the string.
///
/// # Returns
/// The next position in the buffer after reading the string.
///
/// # Panics
/// Panics if the requested range (buffer_index..buffer_index+length) exceeds the buffer length.
fn decode_string(
    val: &mut String,
    buffer: &[u8],
    buffer_index: usize,
    length: usize,
) -> Result<usize, DecodeError> {
    if buffer_index + length > buffer.len() {
        return Err(DecodeError::new(
            &format!(
                "Attempt to read {} bytes exceeds buffer length {}",
                length,
                buffer.len()
            ),
            buffer_index,
        ));
    }
    *val = String::from_utf8_lossy(&buffer[buffer_index..buffer_index + length]).to_string();
    Ok(buffer_index + length)
}

/// Decodes an ASN.1 BER tag and length field from the buffer at the specified position,
/// writing the results into the provided mutable references.
///
/// This function supports definite-length encoding with up to 3 length bytes (sufficient for most practical uses).
///
/// # Parameters
/// - `tag`: Mutable reference to store the decoded tag (`u8`).
/// - `length`: Mutable reference to store the decoded length (`usize`).
/// - `buffer`: The input byte slice containing the encoded tag and length.
/// - `buffer_index`: The starting position in the buffer to read the tag and length from.
///
/// # Returns
/// The next position in the buffer after reading the tag and length.
///
/// # Panics
/// Panics if the buffer does not contain enough bytes to decode the tag and length.
fn decode_tag_length(
    tag: &mut u8,
    length: &mut usize,
    buffer: &[u8],
    buffer_index: usize,
) -> Result<usize, DecodeError> {
    if buffer_index >= buffer.len() {
        return Err(DecodeError::new(
            &format!("Out of bounds for buffer length {}", buffer.len()),
            buffer_index,
        ));
    }

    *tag = buffer[buffer_index];
    let mut pos = buffer_index + 1;

    if pos >= buffer.len() {
        return Err(DecodeError::new(
            "Decode tag length: missing length byte ",
            buffer_index,
        ));
    }

    let first_len_byte = buffer[pos];
    pos += 1;

    *length = if first_len_byte & 0x80 == 0 {
        // Short form: single byte length (0..127)
        first_len_byte as usize
    } else {
        // Long form: lower 7 bits indicate number of length bytes
        let num_len_bytes = (first_len_byte & 0x7F) as usize;
        if num_len_bytes == 0 || num_len_bytes > 3 {
            return Err(DecodeError::new(
                &format!(
                    "Decode tag length: unsupported or invalid number of length bytes: {}",
                    num_len_bytes
                ),
                buffer_index,
            ));
        }
        if pos + num_len_bytes > buffer.len() {
            return Err(DecodeError::new(
                &format!(
                    "Decode tag length: not enough bytes for {}-byte length at position {}",
                    num_len_bytes, pos
                ),
                buffer_index,
            ));
        }
        let mut len = 0usize;
        for _ in 0..num_len_bytes {
            len = (len << 8) | buffer[pos] as usize;
            pos += 1;
        }
        len
    };

    Ok(pos)
}

/// Decodes a Sampled Values PDU from the buffer at the specified position.
///
/// The caller must supply a [`SavDataSetConfig`] that describes the data set
/// structure, because the sampled-value payload is not self-describing.
///
/// # Parameters
/// - `buffer`: The input byte slice containing the encoded SMV PDU.
/// - `pos`: The starting position in the buffer to read from.
/// - `config`: The data set configuration describing the structure of the sampled values.
///
/// # Returns
/// The decoded `SavPdu`.
///
/// # Data set configuration
///
/// For an IEC 61850-9-2LE packet with the fixed 8-channel data set, use the
/// built-in configuration. It expects eight 4-byte integer + 4-byte quality
/// samples with a scale factor of `0.001` for currents and `0.01` for voltages:
///
/// ```ignore
/// let pdu = decode_smv(&buffer, pos, &SavDataSetConfig::le_92())?;
/// ```
///
/// For a flexible data set, build a [`SavDataSetConfig`] with one
/// [`SavValueConfig`] per member. Each member defines its own scale factor:
///
/// ```ignore
/// let config = SavDataSetConfig::new(vec![
///     SavValueConfig::new(0.001),
///     SavValueConfig::new(0.001),
/// ]);
/// let pdu = decode_smv(&buffer, pos, &config)?;
/// ```
pub fn decode_smv(
    buffer: &[u8],
    pos: usize,
    config: &SavDataSetConfig,
) -> Result<SavPdu, DecodeError> {
    let mut pdu = SavPdu::default();
    let mut new_pos = pos;

    // decode simulation bit that is encoded into the first bit of reserved 1 field (see decode ethernet)
    pdu.sim = decode_sim_bit(buffer).unwrap_or(false);

    // Jump over the length tag of the SAV PDU
    let mut _tag = 0u8;
    let mut _length = 0usize;
    new_pos = decode_tag_length(&mut _tag, &mut _length, buffer, new_pos)?;

    // Number of ASDUs in the packet
    new_pos = decode_tag_length(&mut _tag, &mut _length, buffer, new_pos)?;
    new_pos = decode_unsigned_16(&mut pdu.no_asdu, buffer, new_pos, _length)?;

    // Optional field security (ANY OPTIONAL - reserved for future use)
    let tag = buffer[new_pos];
    if tag == 0x81 {
        let mut _length = 0usize;
        new_pos = decode_tag_length(&mut _tag, &mut _length, buffer, new_pos)?;
        let mut sec_buf = vec![0u8; _length];
        new_pos = decode_octet_string(&mut sec_buf, buffer, new_pos, _length)?;
        pdu.security = Some(sec_buf);
    } else {
        pdu.security = None;
    }

    // sequence of ASDU
    let mut length = 0usize;
    new_pos = decode_tag_length(&mut _tag, &mut length, buffer, new_pos)?;

    pdu.sav_asdu.clear();
    decode_smv_asdus(&mut pdu.sav_asdu, buffer, new_pos, pdu.no_asdu, config)?;

    Ok(pdu)
}

/// Determines if the provided Ethernet frame buffer contains a Sampled Values (SMV) frame
/// by checking the EtherType field, accounting for possible VLAN tagging.
///
/// Returns `true` if the EtherType matches the SMV type (0x88ba), regardless of VLAN presence.
/// If a VLAN tag (0x81, 0x00) is detected, the EtherType is checked at bytes 16-17; otherwise, at bytes 12-13.
pub fn is_smv_frame(buffer: &[u8]) -> bool {
    if buffer.len() < 14 {
        return false;
    }
    // If VLAN tag (0x81, 0x00) is present, EtherType is at offset 16; otherwise, at 12.
    let ether_type_offset = if buffer[12..14] == [0x81, 0x00] {
        16
    } else {
        12
    };
    if buffer.len() < ether_type_offset + 2 {
        return false;
    }
    let ether_type = &buffer[ether_type_offset..ether_type_offset + 2];
    ether_type == [0x88, 0xba]
}

/// Decodes a sequence of Sampled Values ASDUs from the buffer.
///
/// # Parameters
/// - `val`: A mutable reference to the vector where decoded `SavAsdu` instances are appended.
/// - `buffer`: The input byte slice containing the encoded ASDUs.
/// - `start_pos`: The starting position in the buffer to read from.
/// - `no_asdu`: The number of ASDUs to decode.
/// - `config`: The data set configuration describing the structure of the sampled values.
///
/// # Returns
/// The new buffer position after decoding all ASDUs.
///
/// # Errors
/// Returns `DecodeError` if the buffer is malformed or too short.
fn decode_smv_asdus(
    val: &mut Vec<SavAsdu>,
    buffer: &[u8],
    start_pos: usize,
    no_asdu: u16,
    config: &SavDataSetConfig,
) -> Result<usize, DecodeError> {
    let mut new_pos = start_pos;

    let mut _tag = 0u8;
    let mut _length = 0usize;

    for _ in 0..no_asdu {
        // length field of the next ASDU
        new_pos = decode_tag_length(&mut _tag, &mut _length, buffer, new_pos)?;

        let (next_pos, new_asdu) = decode_smv_asdu(buffer, new_pos, config)?;
        val.push(new_asdu);
        new_pos = next_pos;
    }

    Ok(new_pos)
}

/// Decodes a single Sampled Values Application Service Data Unit (ASDU) from the buffer,
/// writing the result into a newly created `SavAsdu`.
///
/// # Parameters
/// - `buffer`: The input byte slice containing the encoded ASDU.
/// - `start_pos`: The starting position in the buffer to read from.
/// - `config`: The data set configuration describing the structure of the sampled values.
///
/// # Returns
/// A tuple containing the new buffer position and the decoded `SavAsdu`.
///
/// # Errors
/// Returns `DecodeError` if the buffer is malformed or too short.
fn decode_smv_asdu(
    buffer: &[u8],
    start_pos: usize,
    config: &SavDataSetConfig,
) -> Result<(usize, SavAsdu), DecodeError> {
    let mut asdu = SavAsdu::default();

    let mut new_pos = start_pos;

    // SMV ASDU length
    let mut _tag = 0u8;
    let mut _length = 0usize;

    // sampled value ID
    let mut length = 0usize;
    new_pos = decode_tag_length(&mut _tag, &mut length, buffer, new_pos)?;
    new_pos = decode_string(&mut asdu.msv_id, buffer, new_pos, length)?;

    // Optional data set reference description
    let tag = buffer[new_pos];
    if tag == 0x81 {
        new_pos = decode_tag_length(&mut _tag, &mut length, buffer, new_pos)?;
        let mut dat_set_str = String::new();
        new_pos = decode_string(&mut dat_set_str, buffer, new_pos, length)?;
        asdu.dat_set = Some(dat_set_str);
    } else {
        asdu.dat_set = None;
    }

    // sample count
    new_pos = decode_tag_length(&mut _tag, &mut length, buffer, new_pos)?;
    new_pos = decode_unsigned_16(&mut asdu.smp_cnt, buffer, new_pos, length)?;

    // conf_rev
    new_pos = decode_tag_length(&mut _tag, &mut length, buffer, new_pos)?;
    new_pos = decode_unsigned_32(&mut asdu.conf_rev, buffer, new_pos, length)?;

    // Optional refresh time (timestamp)
    let tag = buffer[new_pos];
    if tag == 0x84 {
        new_pos = decode_tag_length(&mut _tag, &mut length, buffer, new_pos)?;
        let mut refr_tm_arr = [0u8; 8];
        refr_tm_arr.copy_from_slice(&buffer[new_pos..new_pos + 8]);
        asdu.refr_tm = Some(refr_tm_arr);
        new_pos += 8;
    } else {
        asdu.refr_tm = None;
    }

    // samples synched
    new_pos = decode_tag_length(&mut _tag, &mut length, buffer, new_pos)?;
    new_pos = decode_unsigned_8(&mut asdu.smp_synch, buffer, new_pos, length)?;

    // Optional sample rate
    let tag = buffer[new_pos];
    if tag == 0x86 {
        new_pos = decode_tag_length(&mut _tag, &mut length, buffer, new_pos)?;
        let mut smp_rate_num = 0u16;
        new_pos = decode_unsigned_16(&mut smp_rate_num, buffer, new_pos, length)?;
        asdu.smp_rate = Some(smp_rate_num);
    } else {
        asdu.smp_rate = None;
    }

    // Data Content
    new_pos = decode_tag_length(&mut _tag, &mut length, buffer, new_pos)?;
    asdu.all_data.clear();
    let (next_pos, result) = decode_savs(buffer, new_pos, config)?;
    new_pos = next_pos;
    asdu.all_data = result;

    // Optional Sampling Mod
    if new_pos < buffer.len() && buffer[new_pos] == 0x88 {
        new_pos = decode_tag_length(&mut _tag, &mut length, buffer, new_pos)?;
        let mut smp_mod_num = 0u16;
        new_pos = decode_unsigned_16(&mut smp_mod_num, buffer, new_pos, length)?;
        asdu.smp_mod = Some(smp_mod_num);
    } else {
        asdu.smp_mod = None;
    }

    // Optional grandmaster clock identity
    if new_pos < buffer.len() && buffer[new_pos] == 0x89 {
        new_pos = decode_tag_length(&mut _tag, &mut length, buffer, new_pos)?;
        let mut gm_identity_oct = [0u8; 8];
        new_pos = decode_octet_string(&mut gm_identity_oct, buffer, new_pos, length)?;
        asdu.gm_identity = Some(gm_identity_oct);
    } else {
        asdu.gm_identity = None;
    }

    Ok((new_pos, asdu))
}

/// Extracts the SIM bit from the "reserved 1" field in the SV/SMV header.
/// The SIM bit is the most significant bit (bit 7) of the first byte of reserved 1.
/// Returns Some(true) if the SIM bit is set, Some(false) if not, or None if the buffer is too short.
///
/// # Arguments
/// * `buffer` - The Ethernet frame buffer (must be long enough to contain reserved 1).
fn decode_sim_bit(buffer: &[u8]) -> Option<bool> {
    // Ethernet: 6 (dst) + 6 (src)
    let mut offset = 12;

    // Check for VLAN tag (0x81, 0x00)
    if buffer.len() >= offset + 2 && buffer[offset..offset + 2] == [0x81, 0x00] {
        offset += 4; // VLAN tag is 4 bytes
    }

    // EtherType (2) + appid (2) + length (2)
    offset += 2 + 2 + 2;

    // Now offset points to the first byte of reserved 1
    if buffer.len() <= offset {
        return None;
    }

    let reserved1_byte = buffer[offset];
    Some((reserved1_byte & 0x80) != 0)
}

/// Decodes the sampled-value data set from the raw ASDU payload.
///
/// Each configured scaling factor is read as a sample - 4-byte big-endian signed integer (`i32`)
/// followed by a 4-byte big-endian quality field (`u32`). The number of samples
/// and the per-sample scale factor are taken from `data_set_config`.
///
/// # Arguments
/// * `buffer` - The raw bytes of the ASDU data content.
/// * `buffer_index` - The position in `buffer` where the data set starts.
/// * `data_set_config` - Description of the data set: one entry per sample,
///   each carrying the scale factor to apply to the raw integer value.
///
/// # Returns
/// A tuple containing the new buffer position and the decoded `Sample`s.
///
/// # Errors
/// Returns `DecodeError` if the buffer is too short for the configured data set.
fn decode_savs(
    buffer: &[u8],
    buffer_index: usize,
    data_set_config: &SavDataSetConfig,
) -> Result<(usize, Vec<Sample>), DecodeError> {
    let mut pos = buffer_index;

    let mut samples = vec![];

    for config in data_set_config.config.iter() {
        if pos + 8 > buffer.len() {
            return Err(DecodeError::new(
                "Buffer too short for sample value data set",
                pos,
            ));
        }

        // Decode the integer value
        let mut value_bytes = [0u8; 4];
        value_bytes.copy_from_slice(&buffer[pos..pos + 4]);
        let value = i32::from_be_bytes(value_bytes) as f32 * config.scale_factor;
        pos += 4;

        let mut quality_bytes = [0u8; 4];
        quality_bytes.copy_from_slice(&buffer[pos..pos + 4]);
        let quality_32 = u32::from_be_bytes(quality_bytes);
        let quality = Quality::from_sv(quality_32);
        pos += 4;

        samples.push(Sample::new(value, quality, config.scale_factor));
    }

    Ok((pos, samples))
}

#[cfg(test)]
mod tests {
    use crate::{
        rt_services::ethernet_header::decode_ethernet_header,
        types::{EthernetHeader, SavValueConfig, Validity},
    };

    use super::*;

    fn buffer_92_le() -> Vec<u8> {
        vec![
            0x01, 0x0c, 0xcd, 0x04, 0x00, 0x00, 0xb4, 0xb1, 0x5a, 0x0e, 0x75, 0xb1, 0x88, 0xba,
            0x40, 0x01, 0x00, 0x79, 0x00, 0x00, 0x00, 0x00, 0x60, 0x6f, 0x80, 0x01, 0x01, 0xa2,
            0x6a, 0x30, 0x68, 0x80, 0x0d, 0x53, 0x49, 0x50, 0x41, 0x4d, 0x6f, 0x64, 0x33, 0x4d,
            0x55, 0x31, 0x30, 0x33, 0x82, 0x02, 0x0c, 0xb3, 0x83, 0x04, 0x00, 0x00, 0x27, 0x11,
            0x85, 0x01, 0x02, 0x87, 0x40, 0xff, 0xff, 0xfe, 0x1b, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x01, 0xe8, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xaa, 0x00, 0x00, 0x00,
            0x00, 0xff, 0xff, 0xff, 0xc3, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x11, 0x23, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x12, 0x23, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xd8,
            0x7b, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xfc, 0xb4, 0x00, 0x00, 0x00, 0x00, 0x89,
            0x08, 0xec, 0x46, 0x70, 0xff, 0xfe, 0x0a, 0xa5, 0x00,
        ]
    }

    fn flexible_data_set() -> Vec<u8> {
        vec![
            0x01, 0x0c, 0xcd, 0x04, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x88, 0xba,
            0x40, 0x00, 0x00, 0x2e, 0x00, 0x00, 0x00, 0x00, 0x60, 0x24, 0x80, 0x01, 0x01, 0xa2,
            0x1f, 0x30, 0x1d, 0x80, 0x04, 0x30, 0x30, 0x30, 0x30, 0x82, 0x02, 0x02, 0x8d, 0x83,
            0x04, 0x00, 0x00, 0x00, 0x01, 0x85, 0x01, 0x01, 0x87, 0x08, 0x00, 0x08, 0x46, 0x59,
            0x00, 0x00, 0x15, 0x55,
        ]
    }

    #[test]
    fn test_decode_92_le_data_correctness() {
        let packet = buffer_92_le();

        let mut header = EthernetHeader::default();
        let pos = decode_ethernet_header(&mut header, &packet);

        assert!(header.dst_addr == [0x01, 0x0c, 0xcd, 0x04, 0x00, 0x00]);
        assert!(header.src_addr == [0xb4, 0xb1, 0x5a, 0x0e, 0x75, 0xb1]);
        assert!(header.ether_type == [0x88, 0xba]);
        assert!(header.tpid == None);
        assert!(header.tci == None);

        let result: Result<SavPdu, DecodeError> =
            decode_smv(&packet, pos, &SavDataSetConfig::le_92());

        assert!(result.is_ok());

        let pdu = result.unwrap();

        assert_eq!(pdu.sim, false);
        assert!(pdu.no_asdu == 1);
        assert!(pdu.security == None);

        // Check ASDU
        let asdu = &pdu.sav_asdu[0];
        assert!(asdu.msv_id == "SIPAMod3MU103".to_string());
        assert!(asdu.dat_set == None);
        assert!(asdu.refr_tm == None);
        assert_eq!(asdu.smp_cnt, 3251);
        assert_eq!(asdu.conf_rev, 10001);
        assert_eq!(asdu.smp_synch, 2);
        assert_eq!(asdu.smp_rate, None);
        assert_eq!(asdu.smp_mod, None);
        assert_eq!(
            asdu.gm_identity,
            Some([0xec, 0x46, 0x70, 0xff, 0xfe, 0x0a, 0xa5, 0x00])
        );

        let data = &asdu.all_data;
        assert!(data[0].value == -485.0 * data[0].scale_factor);
        assert!(data[1].value == 488.0 * data[1].scale_factor);
        assert!(data[2].value == -86.0 * data[2].scale_factor);
        assert!(data[3].value == -61.0 * data[3].scale_factor);
        assert!(data[4].value == 4387.0 * data[4].scale_factor);
        assert!(data[5].value == 4643.0 * data[5].scale_factor);
        assert!(data[6].value == -10117.0 * data[6].scale_factor);
        assert!(data[7].value == -844.0 * data[7].scale_factor);
    }

    #[test]
    fn test_decode_flex_data_set_correctness() {
        let packet = flexible_data_set();

        let mut header = EthernetHeader::default();
        let pos = decode_ethernet_header(&mut header, &packet);

        assert!(header.dst_addr == [0x01, 0x0c, 0xcd, 0x04, 0x00, 0x00]);
        assert!(header.src_addr == [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]);
        assert!(header.ether_type == [0x88, 0xba]);
        assert!(header.tpid == None);
        assert!(header.tci == None);

        let config = SavDataSetConfig::new(vec![SavValueConfig::new(0.001)]);
        let result: Result<SavPdu, DecodeError> = decode_smv(&packet, pos, &config);

        assert!(result.is_ok());

        let pdu = result.unwrap();

        assert_eq!(pdu.sim, false);
        assert!(pdu.no_asdu == 1);
        assert!(pdu.security == None);

        // Check ASDU
        let asdu = &pdu.sav_asdu[0];
        assert!(asdu.msv_id == "0000".to_string());
        assert!(asdu.dat_set == None);
        assert!(asdu.refr_tm == None);
        assert_eq!(asdu.smp_cnt, 653);
        assert_eq!(asdu.conf_rev, 1);
        assert_eq!(asdu.smp_synch, 1);
        assert_eq!(asdu.smp_rate, None);
        assert_eq!(asdu.smp_mod, None);

        let data = &asdu.all_data;
        assert!(data[0].value == 542297.0 * data[0].scale_factor);
        assert_eq!(data[0].quality.validity, Validity::Invalid);
        assert_eq!(data[0].quality.overflow, true);
        assert_eq!(data[0].quality.out_of_range, false);
        assert_eq!(data[0].quality.bad_reference, true);
        assert_eq!(data[0].quality.oscillatory, false);
        assert_eq!(data[0].quality.failure, true);
        assert_eq!(data[0].quality.old_data, false);
        assert_eq!(data[0].quality.inconsistent, true);
        assert_eq!(data[0].quality.inaccurate, false);
        assert_eq!(data[0].quality.source_substituted, true);
        assert_eq!(data[0].quality.test, false);
        assert_eq!(data[0].quality.operator_blocked, true);
    }

    #[test]
    fn test_is_smv_frame_no_vlan() {
        let frame = vec![
            0x01, 0x0c, 0xcd, 0x04, 0x00, 0x01, // dst MAC
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // src MAC
            0x88, 0xba, // EtherType = SMV
        ];

        assert!(is_smv_frame(&frame));
    }

    #[test]
    fn test_is_smv_frame_with_vlan() {
        let frame = vec![
            0x01, 0x0c, 0xcd, 0x04, 0x00, 0x01, // dst MAC
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // src MAC
            0x81, 0x00, // VLAN TPID
            0x00, 0x64, // VLAN TCI
            0x88, 0xba, // EtherType = SMV
        ];

        assert!(is_smv_frame(&frame));
    }

    #[test]
    fn test_is_smv_frame_not_smv() {
        let frame = vec![
            0x01, 0x0c, 0xcd, 0x04, 0x00, 0x01, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x08,
            0x00, // EtherType = IPv4
        ];

        assert!(!is_smv_frame(&frame));
    }

    #[test]
    fn test_decode_sim_bit() {
        // Without VLAN, SIM bit not set
        let mut frame = vec![
            0x01, 0x0c, 0xcd, 0x04, 0x00, 0x01, // dst
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // src
            0x88, 0xba, // EtherType
            0x40, 0x00, // APPID
            0x00, 0x64, // Length
            0x00, 0x00, // Reserved 1 (SIM bit = 0)
        ];

        assert_eq!(decode_sim_bit(&frame), Some(false));

        // Set SIM bit (MSB of reserved 1)
        frame[18] = 0x80;
        assert_eq!(decode_sim_bit(&frame), Some(true));
    }
}
