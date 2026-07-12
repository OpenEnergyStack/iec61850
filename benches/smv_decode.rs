use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use iec_61850::decode_smv::decode_smv;
use iec_61850::encode_smv::encode_smv;
use iec_61850::types::{
    EthernetHeader, Quality, Sample, SavAsdu, SavDataSetConfig, SavPdu, SavValueConfig, Validity,
};

/// Diagnostic function to validate packet structure
fn validate_packet(packet: &[u8], name: &str, config: &SavDataSetConfig) {
    println!("\n=== Validating {} ===", name);
    println!("Packet size: {} bytes", packet.len());

    match decode_smv(packet, 22, &config) {
        Ok(pdu) => {
            println!("✓ Successfully decoded PDU");
            println!("  Number of ASDUs: {}", pdu.no_asdu);
            println!("  Simulation: {}", pdu.sim);
        }
        Err(e) => {
            println!("✗ Decode error at index {}: {}", e.buffer_index, e.message);
            println!("  Packet hex around error (10 bytes before/after):");
            let start = e.buffer_index.saturating_sub(10);
            let end = (e.buffer_index + 10).min(packet.len());
            print!("  ");
            for i in start..end {
                if i == e.buffer_index {
                    print!("[{:02X}] ", packet[i]);
                } else {
                    print!("{:02X} ", packet[i]);
                }
            }
            println!();
        }
    }
}

/// Helper function to encode samples in ASN.1 BER format
fn encode_samples(buffer: &mut Vec<u8>, num_samples: usize, start_value: i32) {
    for i in 0..num_samples {
        let value = start_value + (i as i32 * 100);
        let value_bytes = value.to_be_bytes();

        // INT32
        buffer.extend_from_slice(&value_bytes);

        // BITSTRING with tag 0x84 (13-bit quality in 2 bytes + 1 byte for unused bits)
        let quality_13bit = 0_i32.to_be_bytes();

        buffer.extend_from_slice(&quality_13bit);
    }
}

fn config(samples: usize) -> SavDataSetConfig {
    SavDataSetConfig::new(vec![SavValueConfig::new(0.01); samples])
}

fn config_92le() -> SavDataSetConfig {
    SavDataSetConfig::new(vec![
        SavValueConfig::new(0.001),
        SavValueConfig::new(0.001),
        SavValueConfig::new(0.001),
        SavValueConfig::new(0.001),
        SavValueConfig::new(0.01),
        SavValueConfig::new(0.01),
        SavValueConfig::new(0.01),
        SavValueConfig::new(0.01),
    ])
}

/// Create a maximum stress test SMV packet: 8 ASDUs with 32 samples each
/// This tests the worst-case scenario for IEC 61850-9-2
fn create_max_stress_smv_packet() -> Vec<u8> {
    const NUM_ASDUS: usize = 8;
    const SAMPLES_PER_ASDU: usize = 32;

    // Ethernet header (14 bytes without VLAN)
    let mut packet = vec![
        // Destination MAC
        0x01, 0x0c, 0xcd, 0x04, 0x00, 0x01, // Source MAC
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // EtherType (0x88ba = SMV)
        0x88, 0xba,
    ];

    // APPID and Length placeholders
    let _appid_pos = packet.len();
    packet.extend_from_slice(&[0x40, 0x00]); // APPID placeholder
    let length_pos = packet.len();
    packet.extend_from_slice(&[0x00, 0x00]); // Length placeholder

    // Reserved fields
    packet.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);

    let pdu_start = packet.len();

    // Build all ASDUs first to calculate actual size
    let sv_id = b"IED1/LLN0$MSVCB01";
    let mut all_asdus = Vec::new();

    for asdu_idx in 0..NUM_ASDUS {
        let mut asdu = Vec::new();

        // svID (tag 0x80)
        asdu.push(0x80);
        asdu.push(sv_id.len() as u8);
        asdu.extend_from_slice(sv_id);

        // smpCnt (tag 0x82)
        let smp_cnt = (0x1000 + asdu_idx * 100) as u16;
        asdu.extend_from_slice(&[0x82, 0x02]);
        asdu.extend_from_slice(&smp_cnt.to_be_bytes());

        // confRev (tag 0x83)
        asdu.extend_from_slice(&[0x83, 0x04, 0x00, 0x00, 0x00, 0x01]);

        // smpSynch (tag 0x85)
        asdu.extend_from_slice(&[0x85, 0x01, 0x02]);

        // sample values (tag 0x87) - encode samples first to get actual size
        let mut samples_data = Vec::new();
        encode_samples(
            &mut samples_data,
            SAMPLES_PER_ASDU,
            10000 + (asdu_idx as i32 * 5000),
        );

        asdu.push(0x87);
        if samples_data.len() > 255 {
            asdu.push(0x82); // 2-byte length follows
            asdu.push(((samples_data.len() >> 8) & 0xFF) as u8);
            asdu.push((samples_data.len() & 0xFF) as u8);
        } else if samples_data.len() > 127 {
            asdu.push(0x81); // 1-byte length follows
            asdu.push(samples_data.len() as u8);
        } else {
            asdu.push(samples_data.len() as u8);
        }
        asdu.extend_from_slice(&samples_data);

        // Prepend ASDU tag and length
        let asdu_content_size = asdu.len();
        let mut final_asdu = Vec::new();
        final_asdu.push(0x30);
        if asdu_content_size > 255 {
            final_asdu.push(0x82);
            final_asdu.push(((asdu_content_size >> 8) & 0xFF) as u8);
            final_asdu.push((asdu_content_size & 0xFF) as u8);
        } else if asdu_content_size > 127 {
            final_asdu.push(0x81);
            final_asdu.push(asdu_content_size as u8);
        } else {
            final_asdu.push(asdu_content_size as u8);
        }
        final_asdu.extend_from_slice(&asdu);

        all_asdus.extend_from_slice(&final_asdu);
    }

    // Now build the PDU with correct lengths
    let all_asdus_size = all_asdus.len();

    // SMV PDU tag 0x60 with length
    let pdu_content_size = 3 + 2 + all_asdus_size; // noASDU (3) + A2 tag+len (2) + ASDUs
    packet.push(0x60);
    if pdu_content_size > 255 {
        packet.push(0x82);
        packet.push(((pdu_content_size >> 8) & 0xFF) as u8);
        packet.push((pdu_content_size & 0xFF) as u8);
    } else if pdu_content_size > 127 {
        packet.push(0x81);
        packet.push(pdu_content_size as u8);
    } else {
        packet.push(pdu_content_size as u8);
    }

    // noASDU (tag 0x80)
    packet.extend_from_slice(&[0x80, 0x01, NUM_ASDUS as u8]);

    // Sequence of ASDUs (tag 0xA2)
    packet.push(0xA2);
    if all_asdus_size > 255 {
        packet.push(0x82);
        packet.push(((all_asdus_size >> 8) & 0xFF) as u8);
        packet.push((all_asdus_size & 0xFF) as u8);
    } else if all_asdus_size > 127 {
        packet.push(0x81);
        packet.push(all_asdus_size as u8);
    } else {
        packet.push(all_asdus_size as u8);
    }
    packet.extend_from_slice(&all_asdus);

    // Update length field
    let pdu_length = packet.len() - pdu_start;
    packet[length_pos] = ((pdu_length >> 8) & 0xFF) as u8;
    packet[length_pos + 1] = (pdu_length & 0xFF) as u8;

    packet
}

/// Create a maximum realistic SMV packet that fits within Ethernet MTU
/// Uses 8 ASDUs with 12 samples each = 96 total samples
fn create_max_realistic_smv_packet() -> Vec<u8> {
    const NUM_ASDUS: usize = 8;
    const SAMPLES_PER_ASDU: usize = 12;

    // Ethernet header (14 bytes without VLAN)
    let mut packet = vec![
        // Destination MAC
        0x01, 0x0c, 0xcd, 0x04, 0x00, 0x01, // Source MAC
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // EtherType (0x88ba = SMV)
        0x88, 0xba,
    ];

    // APPID and Length placeholders
    let _appid_pos = packet.len();
    packet.extend_from_slice(&[0x40, 0x00]); // APPID placeholder
    let length_pos = packet.len();
    packet.extend_from_slice(&[0x00, 0x00]); // Length placeholder

    // Reserved fields
    packet.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);

    let pdu_start = packet.len();

    // Build all ASDUs first to calculate actual size
    let sv_id = b"IED1/LLN0$MSVCB01";
    let mut all_asdus = Vec::new();

    for asdu_idx in 0..NUM_ASDUS {
        let mut asdu = Vec::new();

        // svID (tag 0x80)
        asdu.push(0x80);
        asdu.push(sv_id.len() as u8);
        asdu.extend_from_slice(sv_id);

        // smpCnt (tag 0x82)
        let smp_cnt = (0x1000 + asdu_idx * 100) as u16;
        asdu.extend_from_slice(&[0x82, 0x02]);
        asdu.extend_from_slice(&smp_cnt.to_be_bytes());

        // confRev (tag 0x83)
        asdu.extend_from_slice(&[0x83, 0x04, 0x00, 0x00, 0x00, 0x01]);

        // smpSynch (tag 0x85)
        asdu.extend_from_slice(&[0x85, 0x01, 0x02]);

        // sample values (tag 0x87) - encode samples first to get actual size
        let mut samples_data = Vec::new();
        encode_samples(
            &mut samples_data,
            SAMPLES_PER_ASDU,
            10000 + (asdu_idx as i32 * 5000),
        );

        asdu.push(0x87);
        if samples_data.len() > 127 {
            asdu.push(0x81);
            asdu.push(samples_data.len() as u8);
        } else {
            asdu.push(samples_data.len() as u8);
        }
        asdu.extend_from_slice(&samples_data);

        // Prepend ASDU tag and length
        let asdu_content_size = asdu.len();
        let mut final_asdu = Vec::new();
        final_asdu.push(0x30);
        if asdu_content_size > 127 {
            final_asdu.push(0x81);
            final_asdu.push(asdu_content_size as u8);
        } else {
            final_asdu.push(asdu_content_size as u8);
        }
        final_asdu.extend_from_slice(&asdu);

        all_asdus.extend_from_slice(&final_asdu);
    }

    // Now build the PDU with correct lengths
    let all_asdus_size = all_asdus.len();

    // SMV PDU tag 0x60 with length
    let pdu_content_size = 3 + 2 + all_asdus_size; // noASDU (3) + A2 tag+len (2) + ASDUs
    packet.push(0x60);
    if pdu_content_size > 127 {
        packet.push(0x81);
        packet.push(pdu_content_size as u8);
    } else {
        packet.push(pdu_content_size as u8);
    }

    // noASDU (tag 0x80)
    packet.extend_from_slice(&[0x80, 0x01, NUM_ASDUS as u8]);

    // Sequence of ASDUs (tag 0xA2)
    packet.push(0xA2);
    if all_asdus_size > 127 {
        packet.push(0x81);
        packet.push(all_asdus_size as u8);
    } else {
        packet.push(all_asdus_size as u8);
    }
    packet.extend_from_slice(&all_asdus);

    // Update length field
    let pdu_length = packet.len() - pdu_start;
    packet[length_pos] = ((pdu_length >> 8) & 0xFF) as u8;
    packet[length_pos + 1] = (pdu_length & 0xFF) as u8;

    packet
}

/// Create a realistic SMV packet for benchmarking (single ASDU, 8 samples)
fn create_92le_sample_smv_packet() -> Vec<u8> {
    // Ethernet header (14 bytes without VLAN)
    let mut packet = vec![
        // Destination MAC
        0x01, 0x0c, 0xcd, 0x04, 0x00, 0x01, // Source MAC
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // EtherType (0x88ba = SMV)
        0x88, 0xba, // APPID
        0x40, 0x00, // Length
        0x00, 0x9c, // Reserved 1 (2 bytes) - SIM bit in MSB
        0x00, 0x00, // Reserved 2 (2 bytes)
        0x00, 0x00,
    ];

    // SMV PDU starts here (after Ethernet + 8 bytes header)
    // Tag 0x60 (APPLICATION 0), length
    packet.extend_from_slice(&[0x60, 0x81, 0x8c]); // ~140 bytes length

    // noASDU (tag 0x80)
    packet.extend_from_slice(&[0x80, 0x01, 0x01]); // 1 ASDU

    // Sequence of ASDUs (tag 0xA2)
    packet.extend_from_slice(&[0xA2, 0x81, 0x84]); // ~132 bytes

    // ASDU (tag 0x30)
    packet.extend_from_slice(&[0x30, 0x81, 0x81]); // ~129 bytes

    // svID (tag 0x80) - VisibleString
    let sv_id = b"IED1/LLN0$MSVCB01";
    packet.push(0x80);
    packet.push(sv_id.len() as u8);
    packet.extend_from_slice(sv_id);

    // smpCnt (tag 0x82) - unsigned16
    packet.extend_from_slice(&[0x82, 0x02, 0x12, 0x34]);

    // confRev (tag 0x83) - unsigned32
    packet.extend_from_slice(&[0x83, 0x04, 0x00, 0x00, 0x00, 0x01]);

    // smpSynch (tag 0x85) - unsigned8
    packet.extend_from_slice(&[0x85, 0x01, 0x02]); // globally synced

    // sample values (tag 0x87) - ASN.1 BER encoded sequence
    // Calculate the length: 8 samples * (2+2+2+3) = 8 * 9 = 72 bytes
    // Each sample: tag(1) + len(1) + value(2) + tag(1) + len(1) + unused(1) + quality(2)
    packet.push(0x87);
    packet.push(72);

    // sample values (tag 0x87) - encode samples first to get actual size
    let mut samples_data = Vec::new();
    encode_samples(&mut samples_data, 8, 10000 + (1 as i32 * 5000));

    packet.extend_from_slice(&samples_data);

    packet
}

fn benchmark_92le_smv_decode(c: &mut Criterion) {
    let packet = create_92le_sample_smv_packet();

    c.bench_function("full_smv_decode", |b| {
        b.iter(|| {
            // Skip Ethernet header (14 bytes) and 8-byte SMV header
            decode_smv(black_box(&packet), black_box(22), &config_92le())
        });
    });
}

fn benchmark_throughput(c: &mut Criterion) {
    let packet = create_92le_sample_smv_packet();

    let mut group = c.benchmark_group("smv_throughput");

    // Simulate different packet rates
    for rate_khz in [4, 8, 16].iter() {
        group.bench_with_input(
            BenchmarkId::new("decode_rate_kHz", rate_khz),
            rate_khz,
            |b, _| {
                b.iter(|| decode_smv(black_box(&packet), black_box(22), &config_92le()));
            },
        );

        group.throughput(criterion::Throughput::Elements(*rate_khz as u64 * 1000));
    }

    group.finish();
}

fn benchmark_max_stress_decode(c: &mut Criterion) {
    let packet_realistic = create_max_realistic_smv_packet();
    let packet_stress = create_max_stress_smv_packet();

    // Validate packets first
    validate_packet(&packet_realistic, "Realistic Max (8×12)", &config(12));
    validate_packet(&packet_stress, "Stress Test (8×32)", &config(32));

    // Print packet information
    println!("\n=== SMV Packet Configurations ===");
    println!("Realistic Max (8 ASDUs × 12 samples = 96 total):");
    println!("  - Packet size: {} bytes", packet_realistic.len());
    println!(
        "  - MTU utilization: {:.1}%",
        (packet_realistic.len() as f64 / 1500.0) * 100.0
    );
    if packet_realistic.len() <= 1500 {
        println!("  - ✓ Fits within Ethernet MTU");
    } else {
        println!("  - ⚠️  Exceeds Ethernet MTU!");
    }

    println!("\nStress Test (8 ASDUs × 32 samples = 256 total):");
    println!("  - Packet size: {} bytes", packet_stress.len());
    println!(
        "  - MTU utilization: {:.1}%",
        (packet_stress.len() as f64 / 1500.0) * 100.0
    );
    if packet_stress.len() <= 1500 {
        println!("  - ✓ Fits within Ethernet MTU");
    } else {
        println!("  - ⚠️  Exceeds Ethernet MTU!");
    }
    println!("=================================\n");

    let mut group = c.benchmark_group("max_configurations");

    group.bench_function("realistic_max_8x12", |b| {
        b.iter(|| decode_smv(black_box(&packet_realistic), black_box(22), &config(12)));
    });

    group.bench_function("stress_test_8x32", |b| {
        b.iter(|| decode_smv(black_box(&packet_stress), black_box(22), &config(32)));
    });

    group.finish();
}

fn benchmark_decode_comparison(c: &mut Criterion) {
    let small_packet = create_92le_sample_smv_packet(); // 1 ASDU, 8 samples
    let realistic_packet = create_max_realistic_smv_packet(); // 8 ASDUs, 12 samples each
    let large_packet = create_max_stress_smv_packet(); // 8 ASDUs, 32 samples each

    println!("\n=== Comprehensive Packet Size Comparison ===");
    println!(
        "Small (1 ASDU × 8 samples = 8 total): {} bytes",
        small_packet.len()
    );
    println!(
        "Realistic Max (8 ASDUs × 12 samples = 96 total): {} bytes",
        realistic_packet.len()
    );
    println!(
        "Stress Test (8 ASDUs × 32 samples = 256 total): {} bytes",
        large_packet.len()
    );
    println!("\nSize ratios:");
    println!(
        "  - Realistic vs Small: {:.1}x larger",
        realistic_packet.len() as f64 / small_packet.len() as f64
    );
    println!(
        "  - Stress vs Small: {:.1}x larger",
        large_packet.len() as f64 / small_packet.len() as f64
    );
    println!(
        "  - Stress vs Realistic: {:.1}x larger",
        large_packet.len() as f64 / realistic_packet.len() as f64
    );
    println!("===========================================\n");

    let mut group = c.benchmark_group("smv_packet_comparison");

    group.bench_function("small_1x8", |b| {
        b.iter(|| decode_smv(black_box(&small_packet), black_box(22), &config_92le()));
    });

    group.bench_function("realistic_8x12", |b| {
        b.iter(|| decode_smv(black_box(&realistic_packet), black_box(22), &config(12)));
    });

    group.bench_function("stress_8x32", |b| {
        b.iter(|| decode_smv(black_box(&large_packet), black_box(22), &config(32)));
    });

    group.finish();
}

/// Helper function to create sample data for encoding benchmarks
fn create_sample_pdu(num_asdus: usize, samples_per_asdu: usize) -> SavPdu {
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
    let mut sav_asdu = Vec::new();

    for i in 0..num_asdus {
        let mut samples = Vec::new();
        for j in 0..samples_per_asdu {
            samples.push(Sample::new(10.00 + (i * 100 + j) as f32, QUALITY, 0.01));
        }

        sav_asdu.push(SavAsdu {
            msv_id: format!("IED1/LLN0$MSVCB{:02}", i + 1),
            dat_set: Some(format!("IED1/LLN0$DATASET{:02}", i + 1)),
            smp_cnt: (i * 1000) as u16,
            conf_rev: 1,
            refr_tm: Some([0x20, 0x21, 0x06, 0x12, 0x0A, 0x30, 0x00, 0x00]),
            smp_synch: 1,
            smp_rate: Some(4000),
            all_data: samples,
            smp_mod: None,
            gm_identity: None,
        });
    }

    SavPdu {
        sim: false,
        no_asdu: num_asdus as u16,
        security: None,
        sav_asdu,
    }
}

fn benchmark_smv_encode(c: &mut Criterion) {
    let header = EthernetHeader {
        dst_addr: [0x01, 0x0c, 0xcd, 0x04, 0x00, 0x01],
        src_addr: [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
        tpid: None,
        tci: None,
        ether_type: [0x88, 0xba], // SMV EtherType
        appid: [0x40, 0x00],
        length: [0x00, 0x00],
    };

    let small_pdu = create_sample_pdu(1, 8); // 1 ASDU × 8 samples
    let realistic_pdu = create_sample_pdu(8, 12); // 8 ASDUs × 12 samples
    let stress_pdu = create_sample_pdu(8, 32); // 8 ASDUs × 32 samples

    let mut group = c.benchmark_group("smv_encode");

    group.bench_function("small_1x8", |b| {
        b.iter(|| encode_smv(black_box(&header), black_box(&small_pdu)));
    });

    group.bench_function("realistic_8x12", |b| {
        b.iter(|| encode_smv(black_box(&header), black_box(&realistic_pdu)));
    });

    group.bench_function("stress_8x32", |b| {
        b.iter(|| encode_smv(black_box(&header), black_box(&stress_pdu)));
    });

    group.finish();
}

fn benchmark_smv_encode_comparison(c: &mut Criterion) {
    let header = EthernetHeader {
        dst_addr: [0x01, 0x0c, 0xcd, 0x04, 0x00, 0x01],
        src_addr: [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
        tpid: None,
        tci: None,
        ether_type: [0x88, 0xba],
        appid: [0x40, 0x00],
        length: [0x00, 0x00],
    };

    let small_pdu = create_sample_pdu(1, 8);
    let realistic_pdu = create_sample_pdu(8, 12);
    let stress_pdu = create_sample_pdu(8, 32);

    println!("\n=== SMV Encoding Performance (Zero-Copy) ===");
    println!("Testing zero-copy encoding with exact allocation");
    println!("================================================\n");

    let mut group = c.benchmark_group("smv_encode_comparison");

    // Small packet benchmarks
    group.bench_with_input(
        BenchmarkId::new("zero_copy", "small_1x8"),
        &small_pdu,
        |b, pdu| {
            b.iter(|| encode_smv(black_box(&header), black_box(pdu)));
        },
    );

    // Realistic packet benchmarks
    group.bench_with_input(
        BenchmarkId::new("zero_copy", "realistic_8x12"),
        &realistic_pdu,
        |b, pdu| {
            b.iter(|| encode_smv(black_box(&header), black_box(pdu)));
        },
    );

    // Stress packet benchmarks
    group.bench_with_input(
        BenchmarkId::new("zero_copy", "stress_8x32"),
        &stress_pdu,
        |b, pdu| {
            b.iter(|| encode_smv(black_box(&header), black_box(pdu)));
        },
    );

    group.finish();
}

fn benchmark_smv_roundtrip(c: &mut Criterion) {
    let header = EthernetHeader {
        dst_addr: [0x01, 0x0c, 0xcd, 0x04, 0x00, 0x01],
        src_addr: [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
        tpid: None,
        tci: None,
        ether_type: [0x88, 0xba],
        appid: [0x40, 0x00],
        length: [0x00, 0x00],
    };

    let small_pdu = create_sample_pdu(1, 8);
    let realistic_pdu = create_sample_pdu(8, 12);
    let stress_pdu = create_sample_pdu(8, 32);

    let mut group = c.benchmark_group("smv_roundtrip");

    group.bench_function("small_1x8", |b| {
        b.iter(|| {
            let encoded = encode_smv(black_box(&header), black_box(&small_pdu)).unwrap();
            decode_smv(black_box(&encoded), black_box(22), &config_92le())
        });
    });

    group.bench_function("realistic_8x12", |b| {
        b.iter(|| {
            let encoded = encode_smv(black_box(&header), black_box(&realistic_pdu)).unwrap();
            decode_smv(black_box(&encoded), black_box(22), &config(12))
        });
    });

    group.bench_function("stress_8x32", |b| {
        b.iter(|| {
            let encoded = encode_smv(black_box(&header), black_box(&stress_pdu)).unwrap();
            decode_smv(black_box(&encoded), black_box(22), &config(32))
        });
    });

    group.finish();
}

criterion_group!(
    benches,
    benchmark_92le_smv_decode,
    benchmark_throughput,
    benchmark_max_stress_decode,
    benchmark_decode_comparison,
    benchmark_smv_encode,
    benchmark_smv_encode_comparison,
    benchmark_smv_roundtrip
);
criterion_main!(benches);
