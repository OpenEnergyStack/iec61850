use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use iec_61850::decode_basics::decode_ethernet_header;
use iec_61850::decode_goose::{decode_goose_pdu, is_goose_frame};
use iec_61850::encode_goose::{encode_ethernet_header, encode_goose};
use iec_61850::types::{EthernetHeader, IECData, IECGoosePdu, TimeQuality, Timestamp};

/// Create sample GOOSE PDU for encoding with realistic data size
/// Typical GOOSE frames contain 50-200 data points
/// This creates a large frame approaching Ethernet MTU limit (~1500 bytes)
fn create_sample_goose_pdu() -> IECGoosePdu {
    // Create a realistic dataset with ~220 data points
    // This represents a complete substation bay with:
    // - Circuit breaker statuses
    // - Disconnector positions
    // - Analog measurements (scaled integers)
    // - Quality bits
    // - Protection relay outputs
    let mut all_data = vec![];

    // 40 circuit breaker positions (Boolean)
    for i in 0..40 {
        all_data.push(IECData::Boolean(i % 2 == 0));
    }

    // 50 disconnector positions (Boolean)
    for i in 0..50 {
        all_data.push(IECData::Boolean(i % 3 == 0));
    }

    // 50 analog values (current/voltage as Int32)
    for i in 0..50 {
        all_data.push(IECData::Int((10000 + i * 1000) as i64));
    }

    // 50 quality/status values (UInt32 bitstrings)
    for i in 0..50 {
        all_data.push(IECData::UInt(0xC000 + i as u64)); // Quality bits
    }

    // Add structured data representing multiple bays (15 strings each with status info)
    for bay in 1..=15 {
        all_data.push(IECData::VisibleString(format!("BAY_{:02}_CB_STATUS", bay)));
        all_data.push(IECData::Int(13800 + bay as i64 * 10)); // Voltage
        all_data.push(IECData::Int(450 + bay as i64)); // Current
        all_data.push(IECData::Boolean(bay % 2 == 0)); // Trip signal
    }

    IECGoosePdu {
        go_cb_ref: "SUBSTATION1/BAY_COMPLETE/LLN0$GO$gcb_full_status".to_string(),
        time_allowed_to_live: 2000,
        dat_set: "SUBSTATION1/BAY_COMPLETE/LLN0$DATASET_FULL_STATUS".to_string(),
        go_id: "GOOSE_SUBSTATION_COMPLETE_STATUS".to_string(),
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
        num_dat_set_entries: all_data.len() as u32,
        all_data,
    }
}

/// Create a large GOOSE packet dynamically for benchmarking
/// This approaches the Ethernet MTU limit (~1500 bytes)
fn create_large_goose_packet() -> Vec<u8> {
    let header = create_sample_ethernet_header();
    let pdu = create_sample_goose_pdu();
    encode_goose(&header, &pdu).expect("Failed to encode large GOOSE packet")
}

/// Create sample Ethernet header for encoding
fn create_sample_ethernet_header() -> EthernetHeader {
    EthernetHeader {
        dst_addr: [0x01, 0x0c, 0xcd, 0x01, 0x00, 0x01],
        src_addr: [0x00, 0x1a, 0xb6, 0x03, 0x2f, 0x1c],
        tpid: Some([0x81, 0x00]),
        tci: Some([0x00, 0x01]),
        ether_type: [0x88, 0xb8],
        appid: [0x10, 0x01],
        length: [0x00, 0x8c],
    }
}

fn benchmark_goose_frame_detection(c: &mut Criterion) {
    let packet = create_large_goose_packet();

    // Print packet size information
    println!("\n=== GOOSE Benchmark Packet Info ===");
    println!("Total packet size: {} bytes", packet.len());
    println!("Ethernet MTU limit: ~1500 bytes");
    println!(
        "Utilization: {:.1}%",
        (packet.len() as f64 / 1500.0) * 100.0
    );
    println!("===================================\n");

    c.bench_function("goose_frame_detection", |b| {
        b.iter(|| is_goose_frame(black_box(&packet)));
    });
}

fn benchmark_goose_pdu_decode(c: &mut Criterion) {
    let packet = create_large_goose_packet();
    let mut header = EthernetHeader::default();
    let pos = decode_ethernet_header(&mut header, &packet);

    c.bench_function("goose_pdu_decode", |b| {
        b.iter(|| decode_goose_pdu(black_box(&packet), black_box(pos)));
    });
}

fn benchmark_full_goose_decode(c: &mut Criterion) {
    let packet = create_large_goose_packet();

    c.bench_function("full_goose_decode", |b| {
        b.iter(|| {
            let mut header = EthernetHeader::default();
            let pos = decode_ethernet_header(black_box(&mut header), black_box(&packet));
            decode_goose_pdu(black_box(&packet), black_box(pos))
        });
    });
}

fn benchmark_ethernet_header_encode(c: &mut Criterion) {
    let header = create_sample_ethernet_header();

    c.bench_function("ethernet_header_encode", |b| {
        b.iter(|| encode_ethernet_header(black_box(&header), black_box(140)));
    });
}

fn benchmark_goose_pdu_encode(c: &mut Criterion) {
    let header = create_sample_ethernet_header();
    let pdu = create_sample_goose_pdu();

    c.bench_function("goose_pdu_encode", |b| {
        b.iter(|| encode_goose(black_box(&header), black_box(&pdu)));
    });
}

fn benchmark_encode_decode_roundtrip(c: &mut Criterion) {
    let header = create_sample_ethernet_header();
    let pdu = create_sample_goose_pdu();

    c.bench_function("goose_encode_decode_roundtrip", |b| {
        b.iter(|| {
            // Encode
            let encoded = encode_goose(black_box(&header), black_box(&pdu)).unwrap();

            // Decode
            let mut decoded_header = EthernetHeader::default();
            let pos = decode_ethernet_header(black_box(&mut decoded_header), black_box(&encoded));
            decode_goose_pdu(black_box(&encoded), black_box(pos))
        });
    });
}

fn benchmark_goose_with_different_data_sizes(c: &mut Criterion) {
    let mut group = c.benchmark_group("goose_data_size");

    // Test realistic data sizes from small to large (approaching MTU limit)
    // Typical GOOSE: 10-200 data points
    // Ethernet MTU: ~1500 bytes (including headers)
    for num_elements in [10, 50, 100, 150, 200].iter() {
        let header = create_sample_ethernet_header();
        let mut pdu = create_sample_goose_pdu();

        // Create mixed data with specified number of elements
        // Mix of different data types to be realistic
        pdu.all_data = (0..*num_elements)
            .map(|i| match i % 5 {
                0 => IECData::Boolean(i % 2 == 0),
                1 => IECData::Int((i * 1000) as i64),
                2 => IECData::UInt(0xC000 + i as u64),
                3 => IECData::Float(i as f64 * 1.5),
                _ => IECData::VisibleString(format!("DATA_{:03}", i)),
            })
            .collect();
        pdu.num_dat_set_entries = *num_elements;

        group.bench_with_input(
            BenchmarkId::new("encode", num_elements),
            num_elements,
            |b, _| {
                b.iter(|| encode_goose(black_box(&header), black_box(&pdu)));
            },
        );
    }

    group.finish();
}

fn benchmark_goose_rates(c: &mut Criterion) {
    let packet = create_large_goose_packet();
    let mut group = c.benchmark_group("goose_packet_rates");

    // GOOSE typical rates (much slower than SMV)
    for rate_hz in [50, 100, 1000].iter() {
        group.bench_with_input(
            BenchmarkId::new("decode_rate_Hz", rate_hz),
            rate_hz,
            |b, _| {
                b.iter(|| {
                    let mut header = EthernetHeader::default();
                    let pos = decode_ethernet_header(black_box(&mut header), black_box(&packet));
                    decode_goose_pdu(black_box(&packet), black_box(pos))
                });
            },
        );

        group.throughput(criterion::Throughput::Elements(*rate_hz as u64));
    }

    group.finish();
}

criterion_group!(
    benches,
    benchmark_goose_frame_detection,
    benchmark_goose_pdu_decode,
    benchmark_full_goose_decode,
    benchmark_ethernet_header_encode,
    benchmark_goose_pdu_encode,
    benchmark_encode_decode_roundtrip,
    benchmark_goose_with_different_data_sizes,
    benchmark_goose_rates
);
criterion_main!(benches);
