//! Microbenchmark for the in-VPN routing lookup (`LpmTable`), the trie
//! every outbound packet hits. It measures ONLY the longest-prefix match
//! — not crypto, framing, or I/O — so the number is the lookup-limited
//! ceiling on packets/sec, an upper bound the real data plane never
//! reaches (sealing + syscalls dominate). Usage: `lpm_bench [n_nodes]`.

use nqvpn_proto::lpm::LpmTable;
use std::hint::black_box;
use std::net::{IpAddr, Ipv4Addr};
use std::time::Instant;

fn node_ip(i: u32) -> Ipv4Addr {
    Ipv4Addr::new(10, 99, (i / 254) as u8, ((i % 254) + 1) as u8)
}

fn main() {
    let n: u32 = std::env::args().nth(1).and_then(|s| s.parse().ok()).unwrap_or(20);

    // The shapes this VPN stores: one /32 host route per member, plus a
    // couple of gateway relays fronting a LAN.
    let mut t = LpmTable::new();
    for i in 1..=n {
        t.insert(format!("{}/32", node_ip(i)).parse().unwrap(), i);
    }
    t.insert("192.168.10.0/24".parse().unwrap(), 1);
    t.insert("192.168.20.0/24".parse().unwrap(), 2);
    let prefixes = n as usize + 2;

    // A fixed 4096-entry query mix: ~70% member /32 hits, ~20% LAN hits,
    // ~10% misses — precomputed so the timed loop is pure lookup.
    const Q: usize = 4096;
    let mut queries: Vec<IpAddr> = Vec::with_capacity(Q);
    let mut s: u64 = 0x9e3779b97f4a7c15;
    let mut rng = || {
        s ^= s << 13;
        s ^= s >> 7;
        s ^= s << 17;
        s
    };
    for _ in 0..Q {
        let bucket = rng() % 10;
        let ip = if bucket < 7 {
            node_ip((rng() % n as u64) as u32 + 1)
        } else if bucket < 9 {
            let lan = if rng() & 1 == 0 { 10 } else { 20 };
            Ipv4Addr::new(192, 168, lan, ((rng() % 254) + 1) as u8)
        } else {
            Ipv4Addr::new(8, 8, (rng() % 254) as u8, (rng() % 254) as u8)
        };
        queries.push(IpAddr::V4(ip));
    }

    // Warm up caches/branch predictor.
    let mut acc = 0u32;
    for q in &queries {
        acc = acc.wrapping_add(t.lookup(*q).unwrap_or(0));
    }
    black_box(acc);

    let iters: u64 = 300_000_000;
    let start = Instant::now();
    let mut acc = 0u32;
    for i in 0..iters as usize {
        let q = queries[i & (Q - 1)];
        acc = acc.wrapping_add(black_box(t.lookup(black_box(q))).unwrap_or(0));
    }
    let el = start.elapsed();
    black_box(acc);

    let per = el.as_secs_f64() / iters as f64;
    let mlps = 1.0 / per / 1e6;
    println!("nodes={n}  prefixes={prefixes}  iters={iters}");
    println!("elapsed={:.3}s   {:.2} ns/lookup", el.as_secs_f64(), per * 1e9);
    println!("1 core : {mlps:.1} M lookups/s");
    println!("2 cores: {:.1} M lookups/s  (lookup-limited pps ceiling)", mlps * 2.0);
}
