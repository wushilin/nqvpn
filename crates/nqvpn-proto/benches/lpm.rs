//! Is the trie actually faster *at our table sizes*?
//!
//! The published prefix-trie numbers use full BGP tables (~1M routes).
//! An nqvpn network holds tens to low hundreds of prefixes, where a
//! linear scan over contiguous memory is genuinely competitive. This
//! measures the shapes we actually deploy so the choice rests on data
//! rather than on asymptotics alone.
//!
//! Run with: cargo bench -p nqvpn-proto

use ipnet::IpNet;
use nqvpn_proto::lpm::LpmTable;
use nqvpn_proto::types::NodeId;
use std::hint::black_box;
use std::net::{IpAddr, Ipv4Addr};
use std::time::Instant;

/// The prefix mix a real network has: one /32 per member, plus a
/// handful of gateway LANs.
fn build(members: u32) -> (LpmTable, Vec<IpAddr>) {
    let mut t = LpmTable::new();
    let mut probes = Vec::new();
    for i in 0..members {
        let a = 10;
        let b = (i >> 16) as u8;
        let c = (i >> 8) as u8;
        let d = i as u8;
        let ip = Ipv4Addr::new(a, b, c, d);
        t.insert(IpNet::from(ipnet::Ipv4Net::new(ip, 32).unwrap()), i as NodeId);
        if i % 8 == 0 {
            probes.push(IpAddr::V4(ip));
        }
    }
    // Gateway LANs, the wide prefixes.
    for g in 0..(members / 20).max(1) {
        let net: IpNet = format!("192.168.{}.0/24", g % 256).parse().unwrap();
        t.insert(net, 100_000 + g as NodeId);
    }
    // A destination nobody owns — the miss path matters too.
    probes.push(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)));
    (t, probes)
}

/// The previous implementation, kept here only as a baseline so the
/// switch can be justified with numbers rather than asymptotics.
struct LinearScan {
    entries: Vec<(IpNet, NodeId)>,
}

impl LinearScan {
    fn build(members: u32) -> LinearScan {
        let mut entries: Vec<(IpNet, NodeId)> = Vec::new();
        for i in 0..members {
            let ip = Ipv4Addr::new(10, (i >> 16) as u8, (i >> 8) as u8, i as u8);
            entries.push((IpNet::from(ipnet::Ipv4Net::new(ip, 32).unwrap()), i as NodeId));
        }
        for g in 0..(members / 20).max(1) {
            entries.push((format!("192.168.{}.0/24", g % 256).parse().unwrap(), 100_000 + g));
        }
        entries.sort_by_key(|e| std::cmp::Reverse(e.0.prefix_len()));
        LinearScan { entries }
    }
    fn lookup(&self, ip: IpAddr) -> Option<NodeId> {
        self.entries.iter().find(|(n, _)| n.contains(&ip)).map(|(_, id)| *id)
    }
}

fn bench(members: u32) {
    let (table, probes) = build(members);
    let iters = 200_000usize;
    // Warm up so we measure steady state, not first-touch page faults.
    for p in &probes {
        black_box(table.lookup(*p));
    }
    let start = Instant::now();
    let mut hits = 0u64;
    for i in 0..iters {
        let p = probes[i % probes.len()];
        if black_box(table.lookup(p)).is_some() {
            hits += 1;
        }
    }
    let elapsed = start.elapsed();
    let trie_ns = elapsed.as_nanos() as f64 / iters as f64;

    // Same workload against the old linear scan.
    let linear = LinearScan::build(members);
    for p in &probes {
        black_box(linear.lookup(*p));
    }
    let start = Instant::now();
    for i in 0..iters {
        black_box(linear.lookup(probes[i % probes.len()]));
    }
    let linear_ns = start.elapsed().as_nanos() as f64 / iters as f64;

    println!(
        "  {members:>6}  {trie_ns:>8.1}  {linear_ns:>10.1}  {:>7.1}x   (hits {hits})",
        linear_ns / trie_ns
    );
}

fn main() {
    println!("prefixes   trie ns   linear ns   speedup");
    for n in [10u32, 50, 100, 500, 2_000, 10_000] {
        bench(n);
    }
}
