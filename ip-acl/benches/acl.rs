//! Build and lookup costs for `Acl`, with a linear first-match scan as a baseline.
//!
//! Run with `cargo bench -p ip-acl`, or e.g. `cargo bench -p ip-acl -- lookup/v4` to filter.

use std::hint::black_box;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use ip_acl::ipnet::IpNet;
use ip_acl::{Acl, Action, Rule};

/// Deterministic xorshift, so every run benches the same rules.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    fn range(&mut self, lo: u8, hi: u8) -> u8 {
        lo + (self.next() % u64::from(hi - lo + 1)) as u8
    }

    fn action(&mut self) -> Action {
        if self.next() & 1 == 0 {
            Action::Allow
        } else {
            Action::Deny
        }
    }
}

#[derive(Clone, Copy)]
enum Family {
    V4,
    V6,
}

impl Family {
    fn name(self) -> &'static str {
        match self {
            Self::V4 => "v4",
            Self::V6 => "v6",
        }
    }

    fn random_ip(self, rng: &mut Rng) -> IpAddr {
        match self {
            Self::V4 => IpAddr::V4(Ipv4Addr::from_bits(rng.next() as u32)),
            Self::V6 => IpAddr::V6(Ipv6Addr::from_bits(
                (u128::from(rng.next()) << 64) | u128::from(rng.next()),
            )),
        }
    }

    /// Prefix lengths typical of real-world lists: /8../32 for IPv4, /16../64 for IPv6.
    fn random_rule(self, rng: &mut Rng) -> Rule {
        let len = match self {
            Self::V4 => rng.range(8, 32),
            Self::V6 => rng.range(16, 64),
        };
        let net = IpNet::new(self.random_ip(rng), len).unwrap().trunc();
        Rule {
            action: rng.action(),
            net,
        }
    }
}

fn rules(family: Family, n: usize) -> Vec<Rule> {
    let mut rng = Rng(0x9e37_79b9_7f4a_7c15 ^ n as u64);
    (0..n).map(|_| family.random_rule(&mut rng)).collect()
}

fn build(rules: &[Rule]) -> Acl {
    let mut acl = Acl::new();
    for r in rules {
        acl.push(*r);
    }
    acl
}

/// Addresses inside the rules (hits), or uniformly random (mostly misses for IPv6).
fn probes(family: Family, rules: &[Rule], hits: bool) -> Vec<IpAddr> {
    let mut rng = Rng(0x2545_f491_4f6c_dd1d);
    (0..1024)
        .map(|i| {
            if hits {
                rules[i % rules.len()].net.network()
            } else {
                family.random_ip(&mut rng)
            }
        })
        .collect()
}

const SIZES: [usize; 4] = [10, 100, 10_000, 100_000];

fn bench_build(c: &mut Criterion) {
    let mut g = c.benchmark_group("build");
    g.sample_size(10);
    for family in [Family::V4, Family::V6] {
        for n in SIZES {
            let random = rules(family, n);
            let mut sorted = random.clone();
            sorted.sort_by_key(|r| r.net.network());
            g.throughput(Throughput::Elements(n as u64));
            for (order, rules) in [("random", &random), ("sorted", &sorted)] {
                g.bench_with_input(
                    BenchmarkId::new(format!("{}/{order}", family.name()), n),
                    rules,
                    |b, rules| b.iter(|| build(black_box(rules))),
                );
            }
        }
    }
    g.finish();
}

fn bench_lookup(c: &mut Criterion) {
    let mut g = c.benchmark_group("lookup");
    for family in [Family::V4, Family::V6] {
        for n in SIZES {
            let rules = rules(family, n);
            let acl = build(&rules);
            for (kind, hits) in [("hit", true), ("random", false)] {
                let probes = probes(family, &rules, hits);
                g.throughput(Throughput::Elements(probes.len() as u64));
                g.bench_with_input(
                    BenchmarkId::new(format!("{}/{kind}", family.name()), n),
                    &probes,
                    |b, probes| {
                        b.iter(|| {
                            for ip in probes {
                                black_box(acl.lookup(black_box(*ip)));
                            }
                        });
                    },
                );
            }
        }
    }
    g.finish();
}

/// What `Acl` replaces: scanning rules in order. Only small sizes, it gets slow quickly.
fn bench_linear_baseline(c: &mut Criterion) {
    let mut g = c.benchmark_group("linear_scan");
    for family in [Family::V4, Family::V6] {
        for n in [10, 100, 1_000] {
            let rules = rules(family, n);
            let probes = probes(family, &rules, true);
            g.throughput(Throughput::Elements(probes.len() as u64));
            g.bench_with_input(
                BenchmarkId::new(format!("{}/hit", family.name()), n),
                &probes,
                |b, probes| {
                    b.iter(|| {
                        for ip in probes {
                            let ip = black_box(*ip);
                            black_box(rules.iter().find(|r| r.net.contains(&ip)).map(|r| r.action));
                        }
                    });
                },
            );
        }
    }
    g.finish();
}

criterion_group!(benches, bench_build, bench_lookup, bench_linear_baseline);
criterion_main!(benches);
