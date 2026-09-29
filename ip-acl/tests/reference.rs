//! Compare `Acl` against a naive first-match linear scan.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use ip_acl::ipnet::IpNet;
use ip_acl::{Acl, Action, Coverage, Rule};
use proptest::prelude::*;

fn first_match(rules: &[Rule], ip: IpAddr) -> Option<Action> {
    rules.iter().find(|r| r.net.contains(&ip)).map(|r| r.action)
}

fn action() -> impl Strategy<Value = Action> {
    prop_oneof![Just(Action::Allow), Just(Action::Deny)]
}

/// Addresses are drawn from a small pool of bit patterns so that rules overlap often.
fn v4() -> impl Strategy<Value = Ipv4Addr> {
    prop_oneof![
        any::<u32>(),
        (0u32..16, 0u32..16).prop_map(|(hi, lo)| (hi << 28) | lo),
        Just(0),
        Just(u32::MAX),
    ]
    .prop_map(Ipv4Addr::from_bits)
}

fn v6() -> impl Strategy<Value = Ipv6Addr> {
    prop_oneof![
        any::<u128>(),
        (0u128..16, 0u128..16).prop_map(|(hi, lo)| (hi << 124) | lo),
        Just(0),
        Just(u128::MAX),
    ]
    .prop_map(Ipv6Addr::from_bits)
}

fn rule() -> impl Strategy<Value = Rule> {
    prop_oneof![
        (v4(), 0u8..=32).prop_map(|(a, l)| (IpAddr::V4(a), l)),
        (v6(), 0u8..=128).prop_map(|(a, l)| (IpAddr::V6(a), l)),
    ]
    .prop_flat_map(|(addr, len)| {
        action().prop_map(move |action| Rule {
            action,
            net: IpNet::new(addr, len).unwrap().trunc(),
        })
    })
}

/// Probe addresses: random ones, plus the edges of each rule's range.
fn probes(rules: &[Rule], extra: &[IpAddr]) -> Vec<IpAddr> {
    let mut out = extra.to_vec();
    for r in rules {
        match r.net {
            IpNet::V4(n) => {
                let (s, e) = (n.network().to_bits(), n.broadcast().to_bits());
                for x in [s.wrapping_sub(1), s, e, e.wrapping_add(1)] {
                    out.push(IpAddr::V4(Ipv4Addr::from_bits(x)));
                }
            }
            IpNet::V6(n) => {
                let (s, e) = (n.network().to_bits(), n.broadcast().to_bits());
                for x in [s.wrapping_sub(1), s, e, e.wrapping_add(1)] {
                    out.push(IpAddr::V6(Ipv6Addr::from_bits(x)));
                }
            }
        }
    }
    out
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2000))]

    #[test]
    fn lookup_matches_linear_scan(
        rules in prop::collection::vec(rule(), 0..40),
        extra in prop::collection::vec(prop_oneof![v4().prop_map(IpAddr::V4), v6().prop_map(IpAddr::V6)], 0..20),
    ) {
        let mut acl = Acl::new();
        for r in &rules {
            acl.push(*r);
        }
        for ip in probes(&rules, &extra) {
            prop_assert_eq!(acl.lookup(ip), first_match(&rules, ip), "ip {}", ip);
        }
    }

    #[test]
    fn coverage_matches_linear_scan(rules in prop::collection::vec(rule(), 1..40)) {
        let mut acl = Acl::new();
        for (i, r) in rules.iter().enumerate() {
            let cov = acl.push(*r);
            // A rule is dead iff every address in it has an earlier first match. Checking that
            // exhaustively is impossible, but the boundaries of all rules so far split the space
            // into ranges on which the earlier first match is constant, so probing those is enough.
            let earlier = &rules[..i];
            let mut effective = false;
            let mut conflict = false;
            for ip in probes(&rules[..=i], &[]) {
                if !r.net.contains(&ip) {
                    continue;
                }
                match first_match(earlier, ip) {
                    None => effective = true,
                    Some(a) if a != r.action => conflict = true,
                    Some(_) => {}
                }
            }
            let expected = if effective {
                Coverage::Effective
            } else if conflict {
                Coverage::Conflicting
            } else {
                Coverage::Redundant
            };
            prop_assert_eq!(cov, expected, "rule #{} {}", i, r);
        }
    }
}
