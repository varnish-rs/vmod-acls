# ip-acl

Ordered IP access control lists, where **the first matching rule wins**.

```rust
use ip_acl::{Acl, Action, Coverage};

let mut acl = Acl::new();
acl.add("10.1.0.0/16").unwrap();  // allow 10.1.x.x ...
acl.add("!10.0.0.0/8").unwrap();  // ... but deny the rest of 10.x.x.x
acl.add("::1").unwrap();

assert_eq!(acl.lookup("10.1.2.3".parse().unwrap()), Some(Action::Allow));
assert_eq!(acl.lookup("10.2.0.0".parse().unwrap()), Some(Action::Deny));
assert_eq!(acl.lookup("192.0.2.1".parse().unwrap()), None);

// Rules that can never take effect are reported when added
let (_, coverage) = acl.add("10.1.2.0/24").unwrap();
assert_eq!(coverage, Coverage::Redundant);
```

- Rule syntax: `[!]address[/prefix_length]`. `!` denies; no prefix length means a single address.
- Networks are [`ipnet::IpNet`](https://docs.rs/ipnet) values (re-exported as `ip_acl::ipnet`).
- Host bits are cleared (`10.0.0.1/8` becomes `10.0.0.0/8`), and reported through
  `ParsedRule::host_bits_masked`.
- IPv4 and IPv6 rules are independent. IPv4-mapped IPv6 addresses (`::ffff:10.0.0.1`) are IPv6
  addresses and only match IPv6 rules.
- `add`/`push` return a `Coverage`, telling whether the rule is `Effective`, `Redundant` (earlier
  rules already do the same thing), or `Conflicting` (earlier rules with the opposite action shadow it).
- Rules are resolved into sorted disjoint ranges as they are added: lookups are a binary search over
  at most `2n + 1` ranges, independent of prefix lengths.

Used by [`vmod_acls`](../vmod_acls) to expose these ACLs to Varnish VCL.
