//! Ordered IP access control lists.
//!
//! An [`Acl`] is a list of rules such as `10.0.0.0/8` (allow) or `!192.168.0.0/16` (deny).
//! Unlike routing tables and Varnish's built-in ACLs, which pick the longest matching prefix,
//! here **the first rule that matches wins**:
//!
//! ```
//! use ip_acl::{Acl, Action};
//!
//! let mut acl = Acl::new();
//! acl.add("!10.0.0.0/8").unwrap();
//! acl.add("10.1.0.0/16").unwrap(); // never matches: 10.1.x.x is already denied above
//! acl.add("0.0.0.0/0").unwrap();
//!
//! assert_eq!(acl.lookup("10.1.2.3".parse().unwrap()), Some(Action::Deny));
//! assert_eq!(acl.lookup("192.0.2.1".parse().unwrap()), Some(Action::Allow));
//! assert_eq!(acl.lookup("::1".parse().unwrap()), None);
//! ```
//!
//! IPv4 and IPv6 are separate: IPv4 rules never match IPv6 addresses, including IPv4-mapped
//! ones like `::ffff:10.0.0.1`.
//!
//! Rules are resolved when added, so lookups are a binary search over at most `2n + 1`
//! ranges, whatever the prefix lengths.

mod parse;
mod ranges;

use std::net::IpAddr;

pub use ipnet;
use ipnet::IpNet;
pub use parse::{Action, ParseError, ParsedRule, Rule};
use ranges::Ranges;

/// What a newly added rule contributes, given the rules added before it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Coverage {
    /// The rule is the first match for at least one address.
    Effective,
    /// Every address in the rule is already matched by earlier rules with the same action.
    /// The rule changes nothing.
    Redundant,
    /// Every address in the rule is already matched by earlier rules, and some of them have the
    /// opposite action. The rule can never take effect, which is likely a mistake.
    Conflicting,
}

/// An ordered list of allow/deny rules, where the first matching rule decides.
#[derive(Debug, Clone, Default)]
pub struct Acl {
    v4: Ranges<u32>,
    v6: Ranges<u128>,
}

impl Acl {
    /// Create an empty ACL, which matches nothing.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Append a rule. It only applies to addresses that no earlier rule matches.
    pub fn push(&mut self, rule: Rule) -> Coverage {
        match rule.net {
            IpNet::V4(n) => {
                self.v4
                    .push(n.network().to_bits(), n.broadcast().to_bits(), rule.action)
            }
            IpNet::V6(n) => {
                self.v6
                    .push(n.network().to_bits(), n.broadcast().to_bits(), rule.action)
            }
        }
    }

    /// Parse and append a rule, see [`ParsedRule`] for the syntax.
    ///
    /// # Errors
    ///
    /// Returns an error if `s` is not a valid rule; the ACL is left unchanged.
    pub fn add(&mut self, s: &str) -> Result<(ParsedRule, Coverage), ParseError> {
        let parsed: ParsedRule = s.parse()?;
        Ok((parsed, self.push(parsed.rule)))
    }

    /// Action of the first rule matching `ip`, or `None` if no rule matches.
    #[must_use]
    pub fn lookup(&self, ip: IpAddr) -> Option<Action> {
        match ip {
            IpAddr::V4(a) => self.v4.lookup(a.to_bits()),
            IpAddr::V6(a) => self.v6.lookup(a.to_bits()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use Action::{Allow, Deny};

    fn acl(rules: &[&str]) -> Acl {
        let mut acl = Acl::new();
        for r in rules {
            acl.add(r).unwrap();
        }
        acl
    }

    fn lookup(acl: &Acl, ip: &str) -> Option<Action> {
        acl.lookup(ip.parse().unwrap())
    }

    #[test]
    fn empty_matches_nothing() {
        let a = Acl::new();
        assert_eq!(lookup(&a, "0.0.0.0"), None);
        assert_eq!(lookup(&a, "::"), None);
    }

    #[test]
    fn order_matters() {
        let a = acl(&["0.0.0.0/0", "!0.0.0.0/0"]);
        assert_eq!(lookup(&a, "1.2.3.4"), Some(Allow));
        assert_eq!(lookup(&a, "255.255.255.255"), Some(Allow));

        let a = acl(&["!0.0.0.0/0", "0.0.0.0/0"]);
        assert_eq!(lookup(&a, "1.2.3.4"), Some(Deny));
    }

    #[test]
    fn first_match_not_longest_prefix() {
        let a = acl(&["!10.0.0.0/8", "10.1.0.0/16"]);
        assert_eq!(lookup(&a, "10.1.2.3"), Some(Deny));

        let a = acl(&["10.1.0.0/16", "!10.0.0.0/8"]);
        assert_eq!(lookup(&a, "10.1.2.3"), Some(Allow));
        assert_eq!(lookup(&a, "10.2.0.0"), Some(Deny));
        assert_eq!(lookup(&a, "11.0.0.0"), None);
    }

    #[test]
    fn user_example() {
        let a = acl(&["::1", "!10.0.0.0/8", "127.0.0.1/24"]);
        assert_eq!(lookup(&a, "::1"), Some(Allow));
        assert_eq!(lookup(&a, "::2"), None);
        assert_eq!(lookup(&a, "10.20.30.40"), Some(Deny));
        assert_eq!(lookup(&a, "127.0.0.200"), Some(Allow));
        assert_eq!(lookup(&a, "127.0.1.1"), None);
    }

    #[test]
    fn families_are_separate() {
        let a = acl(&["0.0.0.0/0"]);
        assert_eq!(lookup(&a, "::ffff:10.0.0.1"), None);
        assert_eq!(lookup(&a, "::"), None);

        let a = acl(&["!::/0"]);
        assert_eq!(lookup(&a, "::ffff:10.0.0.1"), Some(Deny));
        assert_eq!(lookup(&a, "10.0.0.1"), None);
    }

    #[test]
    fn full_width_prefixes() {
        let a = acl(&[
            "!255.255.255.255",
            "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
            "::/0",
        ]);
        assert_eq!(lookup(&a, "255.255.255.255"), Some(Deny));
        assert_eq!(lookup(&a, "255.255.255.254"), None);
        assert_eq!(
            lookup(&a, "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"),
            Some(Allow)
        );
        assert_eq!(lookup(&a, "::"), Some(Allow));
    }

    #[test]
    fn coverage() {
        let cov = |acl: &mut Acl, s: &str| acl.add(s).unwrap().1;

        let mut a = Acl::new();
        assert_eq!(cov(&mut a, "!10.0.0.0/8"), Coverage::Effective);
        assert_eq!(cov(&mut a, "10.1.0.0/16"), Coverage::Conflicting);
        assert_eq!(cov(&mut a, "!10.1.0.0/16"), Coverage::Redundant);
        assert_eq!(cov(&mut a, "!10.0.0.0/8"), Coverage::Redundant);
        assert_eq!(cov(&mut a, "0.0.0.0/0"), Coverage::Effective);

        let mut a = Acl::new();
        assert_eq!(cov(&mut a, "10.1.0.0/16"), Coverage::Effective);
        assert_eq!(cov(&mut a, "!10.0.0.0/8"), Coverage::Effective);

        // Shadowed by the union of two earlier rules, not by any single one.
        let mut a = Acl::new();
        assert_eq!(cov(&mut a, "10.0.0.0/9"), Coverage::Effective);
        assert_eq!(cov(&mut a, "10.128.0.0/9"), Coverage::Effective);
        assert_eq!(cov(&mut a, "10.0.0.0/8"), Coverage::Redundant);
        assert_eq!(cov(&mut a, "!10.0.0.0/8"), Coverage::Conflicting);

        // Same network in the other family is unaffected.
        assert_eq!(cov(&mut a, "::ffff:10.0.0.0/104"), Coverage::Effective);
    }
}
