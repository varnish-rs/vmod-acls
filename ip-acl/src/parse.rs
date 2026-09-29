use std::fmt;
use std::net::IpAddr;
use std::str::FromStr;

use ipnet::IpNet;

/// Whether a matching rule lets the address through or rejects it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Action {
    /// Rule written without a leading `!`.
    Allow,
    /// Rule written with a leading `!`.
    Deny,
}

/// A single ACL entry: a network and what to do with addresses inside it.
///
/// Host bits in `net` are ignored: `10.0.0.1/8` covers the same addresses as `10.0.0.0/8`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Rule {
    pub action: Action,
    pub net: IpNet,
}

impl fmt::Display for Rule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.action == Action::Deny {
            f.write_str("!")?;
        }
        self.net.fmt(f)
    }
}

/// Parse a rule, silently clearing host bits. Use [`ParsedRule`] to find out whether that happened.
impl FromStr for Rule {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        s.parse::<ParsedRule>().map(|p| p.rule)
    }
}

/// Result of parsing a rule string, along with anything worth warning about.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParsedRule {
    /// The parsed rule, with host bits cleared.
    pub rule: Rule,
    /// The address had host bits set (e.g. `10.0.0.1/8`) and they were cleared.
    pub host_bits_masked: bool,
}

/// Parse `[!]addr[/prefix_len]`, ignoring surrounding whitespace.
///
/// Without a prefix length, the rule matches a single address (`/32` or `/128`).
impl FromStr for ParsedRule {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let input = s.trim();
        let (action, s) = match input.strip_prefix('!') {
            Some(rest) => (Action::Deny, rest),
            None => (Action::Allow, input),
        };
        let net = parse_net(s).ok_or_else(|| ParseError(input.to_owned()))?;
        let trunc = net.trunc();
        Ok(Self {
            rule: Rule { action, net: trunc },
            host_bits_masked: trunc != net,
        })
    }
}

/// Parse `addr[/prefix_len]`.
///
/// The address is parsed by `std`, not `ipnet`: `ipnet` accepts leading zeros (`010.0.0.0/8`
/// as `10.0.0.0/8`), which other tools read as octal, while `std` rejects them.
fn parse_net(s: &str) -> Option<IpNet> {
    match s.split_once('/') {
        None => s.parse::<IpAddr>().ok().map(IpNet::from),
        Some((addr, _)) => {
            addr.parse::<IpAddr>().ok()?;
            s.parse().ok()
        }
    }
}

/// A rule string could not be parsed. Holds the offending input, trimmed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseError(String);

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "invalid rule '{}', expected an IP address with an optional prefix length",
            self.0
        )
    }
}

impl std::error::Error for ParseError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(s: &str) -> ParsedRule {
        s.parse().unwrap()
    }

    #[test]
    fn plain_addresses() {
        let p = parse("127.0.0.1");
        assert_eq!(p.rule.action, Action::Allow);
        assert_eq!(p.rule.net.to_string(), "127.0.0.1/32");
        assert!(!p.host_bits_masked);

        let p = parse("::1");
        assert_eq!(p.rule.net.to_string(), "::1/128");
    }

    #[test]
    fn negation_and_prefix() {
        let p = parse("!10.0.0.0/8");
        assert_eq!(p.rule.action, Action::Deny);
        assert_eq!(p.rule.to_string(), "!10.0.0.0/8");

        assert_eq!(parse("!2001:db8::/32").rule.to_string(), "!2001:db8::/32");
        assert_eq!(parse("0.0.0.0/0").rule.to_string(), "0.0.0.0/0");
        assert_eq!(parse("::/0").rule.to_string(), "::/0");
    }

    #[test]
    fn whitespace_is_trimmed() {
        assert_eq!(parse("  !10.0.0.0/8\t\n").rule.to_string(), "!10.0.0.0/8");
    }

    #[test]
    fn host_bits_are_masked() {
        let p = parse("127.0.0.1/24");
        assert_eq!(p.rule.net.to_string(), "127.0.0.0/24");
        assert!(p.host_bits_masked);

        let p = parse("2001:db8::1/64");
        assert_eq!(p.rule.net.to_string(), "2001:db8::/64");
        assert!(p.host_bits_masked);

        assert!(!parse("10.0.0.0/8").host_bits_masked);
    }

    #[test]
    fn errors() {
        let err = |s: &str| s.parse::<ParsedRule>().unwrap_err();
        assert_eq!(err("  "), ParseError(String::new()));
        assert_eq!(err(" !10/8 "), ParseError("!10/8".into()));
        for s in [
            "",
            "!",
            "foo",
            "10/8",
            "/8",
            "fe80::1%eth0",
            "!!10.0.0.0",
            "! 10.0.0.0",
            "10.0.0.0/",
            "10.0.0.0/+8",
            "10.0.0.0/8/8",
            "10.0.0.0/33",
            "10.0.0.0/999",
            "::/129",
            "010.0.0.0/8",
            "10.0.0.01/32",
            "010.0.0.1",
        ] {
            assert_eq!(err(s), ParseError(s.into()));
        }
        assert_eq!(
            err("10.0.0.0/33").to_string(),
            "invalid rule '10.0.0.0/33', expected an IP address with an optional prefix length"
        );
    }
}
