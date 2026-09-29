// Doc comments below document the VCL interface (they generate API.md), not a Rust API.
#![allow(
    clippy::must_use_candidate,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::self_named_constructors
)]

use std::net::SocketAddr;
use std::sync::RwLock;

use ip_acl::{Acl, Action};

varnish::run_vtc_tests!("tests/*.vtc");

/// An ordered list of IP/CIDR rules, where the first matching rule decides.
pub struct IpAcl {
    name: String,
    /// Written only by `add()` in `vcl_init`, read by every lookup.
    acl: RwLock<Acl>,
}

impl IpAcl {
    fn lookup(&self, ip: Option<SocketAddr>) -> Option<Action> {
        // Whether libc turns `::ffff:a.b.c.d` into IPv4 depends on the platform, so do it here.
        self.acl.read().unwrap().lookup(ip?.ip().to_canonical())
    }
}

/// Ordered IP access control lists.
///
/// Rules are added in `vcl_init` and checked in order: the first rule matching an address
/// decides whether it is allowed (`10.0.0.0/8`) or denied (`!10.0.0.0/8`).
/// This differs from native VCL ACLs, which pick the most specific match.
///
/// ```vcl
/// import acls;
///
/// sub vcl_init {
///     new internal = acls.ip_acl();
///     internal.add("::1");
///     internal.add("!10.0.0.0/8");
///     internal.add("127.0.0.1/24");
/// }
///
/// sub vcl_recv {
///     if (!internal.allowed(client.ip)) {
///         return (synth(403));
///     }
/// }
/// ```
///
/// IPv4 rules only match IPv4 addresses, and IPv6 rules only IPv6 addresses. IPv4-mapped IPv6
/// addresses such as `::ffff:10.0.0.1` are looked up as IPv4 (`10.0.0.1`), so they match IPv4
/// rules, and IPv6 rules inside `::ffff:0:0/96` never match.
#[varnish::vmod(docs = "API.md")]
mod acls {
    use std::net::SocketAddr;
    use std::sync::RwLock;

    use ip_acl::ipnet::{IpNet, Ipv4Net};
    use ip_acl::{Acl, Action, Coverage};
    use varnish::vcl::{Ctx, LogTag, VclError};

    use super::IpAcl;

    impl IpAcl {
        /// Create an empty ACL, matching no address.
        pub fn ip_acl(#[vcl_name] name: &str) -> Self {
            Self {
                name: name.to_owned(),
                acl: RwLock::new(Acl::new()),
            }
        }

        /// Append a rule: `[!]address[/prefix_length]`, e.g. `10.0.0.0/8`, `!2001:db8::/32`
        /// or `::1`. A leading `!` denies instead of allowing. Without a prefix length, the rule
        /// covers a single address.
        ///
        /// The rule only applies to addresses that no earlier rule matched. Lookups made in
        /// `vcl_init` see the rules added so far.
        ///
        /// An invalid rule fails the VCL load. Suspicious rules are reported in the log during
        /// the load (`varnishlog -g raw`):
        /// - `Error` if the address has host bits set (`10.0.0.1/8` is treated as `10.0.0.0/8`),
        /// - `Error` if earlier rules with the opposite action cover the whole rule, so it can
        ///   never take effect,
        /// - `Notice` if earlier rules with the same action cover the whole rule, making it
        ///   redundant,
        /// - `Error` if the rule is inside `::ffff:0:0/96`: IPv4-mapped addresses are looked up
        ///   as IPv4, so it never matches. Write the IPv4 rule instead.
        #[restrict(vcl_init)]
        pub fn add(&self, ctx: &mut Ctx, rule: &str) -> Result<(), VclError> {
            let name = &self.name;
            let (parsed, coverage) = self
                .acl
                .write()
                .unwrap()
                .add(rule)
                .map_err(|e| VclError::new(format!("{name}.add(): {e}")))?;
            let net = parsed.rule.net;
            if parsed.host_bits_masked {
                ctx.log(
                    LogTag::Error,
                    format!("{name}.add(\"{rule}\"): address has host bits set, using {net}"),
                );
            }
            if let IpNet::V6(v6) = net
                && v6.prefix_len() >= 96
                && let Some(v4) = v6.network().to_ipv4_mapped()
            {
                let v4 = Ipv4Net::new_assert(v4, v6.prefix_len() - 96);
                ctx.log(LogTag::Error, format!("{name}.add(\"{rule}\"): never matches, IPv4-mapped addresses are looked up as IPv4, use {v4} instead"));
            }
            match coverage {
                Coverage::Effective => {}
                Coverage::Redundant => {
                    ctx.log(LogTag::Notice, format!("{name}.add(\"{rule}\"): redundant, earlier rules already match all of {net} the same way"));
                }
                Coverage::Conflicting => {
                    ctx.log(LogTag::Error, format!("{name}.add(\"{rule}\"): never matches, earlier rules with the opposite action cover all of {net}"));
                }
            }
            Ok(())
        }

        /// Whether any rule matches `ip`.
        pub fn found(&self, ip: Option<SocketAddr>) -> bool {
            self.lookup(ip).is_some()
        }

        /// Whether the first rule matching `ip` is an allow rule. False if no rule matches.
        pub fn allowed(&self, ip: Option<SocketAddr>) -> bool {
            self.lookup(ip) == Some(Action::Allow)
        }

        /// Whether the first rule matching `ip` is a deny (`!`) rule. False if no rule matches.
        pub fn denied(&self, ip: Option<SocketAddr>) -> bool {
            self.lookup(ip) == Some(Action::Deny)
        }
    }
}
