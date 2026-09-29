# vmod_acls

This is a vmod for [varnish](http://varnish-cache.org/) to match client IPs against ordered lists of IP addresses and CIDR blocks, built at load time from VCL.

Unlike native VCL ACLs, which are compiled into the VCL and pick the most specific match, `vmod_acls`:
- checks rules **in order**, the first matching rule decides
- supports negated rules (`!10.0.0.0/8`) to deny addresses
- tells apart "allowed", "denied" and "not found", so the default policy is up to you
- reports suspicious rules when the VCL loads: host bits set, rules shadowed by earlier ones

The full VCL API is described in [API.md](vmod_acls/API.md).

The matching logic lives in its own crate, [`ip-acl`](ip-acl), so other Rust projects and vmods can use it too.

Don't hesitate to open github issues if something is unclear or impractical. You can also join us on [discord](https://discord.com/invite/EuwdvbZR6d).

## Version matching

| vmod-acls | varnish |
| :-------- | :-----: |
| 0.1.0     | 9.0, 9.1 |

## VCL Examples

### Allow a few networks, deny everything else

``` vcl
import acls;

sub vcl_init {
	new admins = acls.ip_acl();
	admins.add("::1");
	admins.add("127.0.0.1");
	admins.add("192.0.2.0/24");
}

sub vcl_recv {
	if (req.url ~ "^/admin/" && !admins.allowed(client.ip)) {
		return (synth(403));
	}
}
```

### Order matters: exceptions go first

``` vcl
import acls;

sub vcl_init {
	new internal = acls.ip_acl();
	# 10.1.0.0/16 is allowed...
	internal.add("10.1.0.0/16");
	# ...but the rest of 10.0.0.0/8 is not
	internal.add("!10.0.0.0/8");
	# everybody else is fine
	internal.add("0.0.0.0/0");
	internal.add("::/0");
}

sub vcl_recv {
	if (internal.denied(client.ip)) {
		return (synth(403));
	}
}
```

Swapping the first two rules would deny all of `10.0.0.0/8`, and `10.1.0.0/16` would never match. `vmod_acls` notices and logs it when the VCL loads (see below).

### Choosing a default policy with `found()`

``` vcl
import acls;

sub vcl_init {
	new blocklist = acls.ip_acl();
	# a known partner inside the blocked range, it must come first
	blocklist.add("198.51.100.42");
	blocklist.add("!198.51.100.0/24");
	blocklist.add("!2001:db8:bad::/48");
}

sub vcl_recv {
	if (!blocklist.found(client.ip)) {
		# no rule matched: unknown clients go through, but get flagged
		set req.http.x-unknown-client = "1";
	} else if (blocklist.denied(client.ip)) {
		return (synth(403));
	}
}
```

## Rules

Each `add()` call takes one rule: `[!]address[/prefix_length]`.
- `10.0.0.0/8`, `2001:db8::/32`: allow a network
- `!10.0.0.0/8`: deny it
- `::1`, `192.0.2.7`: a single address, same as `/128` or `/32`

An invalid rule fails the VCL load. Some valid but suspicious rules are logged while the VCL loads, visible with `varnishlog -g raw -q 'Error or Notice'`:
- **host bits set**: `10.0.0.1/8` is treated as `10.0.0.0/8` (`Error`)
- **never matches**: earlier rules with the opposite action cover the whole rule (`Error`)
- **redundant**: earlier rules with the same action cover the whole rule (`Notice`)

IPv4 rules only match IPv4 addresses, and IPv6 rules only IPv6 addresses. Note that Varnish converts IPv4-mapped IPv6 addresses such as `::ffff:10.0.0.1` to IPv4, so those match IPv4 rules, as they do with native ACLs.

## Requirements

You'll need:
- `cargo` (and the accompanying `rust` package, 1.90 or newer)
- `clang`
- the `varnish` development libraries/headers ([depends on the `varnish` crate you are using](https://github.com/varnish-rs/varnish-rs#versions))

## Build and test

With `cargo` only:

``` bash
cargo build --release
cargo test --release
```

Build before testing: the VTC tests load the `.so` file produced by `cargo build`.

The vmod file will be found at `target/release/libvmod_acls.so`.
