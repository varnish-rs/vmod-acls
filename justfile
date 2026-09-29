#!/usr/bin/env just --justfile

main_crate := 'vmod_acls'
packages := '--workspace'  # All crates in the workspace
features := '--all-features'  # Enable all features
targets := '--all-targets'  # For all targets (lib, bin, tests, examples, benches)

# which version of Varnish to install by default. Update the `supported_varnish_vers` variable below.
default_varnish_ver := '9.1'

# Make sure to update CI with the changes.
supported_varnish_vers := '9.0 9.1'

# if running in CI, treat warnings as errors by setting RUSTFLAGS and RUSTDOCFLAGS to '-D warnings' unless they are already set
# Use `CI=true just ci-test` to run the same tests as in GitHub CI.
# Use `just env-info` to see the current values of RUSTFLAGS and RUSTDOCFLAGS
ci_mode := if env('CI', '') != '' {'1'} else {''}
# On macOS, .cargo/config.toml sets `-undefined,dynamic_lookup` so VMOD cdylibs
# can defer host-symbol resolution to runtime. But cargo precedence drops
# target.<cfg>.rustflags the moment RUSTFLAGS env is set — which we do below —
# so the flag has to be in RUSTFLAGS too, otherwise `just build` fails to link.
macos_link_arg := if os() == 'macos' {' -C link-arg=-Wl,-undefined,dynamic_lookup'} else {''}
export RUSTFLAGS := env('RUSTFLAGS', (if ci_mode == '1' {'-D warnings'} else {''}) + macos_link_arg)
export RUSTDOCFLAGS := env('RUSTDOCFLAGS', if ci_mode == '1' {'-D warnings'} else {''})
export RUST_BACKTRACE := env('RUST_BACKTRACE', if ci_mode == '1' {'1'} else {''})

@_default:
    {{just_executable()}} --list

# Run the ip-acl benchmarks, e.g. `just bench lookup/v6`
bench *args:
    cargo bench -p ip-acl --bench acl -- {{args}}

# Build the project with just the default and all features
build:
    cargo build {{packages}} {{features}}
    cargo build {{packages}} {{features}} {{targets}}

# Quick compile without building a binary
check:
    cargo check {{packages}} {{features}} {{targets}}

# Run all tests as expected by CI
ci-test: env-info test-fmt build clippy test && assert-git-is-clean

# Run tests only relevant to the latest Varnish version
ci-test-latest: ci-test test-doc

# Clean all build artifacts
clean:
    cargo clean

# Run cargo clippy to lint the code
clippy *args:
    cargo clippy {{packages}} {{features}} {{targets}} {{args}}

# Build and open code documentation
docs *args='--open':
    DOCS_RS=1 cargo doc --no-deps {{args}} {{packages}}

# Print environment info
env-info: && get-varnish-version
    @echo "Running for '{{main_crate}}' crate {{if ci_mode == '1' {'in CI mode'} else {'in dev mode'} }} on {{os()}} / {{arch()}}"
    @echo "PWD $(pwd)"
    {{just_executable()}} --version
    rustc --version
    cargo --version
    rustup --version
    @echo "RUSTFLAGS='$RUSTFLAGS'"
    @echo "RUSTDOCFLAGS='$RUSTDOCFLAGS'"
    @echo "RUST_BACKTRACE='$RUST_BACKTRACE'"

# Reformat all code `cargo fmt`. If nightly is available, use it for better results
fmt:
    #!/usr/bin/env bash
    set -euo pipefail
    if (rustup toolchain list | grep nightly && rustup component list --toolchain nightly | grep rustfmt) &> /dev/null; then
        echo 'Reformatting Rust code using nightly Rust fmt to sort imports'
        cargo +nightly fmt --all -- --config imports_granularity=Module,group_imports=StdExternalCrate
    else
        echo 'Reformatting Rust with the stable cargo fmt.  Install nightly with `rustup install nightly` for better results'
        cargo fmt --all
    fi

# Get the version of Varnish installed on the system. If a version arg is provided, check that the installed version is at least that version. If param is 'print', just print the installed version.
get-varnish-version $required_version='':
    #!/usr/bin/env bash
    set -euo pipefail
    VARNISH_VER=$(varnishd -V 2>&1 | sed -n 's/.*varnish-\([^ )]*\).*/\1/p' | head -1)
    if [ -z "$VARNISH_VER" ]; then
        echo "ERROR: varnishd not found or version could not be parsed"
        exit 1
    elif [ "$required_version" = 'print' ]; then
        echo "$VARNISH_VER"
    elif [ -n "$required_version" ]; then
        if [ "$(printf "$required_version\n$VARNISH_VER" | sort -V | head -n1)" != "$required_version" ]; then
            echo "ERROR: Varnish version $required_version is required, but $VARNISH_VER is installed."
            exit 1
        else
            echo "Found varnishd $VARNISH_VER >= $required_version"
        fi
    else
        echo "Found varnishd $VARNISH_VER"
    fi

# Run all unit and integration tests. Builds first: the VTC tests load the vmod's .so file.
test *args: build
    cargo test {{packages}} {{features}} {{targets}} {{args}}
    cargo test {{packages}} {{features}} --doc {{args}}

# Test documentation generation
test-doc:  (docs '')

# Test code formatting
test-fmt:
    cargo fmt --all -- --check

# Update all dependencies, including breaking changes. Requires nightly toolchain (install with `rustup install nightly`)
update:
    cargo +nightly -Z unstable-options update --breaking
    cargo update

# Ensure that a certain command is available
[private]
assert-cmd command:
    @if ! type {{command}} > /dev/null; then \
        echo "Command '{{command}}' could not be found. Please make sure it has been installed on your computer." ;\
        exit 1 ;\
    fi

# Make sure the git repo has no uncommitted changes
[private]
assert-git-is-clean:
    @if [ -n "$(git status --untracked-files --porcelain)" ]; then \
      >&2 echo "ERROR: git repo is no longer clean. Make sure compilation and tests artifacts are in the .gitignore, and no repo files are modified." ;\
      >&2 echo "######### git status ##########" ;\
      git status ;\
      git --no-pager diff ;\
      exit 1 ;\
    fi

# Install Varnish from packages.varnish-software.com (Debian/Ubuntu only).
# This could be damaging to your system - use with caution. Pass non-empty `debug` argument to skip the installation.
[private]
install-varnish version=default_varnish_ver debug='':
    #!/usr/bin/env bash
    set -euo pipefail

    echo "Installing Varnish '{{version}}'"
    {{ if debug != '' {'exit 0'} else {''} }}

    set -x
    curl -Ls https://packages.varnish-software.com/varnish/bootstrap-deb.sh | sudo sh

    cat << -EOF | sudo tee /etc/apt/preferences.d/varnish
        Package: varnish varnish-dev
        Pin: origin "packages.varnish-software.com"
        Pin: version {{version}}
        Pin-Priority: 1001
    -EOF
    cat /etc/apt/preferences.d/varnish

    sudo apt-cache policy "varnish"
    sudo apt-get install -y "varnish={{version}}*" "varnish-dev={{version}}*"
