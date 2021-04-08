# reexec

[![crates.io](https://img.shields.io/crates/v/reexec.svg)](https://crates.io/crates/reexec)
[![Docs](https://docs.rs/reexec/badge.svg)](https://docs.rs/reexec)
[![GitHub Actions](https://github.com/cptpcrd/reexec/workflows/CI/badge.svg?branch=master&event=push)](https://github.com/cptpcrd/reexec/actions?query=workflow%3ACI+branch%3Amaster+event%3Apush)
[![Cirrus CI](https://api.cirrus-ci.com/github/cptpcrd/reexec.svg?branch=master)](https://cirrus-ci.com/github/cptpcrd/reexec)
[![codecov](https://codecov.io/gh/cptpcrd/reexec/branch/master/graph/badge.svg)](https://codecov.io/gh/cptpcrd/reexec)

A library that makes it easy to re-execute the current process.

# Why not just use `std::env::current_exe()`?

Advantages of `reexec`:

- Most OSes have multiple fallback methods (e.g. may work on Linux even if `/proc` isn't mounted)
- Sometimes able to re-execute the original program even if it has been replaced (only works on certain platforms, and only when `/proc` is mounted)
- Often able to avoid allocating memory
- Has an `unsafe` lower-level interface which some programs may find helpful

Disadvantages of `reexec`:

- OS support is more limited (see below)

# Supported OSes

Tested in CI:

- Linux
- macOS
- FreeBSD

Verified to work on:

- NetBSD
- OpenBSD (but see [below](#openbsd))

Untested:

- Solaris/IllumOS
- DragonFlyBSD

## OS-specific notes

### OpenBSD

OpenBSD doesn't provide a straightforward way to get the executable path, so this is done by looking at the first command-line argument. Hence this will only work if `argv[0]` is an absolute or relative path, not just a program name.

`std::env::current_exe()` does this too. However, `reexec` actually verifies that the path specified in `argv[0]` refers to the current executable; `std` does not. (The disadvantage of this is that `reexec` will not be able to get the executable path if the program has been replaced.)
