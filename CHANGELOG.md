# Changelog

All notable changes to Forte are documented here. The project follows
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Planned

- More verified SLEIGH p-code mappings
- Redistributable mixed-mode ELF fixtures

## [0.1.0] - 2026-08-02

### Added

- Big- and little-endian MIPS16e architecture definitions
- pypcode-backed 16-bit and extended 32-bit instruction decoding
- Odd-address mixed-mode hooks for `mips32` and `mipsel32`
- Delay-slot separation to prevent duplicated LLIL side effects
- Linux o32 calling conventions and related platforms
- Common integer, memory, pointer, floating-point, and control-flow LLIL
- Commands for function creation, odd-symbol seeding, self-test, and coverage
- Standalone decoder tests and cross-platform GitHub Actions CI
