# Changelog
All notable changes to this project will be documented in this file.  
This project adheres to [Semantic Versioning](https://semver.org/).

## [0.1.0] - 2025-09-05
### Added
- Initial public release of **dnssec-server**.
- Authoritative DNS server core with support for UDP, TCP, and DNS-over-TLS.
- Built-in DNSSEC: runtime signing, `buildDnssecMaterial` helper, DS record generation.
- Modern record types: `SVCB/HTTPS`, `TLSA`, `CAA`, `NSEC3`, and more.
- Low-level `encodeMessage` / `decodeMessage` API for raw DNS packets.


## [0.1.6] - 2025-09-12
### Added
- Added `parseZone()` function for compiling BIND-style zone files into a compact `{ origin, default_ttl, records }` object.
- Added `answerFromZone()` helper to resolve queries against compiled zones, returning `{ rcode, answers, authority, additionals, reason }`.
