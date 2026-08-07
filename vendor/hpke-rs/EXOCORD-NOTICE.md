# Exocord hpke-rs compatibility fork

This directory contains the `hpke-rs` 0.6.1 crate source, licensed
MPL-2.0 and originally published from
<https://github.com/cryspen/hpke-rs>.

Exocord keeps the 0.6.1 public API required by OpenMLS 0.8.1, updates
`libcrux-sha3` to 0.0.10, and removes the unused optional libcrux
provider. The application uses `hpke-rs-rust-crypto`.
