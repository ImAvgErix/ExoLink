# Exocord jsonwebtoken compatibility fork

This directory contains the `jsonwebtoken` 10.4.0 crate source,
licensed MIT and originally published from
<https://github.com/Keats/jsonwebtoken>.

Exocord retains the 10.4.0 API required by LiveKit and removes the
unused RustCrypto provider. The application exclusively enables the
AWS-LC provider, which avoids the unfixed `rsa` timing vulnerability
present in the optional RustCrypto dependency graph.
