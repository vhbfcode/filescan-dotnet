# Security Policy

## Scope and limitations

FileScan performs **heuristic detection** of malicious / script-injection content in
uploaded files. It is **not** a certified CDR (Content Disarm & Reconstruction) product
and is **not** a replacement for a full antivirus or a certified commercial solution.

- It is a **defense-in-depth layer**, not a guarantee.
- Obfuscated/encrypted payloads and zero-day threats may evade detection.
- The optional ClamAV layer detects **known** malware only (signature-based).
- The software is provided **without warranty** (see [LICENSE](LICENSE)).

Always validate behavior in your own environment before relying on it.

## Reporting a vulnerability

If you find a security issue in FileScan itself (e.g. a way to bypass a check, a
crash/DoS, or a false-negative class), please **open a private report** via GitHub
Security Advisories, or open an issue **without** including a working malicious payload.

Please do **not** attach real malware or real user documents to public issues.

## Handling test samples

The `_testfiles/` directory contains **synthetic** proof-of-concept samples (benign
demonstrators such as `app.alert`, `calc`, EICAR, and `<?php echo>`). Do not add real
malware or real user data to this repository.
