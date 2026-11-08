# password-audit-rs 🦀

Password strength auditor in Rust. Checks entropy, patterns, and generates HIBP SHA-1 prefix.

## Usage
```bash
password-audit "MyP@ssw0rd!"
password-audit -f passwords.txt
```

## Checks
- Entropy calculation (bits)
- Length requirements
- Common sequences (qwerty, 12345, etc.)
- Repeated characters
- HIBP k-anonymity hash prefix

## License
MIT
