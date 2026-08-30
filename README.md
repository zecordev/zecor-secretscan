# zecor-secretscan

SIMD-accelerated secret and high-entropy-token scanning for diffs and files.

Part of [Zecor](https://zecor.dev) -- an autonomous software construction engine.
Apache-2.0. Prebuilt binaries for Linux / macOS / Windows are attached to each
[release](https://github.com/zecordev/zecor-secretscan/releases); or `cargo install zecor-secretscan`.

## 4. `zecor-secretscan` — secret and injection scanning

**Incumbents.** `gitleaks` (Go, the de-facto standard, ~150 rules, regex-only),
`trufflehog` (Go, adds *live credential verification* — its differentiator — but heavy),
`detect-secrets` (Python, entropy + plugins, Yelp), `ripsecrets` (Rust, fast, thin
rule set). GitHub's own scanning is cloud-only.

**Gaps.** `gitleaks` has no entropy tier and no SIMD; `trufflehog`'s verification is
slow and phones home; none of them are built to scan a *generated diff plus the PR text
about to be posted* in the same pass, and none look for *prompt-injection* payloads,
which is a real vector when the diff came from a model fed untrusted input.

**Shipped.** aho-corasick pre-filter → SIMD regex over ~22 credential shapes (AWS/GitHub/
GitLab/Slack/Google/GCP/OpenAI/Anthropic/HF/Stripe/Twilio/SendGrid/npm/PyPI/JWT/DB-URI/
PEM/…) + a Shannon-entropy tier, placeholder allow-list applied per-token, diff-aware
(added lines only, correct file/line), masked hints (never the secret). **Gitignore-aware
directory scan** (`path DIR`, `ignore`-crate semantics, Rayon across files, binary +
oversize skip). **Baseline** — line-independent FNV fingerprint per finding, `baseline
DIR` emits the accept-list, `--baseline FILE` suppresses; a new finding fails, a known one
does not. **SARIF 2.1.0** output (`--format sarif`) with `partialFingerprints`, plus
JSON and text. **Injection pack** (`--injection`) — "ignore previous instructions",
fenced `system:`/`assistant:` blocks, exfil phrasing, tool-use coercion. Mirrored in
`zecor.secretscan` (parity-tested) and exposed as `zecor scan [--dir] [--sarif]
[--injection]`.

**Still to world-class.**
- **Full `gitleaks` rule import.** Load a `gitleaks.toml` so anyone's ruleset works.
- **Verification hooks (opt-in, off by default).** A `--verify` mode that checks a
  candidate against the issuing service *only when explicitly enabled* — trufflehog's
  value without trufflehog's default-on network.
- **Structured entropy.** Per-context floors (a base64 blob in a test fixture vs. in
  `config.py`), and `--entropy N` tuning.
- **Zero-width / RTL-override / base64-payload** detection in the injection pack.
- **Pre-commit + pre-push hook installers.**

## Build

```
cargo build --release      # -> target/release/zecor-secretscan
cargo test --all-targets
```
