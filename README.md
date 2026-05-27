<h1 align="center">🔍 secretscan</h1>

<p align="center">
  <strong>A fast, production-grade local secret leak scanner for developer repositories</strong>
</p>

<p align="center">
  <a href="#features">Features</a> •
  <a href="#installation">Installation</a> •
  <a href="#quick-start">Quick Start</a> •
  <a href="#usage">Usage</a> •
  <a href="#configuration">Configuration</a> •
  <a href="#how-it-works">How It Works</a> •
  <a href="#contributing">Contributing</a>
</p>

---

## What is secretscan?

**secretscan** is a defensive security tool that scans your local codebases and Git history for accidentally committed secrets — API keys, tokens, private keys, passwords, and other credentials that should never be in source code.

Unlike cloud-based scanners, secretscan runs **entirely locally** — your code never leaves your machine.

### Why secretscan?

- 🔒 **100% local** — no data leaves your machine
- 🎯 **Low false positives** — multi-signal detection (regex + context + entropy + validation)
- ⚡ **Fast** — concurrent scanning with worker pools
- 📜 **Git history** — finds secrets in old commits, even if deleted
- 🔌 **Pluggable** — add custom patterns via config
- 🏗️ **CI-ready** — JSON/SARIF output, exit codes, GitHub Actions support
- ✅ **Live validation** — optionally probe secrets to check if they're still active
- 📋 **Baseline suppression** — suppress known findings, only alert on new ones
- ⏱️ **Incremental scanning** — scan only changed files with `--since`
- 🔓 **Obfuscation detection** — decode base64/hex/URL-encoded secrets

## Features

| Feature | Description |
|---------|-------------|
| 🗂️ Recursive file scan | Scans all text files in a directory tree |
| 📜 Git history scan | Scans commits and diffs for past secrets |
| 🎯 Multi-signal detection | Regex + context keywords + entropy + validation |
| 📊 Confidence scoring | 0–100 score per finding to reduce noise |
| 🚫 Ignore rules | `.secretignore` with glob patterns and negation |
| 📋 Multiple output formats | Terminal (pretty), JSON, SARIF |
| ⚙️ Config file | `.secretscan.yaml` for project-specific settings |
| 🔌 Custom patterns | Add your own regex detectors via config |
| ✅ Live validation | `--validate` probes AWS, GitHub, Stripe endpoints |
| 📋 Baseline suppression | `--update-baseline` / auto-load baseline |
| ⏱️ Incremental scan | `--since main` scans only changed files |
| 🔓 Obfuscation decode | Auto-decodes base64, hex, URL-encoded secrets |
| 🏃 Pre-commit hook | Block commits containing secrets |
| 🤖 GitHub Actions | Ready-to-use CI workflow + GoReleaser |

### Detected Secret Types (25+ detectors)

| Type | Detector | Severity |
|------|----------|----------|
| AWS Access Keys | `aws-key` | Critical |
| AWS Secret Keys | `aws-key` | Critical |
| GitHub Tokens | `github-token` | Critical |
| OpenAI API Keys | `openai-key` | High |
| Slack Tokens | `slack-token` | High |
| Slack Webhooks | `slack-token` | High |
| Stripe Keys | `stripe-key` | Critical |
| Google/Firebase API Keys | `firebase` | High |
| Private Keys (RSA/PEM) | `private-key` | Critical |
| JWT Tokens | `jwt` | High |
| JWT Signing Secrets | `jwt` | Critical |
| Hardcoded Passwords | `password` | High |
| Database Connection Strings | `connection-string` | High |
| Azure SAS Tokens | `azure-sas` | High |
| Azure Connection Strings | `azure-connection` | Critical |
| GCP API Keys | `gcp-api-key` | High |
| GCP Service Account Keys | `gcp-service-account` | Critical |
| Twilio Account SIDs | `twilio-sid` | High |
| Twilio Auth Tokens | `twilio-auth` | High |
| SendGrid API Keys | `sendgrid` | High |
| Mailgun API Keys | `mailgun` | High |
| npm Tokens | `npm-token` | High |
| PyPI API Tokens | `pypi-token` | High |
| Docker Hub Tokens | `dockerhub-token` | High |
| Cloudflare API Tokens | `cloudflare-token` | High |
| HashiCorp Vault Tokens | `vault-token` | Critical |
| High-Entropy Strings | `high-entropy` | Medium |

## Installation

### Quick Install (Linux/macOS)

```bash
curl -sSfL https://raw.githubusercontent.com/Nciibi/secretscan/main/scripts/install.sh | sh
```

### From Source

```bash
git clone https://github.com/Nciibi/secretscan.git
cd secretscan
go build -o secretscan ./cmd/secretscan
go install ./cmd/secretscan
```

### From Releases

Download the latest binary for your platform from
[GitHub Releases](https://github.com/Nciibi/secretscan/releases).

### Verify Installation

```bash
secretscan version
# secretscan v2.0.0
```

## Quick Start

```bash
# Scan current directory
secretscan scan .

# Scan with live secret validation
secretscan scan . --validate

# Scan only files changed since main branch
secretscan scan . --since main

# Scan git history
secretscan git .

# Initialize config files
secretscan init

# Output as JSON
secretscan scan . --output json

# Output as SARIF (for GitHub Code Scanning)
secretscan scan . --output sarif > results.sarif

# Save baseline (suppress known findings)
secretscan scan . --update-baseline

# Subsequent scans auto-suppress baselined findings
secretscan scan .
```

## Usage

### Commands

#### `secretscan scan <path>`

Recursively scans a directory for secrets in text files.

```bash
secretscan scan .
secretscan scan ./src --output json
secretscan scan . --validate --since HEAD~5
secretscan scan . --update-baseline
secretscan scan /project -o sarif > report.sarif
```

Flags specific to `scan`:
| Flag | Description |
|------|-------------|
| `--since <ref>` | Scan only files changed since the given git ref |
| `--update-baseline` | Write current findings to `.secretscan-baseline.json` |
| `--no-baseline` | Ignore existing baseline file |

#### `secretscan git <path>`

Scans Git commit history for past secrets.

```bash
secretscan git .
secretscan git ./my-repo --include-filesystem
secretscan git . --validate --output json
```

#### `secretscan init`

Creates default `.secretscan.yaml` and `.secretignore` files.

#### `secretscan version`

Prints the current version.

### Global Flags

| Flag | Short | Description | Default |
|------|-------|-------------|---------|
| `--output` | `-o` | Output format (text/json/sarif) | `text` |
| `--config` | `-c` | Path to config file | `.secretscan.yaml` |
| `--ignore-file` | | Path to ignore file | `.secretignore` |
| `--workers` | `-w` | Number of concurrent workers | `8` |
| `--verbose` | `-v` | Enable verbose output | `false` |
| `--max-size` | | Maximum file size (bytes) | `10485760` |
| `--entropy` | | Entropy threshold | `4.0` |
| `--validate` | `-V` | Probe detected secrets for liveness | `false` |
| `--no-decode` | | Disable base64/hex/URL decode pass | `false` |

### Exit Codes

| Code | Meaning |
|------|---------|
| `0` | No secrets found |
| `1` | Secrets detected |
| `2` | Invalid usage or configuration error |

## Live Validation (`--validate`)

When `--validate` / `-V` is passed, secretscan makes lightweight API probes to check if detected secrets are still active:

| Detector | Probe Endpoint | Active Signal |
|----------|---------------|---------------|
| AWS Keys | `POST sts.amazonaws.com/?Action=GetCallerIdentity` | 200 = active |
| GitHub Tokens | `GET api.github.com` with auth header | X-RateLimit header present |
| Stripe Keys | `GET api.stripe.com/v1/balance` with bearer | 200 = active |
| All others | — | Marked as "unvalidated" |

Terminal output shows: 🟢 active, 🔴 inactive, ⚪ unvalidated

**Validation is OFF by default.** Only runs when explicitly requested.

## Baseline Suppression

Teams can snapshot current findings and only alert on NEW secrets:

```bash
# Save current findings as baseline
secretscan scan . --update-baseline

# Later scans auto-suppress baselined findings
secretscan scan .
# Output: "ℹ️  5 findings suppressed by baseline"

# See all findings (ignore baseline)
secretscan scan . --no-baseline
```

Baseline file format (`.secretscan-baseline.json`):
```json
{
  "version": 1,
  "generated_at": "2024-01-15T10:30:00Z",
  "findings": [
    {
      "fingerprint": "sha256...",
      "detector": "aws-key",
      "file": "config/.env",
      "line": 3
    }
  ]
}
```

## Incremental Scanning (`--since`)

Scan only files changed since a git ref — makes pre-commit hooks fast on large repos:

```bash
secretscan scan . --since HEAD        # changed vs HEAD (staged changes)
secretscan scan . --since main        # changed vs main branch
secretscan scan . --since abc1234     # changed since commit
```

Falls back to full scan with a warning if the ref cannot be resolved.

## Obfuscation Detection

secretscan automatically attempts to decode obfuscated content before scanning:

1. **Base64** — decodes `[A-Za-z0-9+/=]{20,}` strings
2. **Hex** — decodes `[0-9a-fA-F]{32,}` strings
3. **URL encoding** — runs `url.QueryUnescape` on lines with `%`

If a secret is found in decoded content, the output shows:
```
💬 AWS_KEY=AKIA... (detected via base64 decode)
```

Disable with `--no-decode`.

## Configuration

### Config File (`.secretscan.yaml`)

```yaml
max_file_size: 10485760
max_workers: 8
output_format: text
entropy_threshold: 4.0
include_git_history: false
exclude_paths:
  - .git
  - node_modules
  - dist

custom_patterns:
  - name: "Internal API Key"
    pattern: "MYCOMPANY_[A-Z0-9]{32}"
    severity: high
    keywords:
      - api_key
```

### Ignore File (`.secretignore`)

Uses `.gitignore` syntax with negation support:

```gitignore
node_modules/
*.log
!important.env
```

## How It Works

### Architecture

```
┌─────────────────────────────────────────────────────────┐
│                     CLI (Cobra)                         │
│          scan | git | init | version                    │
│  --validate  --since  --update-baseline  --no-decode    │
├──────────┬───────────┬──────────────────────────────────┤
│ Config   │ Ignore    │ Report Writer                    │
│ (.yaml)  │ (.ignore) │ (text / json / sarif)            │
├──────────┼───────────┼──────────────────────────────────┤
│ Baseline │ Validator │ Decoder                          │
│ (.json)  │ (HTTP)    │ (b64/hex/url)                    │
├──────────┴───────────┴──────────────────────────────────┤
│                Scanner Engine                           │
│        ┌─────────────┬──────────────┐                   │
│        │ File Scanner│ Git Scanner  │                   │
│        │ (workers)   │ (commits)    │                   │
│        └──────┬──────┴──────┬───────┘                   │
│               └──────┬──────┘                           │
│            Detector Registry (25+)                      │
│  ┌──────┬────────┬───────┬───────┬──────┬────────┐     │
│  │ AWS  │ GitHub │ Azure │ GCP   │Twilio│ Custom │     │
│  │ Keys │ Tokens │ SAS   │ SA    │ SID  │Patterns│     │
│  └──────┴────────┴───────┴───────┴──────┴────────┘     │
├─────────────────────────────────────────────────────────┤
│                 Entropy Engine                          │
│            Shannon entropy scoring                      │
└─────────────────────────────────────────────────────────┘
```

### Detection Strategy

Multi-signal analysis instead of regex alone:

1. **Regex Match** (+30 confidence)
2. **Context Keywords** (`key`, `secret`, `token` nearby) (+20)
3. **Entropy Score** (high randomness) (+15–25)
4. **Type Validation** (prefix/length checks) (+25)

Each finding scores 0–100. Only findings above threshold (25) are reported.

### Precision/Recall Benchmark

Run the built-in benchmark tool:
```bash
go run ./cmd/benchmark
```

Output:
```
Detector         TP   FP   FN   Precision  Recall
aws-key           3    0    0   100.0%     100.0%
github-token      2    0    0   100.0%     100.0%
stripe-key        2    0    0   100.0%     100.0%
...
```

## CI/CD Integration

### GitHub Actions

The repo includes two workflows:
- `.github/workflows/secretscan.yml` — runs on push/PR with SARIF upload
- `.github/workflows/release.yml` — builds cross-platform binaries via GoReleaser

### Pre-commit Hook

```bash
cp scripts/pre-commit.sh .git/hooks/pre-commit
chmod +x .git/hooks/pre-commit
```

## Project Structure

```
secretscan/
├── cmd/
│   ├── secretscan/main.go         # CLI entry point
│   └── benchmark/main.go          # Precision/recall benchmark tool
├── internal/
│   ├── cli/                        # Cobra CLI commands
│   ├── config/                     # YAML configuration
│   ├── baseline/                   # Baseline suppression system
│   ├── validate/                   # Live secret validation probes
│   ├── detectors/                  # 25+ secret detectors
│   │   ├── aws.go, github.go       # Original detectors
│   │   ├── cloud.go                # Azure, GCP detectors
│   │   ├── comms.go                # Twilio, SendGrid, Mailgun
│   │   ├── infra.go                # npm, PyPI, Docker, Vault
│   │   ├── custom.go               # User-defined patterns
│   │   └── testdata/               # Benchmark corpus
│   ├── entropy/                    # Shannon entropy scoring
│   ├── ignore/                     # .secretignore matcher
│   ├── models/                     # Core data structures
│   ├── report/                     # Output (text/json/sarif)
│   ├── scanner/files/              # Filesystem scanner
│   ├── scanner/git/                # Git history scanner
│   └── util/                       # Utilities + decode.go
├── scripts/
│   ├── install.sh                  # curl-pipe-sh installer
│   └── pre-commit.sh               # Git pre-commit hook
├── .github/workflows/
│   ├── secretscan.yml              # CI scan workflow
│   └── release.yml                 # GoReleaser workflow
├── .goreleaser.yaml                # Cross-platform build config
├── .secretscan.yaml                # Sample config
├── .secretignore                   # Sample ignore file
└── README.md
```

## Limitations

- **No remote scanning** — local repositories only
- **No auto-remediation** — reports but doesn't fix
- **Large repos** — deep history scanning may be slow
- **Binary files** — skipped by design
- **Encrypted files** — cannot scan encrypted content
- **Validation coverage** — only AWS/GitHub/Stripe support live probes

## Roadmap

- [ ] IDE plugins (VS Code, JetBrains)
- [ ] Secret rotation recommendations
- [ ] Web dashboard for scan results
- [ ] Multi-repo scanning
- [ ] Additional validation endpoints (Slack, Azure, GCP)

## Contributing

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Run `go test ./...` and `go vet ./...`
5. Run `go run ./cmd/benchmark` to verify precision/recall
6. Submit a pull request

## License

MIT License — see [LICENSE](LICENSE) for details.

---

<p align="center">
  <strong>Made with ❤️ for developer security , stay safe guys !</strong>
</p>
