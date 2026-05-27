<h1 align="center">🔍 secretscan</h1>

<p align="center">
  <strong>A fast, local secret leak scanner for developer repositories</strong>
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
| 🏃 Pre-commit hook | Block commits containing secrets |
| 🤖 GitHub Actions | Ready-to-use CI workflow |

### Detected Secret Types

| Type | Example Pattern | Severity |
|------|----------------|----------|
| AWS Access Keys | `AKIA...` | Critical |
| AWS Secret Keys | Context-based detection | Critical |
| GitHub Tokens | `ghp_`, `github_pat_` | Critical |
| OpenAI API Keys | `sk-...`, `sk-proj-...` | High |
| Slack Tokens | `xoxb-`, `xoxp-` | High |
| Slack Webhooks | `hooks.slack.com/services/...` | High |
| Stripe Keys | `sk_live_`, `pk_live_` | Critical |
| Google/Firebase API Keys | `AIza...` | High |
| Private Keys (RSA/PEM) | `-----BEGIN PRIVATE KEY-----` | Critical |
| JWT Tokens | `eyJ...` embedded tokens | High |
| JWT Signing Secrets | `jwt_secret = "..."` | Critical |
| Hardcoded Passwords | `password = "..."` | High |
| Database Connection Strings | `postgresql://user:pass@...` | High |
| High-Entropy Strings | Context + entropy analysis | Medium |

## Installation

### From Source

```bash
# Clone the repository
git clone https://github.com/secretscan/secretscan.git
cd secretscan

# Build
go build -o secretscan ./cmd/secretscan

# Install globally
go install ./cmd/secretscan
```

### Verify Installation

```bash
secretscan version
# secretscan v1.0.0
```

## Quick Start

```bash
# Scan current directory
secretscan scan .

# Scan a specific project
secretscan scan /path/to/project

# Scan git history
secretscan git .

# Initialize config files in your project
secretscan init

# Output as JSON
secretscan scan . --output json

# Output as SARIF (for GitHub Code Scanning)
secretscan scan . --output sarif > results.sarif
```

## Usage

### Commands

#### `secretscan scan <path>`

Recursively scans a directory for secrets in text files.

```bash
secretscan scan .
secretscan scan ./src --output json
secretscan scan /project -o sarif -w 16 > report.sarif
```

#### `secretscan git <path>`

Scans Git commit history for secrets that were committed in the past.

```bash
secretscan git .
secretscan git ./my-repo --include-filesystem
secretscan git . --output json
```

Options:
- `--include-filesystem` — also scan current files alongside history

#### `secretscan init`

Creates default `.secretscan.yaml` and `.secretignore` files in the current directory.

```bash
secretscan init
```

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

### Exit Codes

| Code | Meaning |
|------|---------|
| `0` | No secrets found |
| `1` | Secrets detected |
| `2` | Invalid usage or configuration error |

This makes secretscan CI-friendly:

```bash
secretscan scan . || echo "Secrets found!"
```

## Configuration

### Config File (`.secretscan.yaml`)

```yaml
# Maximum file size to scan (bytes)
max_file_size: 10485760

# Concurrent scanning workers
max_workers: 8

# Output format: text, json, sarif
output_format: text

# Entropy threshold (0-8 scale)
entropy_threshold: 4.0

# Scan git history too
include_git_history: false

# Paths to exclude
exclude_paths:
  - .git
  - node_modules
  - dist
  - build
  - vendor

# Custom detection patterns
custom_patterns:
  - name: "Internal API Key"
    pattern: "MYCOMPANY_[A-Z0-9]{32}"
    severity: high
    keywords:
      - api_key
```

### Ignore File (`.secretignore`)

Uses `.gitignore` syntax:

```gitignore
# Ignore dependencies
node_modules/
vendor/

# Ignore build output
dist/
build/

# Ignore specific files
*.log
*.lock

# But scan this specific file
!important.env
```

## How It Works

### Architecture

```
┌─────────────────────────────────────────────────────────┐
│                     CLI (Cobra)                         │
│                scan | git | init | version               │
├─────────────┬────────────┬──────────────────────────────┤
│  Config     │  Ignore    │  Report Writer               │
│  (.yaml)    │  (.ignore) │  (text / json / sarif)       │
├─────────────┴────────────┴──────────────────────────────┤
│                Scanner Engine                           │
│          ┌─────────────┬──────────────┐                 │
│          │ File Scanner│ Git Scanner  │                 │
│          │ (workers)   │ (commits)    │                 │
│          └──────┬──────┴──────┬───────┘                 │
│                 └──────┬──────┘                         │
│              Detector Registry                          │
│   ┌────────┬────────┬────────┬────────┬──────────┐     │
│   │  AWS   │ GitHub │ Stripe │  JWT   │ Custom   │     │
│   │  Keys  │ Tokens │  Keys  │ Tokens │ Patterns │     │
│   └────────┴────────┴────────┴────────┴──────────┘     │
├─────────────────────────────────────────────────────────┤
│                 Entropy Engine                          │
│            Shannon entropy scoring                      │
└─────────────────────────────────────────────────────────┘
```

### Detection Strategy

secretscan uses **multi-signal analysis** instead of regex alone:

1. **Regex Match** — Pattern matches a known secret format (+30 confidence)
2. **Context Keywords** — Words like `key`, `secret`, `token` nearby (+20 confidence)
3. **Entropy Score** — High randomness suggests real secrets (+15–25 confidence)
4. **Type Validation** — Secret-specific checks like prefix/length (+25 confidence)

Each finding receives a **confidence score from 0 to 100**. Only findings above the threshold (25) are reported.

### False Positive Reduction

- Placeholder values (`example`, `your_`, `placeholder`, `changeme`) are filtered
- Low-entropy strings are deprioritized
- Ambiguous matches are scored as medium confidence, not critical
- Context keywords must be present for generic patterns
- Lock files and binary files are skipped by default

### Git History Scanning

When using `secretscan git`, the tool:

1. Opens the Git repository and iterates commits from HEAD
2. For each commit, computes the diff against its parent
3. Scans only **added lines** in diffs (not removed or unchanged)
4. Deduplicates findings — same secret in multiple commits is reported once
5. Includes commit hash, message, and author in findings

## Output Examples

### Terminal Output

```
🔍 secretscan results
   Path: ./my-project | Mode: filesystem | Duration: 234ms
   Files scanned: 156
──────────────────────────────────────────────────────────────

📊 Summary: 3 findings
   🔴 Critical: 1
   🟠 High: 1
   🟡 Medium: 1
──────────────────────────────────────────────────────────────

[1] 🔴 CRITICAL | AWS Access Key
    📁 config/.env:3:15
    🔎 Detector: aws-key | Confidence: 90% | Source: filesystem
    📝 Matched AWS Access Key pattern; context keyword 'key' found nearby
    💬 AWS_ACCESS_KEY_ID=AKIA****************MPLE

[2] 🟠 HIGH | Hardcoded Password
    📁 app/settings.py:42:12
    🔎 Detector: password | Confidence: 75% | Source: filesystem
    📝 Hardcoded password assignment detected
    💬 password = "s3cr3t_..."
```

### JSON Output

```json
{
  "findings": [
    {
      "type": "AWS Access Key",
      "severity": "critical",
      "confidence": 90,
      "file": "config/.env",
      "line": 3,
      "column": 15,
      "preview": "AWS_ACCESS_KEY_ID=AKIA...",
      "reason": "Matched AWS Access Key pattern",
      "detector": "aws-key",
      "source": "filesystem"
    }
  ],
  "scanned_files": 156,
  "duration": "234ms",
  "scan_path": "./my-project",
  "scan_mode": "filesystem"
}
```

### SARIF Output

SARIF output can be uploaded to GitHub Code Scanning:

```bash
secretscan scan . --output sarif > results.sarif
```

The SARIF output conforms to v2.1.0 and is compatible with:
- GitHub Code Scanning
- Azure DevOps
- VS Code SARIF Viewer

## CI/CD Integration

### GitHub Actions

Add the included workflow (`.github/workflows/secretscan.yml`):

```yaml
- name: Run secretscan
  run: ./secretscan scan . --output sarif > results.sarif

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

### Pre-commit Hook

```bash
# Install the pre-commit hook
cp scripts/pre-commit.sh .git/hooks/pre-commit
chmod +x .git/hooks/pre-commit
```

## Project Structure

```
secretscan/
├── cmd/secretscan/main.go         # Entry point
├── internal/
│   ├── cli/                        # CLI commands (Cobra)
│   │   ├── root.go                 # Root command and flags
│   │   ├── scan.go                 # Filesystem scan command
│   │   ├── git.go                  # Git history scan command
│   │   └── init.go                 # Init command
│   ├── config/                     # Configuration loading
│   ├── detectors/                  # Secret detection logic
│   │   ├── detectors.go            # Base detector + helpers
│   │   ├── registry.go             # Detector registry
│   │   ├── aws.go                  # AWS key detector
│   │   ├── github.go               # GitHub token detector
│   │   ├── apikeys.go              # OpenAI, Slack, Stripe
│   │   ├── secrets.go              # Private keys, JWT, passwords
│   │   └── custom.go               # Custom pattern detector
│   ├── entropy/                    # Shannon entropy scoring
│   ├── ignore/                     # .secretignore matcher
│   ├── models/                     # Core data structures
│   ├── report/                     # Output formatting
│   │   ├── report.go               # Text + JSON output
│   │   └── sarif.go                # SARIF output
│   ├── scanner/
│   │   ├── scanner.go              # Deduplication
│   │   ├── files/                  # Filesystem scanner
│   │   └── git/                    # Git history scanner
│   └── util/                       # Shared utilities
├── scripts/pre-commit.sh           # Pre-commit hook
├── .github/workflows/              # CI workflow
├── .secretscan.yaml                # Sample config
├── .secretignore                   # Sample ignore file
├── go.mod
├── LICENSE
└── README.md
```

## Limitations

- **No remote scanning** — secretscan only works on local repositories
- **No auto-remediation** — it reports findings but doesn't fix them
- **Large repos** — very large repositories with deep history may take time
- **Binary files** — binary content is skipped (by design)
- **Encrypted files** — cannot scan encrypted or encoded content
- **Custom formats** — proprietary secret formats need custom patterns
- **No API validation** — does not call APIs to verify if secrets are active

## Roadmap

- [ ] Incremental scanning (only changed files)
- [ ] Baseline file to suppress known findings
- [ ] IDE plugins (VS Code, JetBrains)
- [ ] Secret rotation recommendations
- [ ] Support for additional VCS (Mercurial, SVN)
- [ ] Web dashboard for scan results
- [ ] Multi-repo scanning
- [ ] SOCKS/proxy support for enterprise environments

## Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Run `go test ./...` and `go vet ./...`
5. Submit a pull request

## License

MIT License — see [LICENSE](LICENSE) for details.

---

<p align="center">
  <strong>Made with ❤️ for developer security</strong>
</p>
