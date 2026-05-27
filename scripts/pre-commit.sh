#!/bin/sh
# secretscan pre-commit hook
# Add this to .git/hooks/pre-commit or use with a pre-commit framework
#
# Installation:
#   cp scripts/pre-commit.sh .git/hooks/pre-commit
#   chmod +x .git/hooks/pre-commit
#
# Or with the pre-commit framework (https://pre-commit.com):
#   Add to .pre-commit-config.yaml:
#
#   repos:
#     - repo: local
#       hooks:
#         - id: secretscan
#           name: secretscan
#           entry: secretscan scan
#           language: system
#           types: [file]
#           pass_filenames: false

set -e

echo "🔍 Running secretscan pre-commit check..."

# Check if secretscan is installed.
if ! command -v secretscan >/dev/null 2>&1; then
    echo "⚠️  secretscan is not installed. Skipping secret scan."
    echo "   Install: go install github.com/secretscan/secretscan/cmd/secretscan@latest"
    exit 0
fi

# Get the list of staged files.
STAGED_FILES=$(git diff --cached --name-only --diff-filter=ACM)

if [ -z "$STAGED_FILES" ]; then
    exit 0
fi

# Create a temporary directory with staged file contents.
TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT

for file in $STAGED_FILES; do
    # Create directory structure.
    mkdir -p "$TMPDIR/$(dirname "$file")"
    # Copy staged version.
    git show ":$file" > "$TMPDIR/$file" 2>/dev/null || true
done

# Run secretscan on staged files.
secretscan scan "$TMPDIR" --output text

EXIT_CODE=$?

if [ $EXIT_CODE -eq 1 ]; then
    echo ""
    echo "❌ Secrets detected in staged files!"
    echo "   Please remove them before committing."
    echo ""
    echo "   To bypass this check (NOT recommended):"
    echo "   git commit --no-verify"
    exit 1
fi

if [ $EXIT_CODE -eq 2 ]; then
    echo "⚠️  secretscan encountered an error."
    exit 0  # Don't block commits on tool errors
fi

echo "✅ No secrets detected."
exit 0
