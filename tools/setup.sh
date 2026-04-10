#!/usr/bin/env bash
# setup.sh — Glasswing developer environment setup (macOS)
# Installs tools needed for memory safety research

set -e

echo "=== Glasswing Dev Environment Setup ==="

# 1. Homebrew check
if ! command -v brew &>/dev/null; then
  echo "Homebrew not found. Install from https://brew.sh first."
  exit 1
fi

# 2. Core tools
echo "[1/4] Installing core tools..."
brew install llvm          # clang with ASan/UBSan
brew install coreutils
brew install cmake

# 3. Static analysis
echo "[2/4] Installing static analysis tools..."
brew install cppcheck      # C/C++ static analyzer
brew install semgrep       # pattern-based code scanner

# 4. Fuzzing
echo "[3/4] Installing fuzzing tools..."
brew install afl-fuzz      # AFL++ coverage-guided fuzzer

# 5. FFmpeg (for reference — current patched version)
echo "[4/4] Installing FFmpeg..."
brew install ffmpeg

echo ""
echo "=== Setup complete ==="
echo ""
echo "Quick start:"
echo "  cd tools/"
echo "  clang -fsanitize=address -g -o vulnerable_decoder vulnerable_decoder.c"
echo "  ./vulnerable_decoder 10 10 5       # safe"
echo "  ./vulnerable_decoder 10 10 999     # triggers ASan OOB"
echo ""
echo "  clang -fsanitize=address -g -o fixed_decoder fixed_decoder.c"
echo "  ./fixed_decoder 10 10 999          # gracefully rejected"
