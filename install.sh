#!/usr/bin/env bash
# SNAPESCAPE One-Click Install (Linux/Mac)
set -e
cd "$(dirname "$0")"

echo ""
echo "   SNAPESCAPE INSTALLER"
echo "   Created By: Pr0Fessor_SnApe"
echo ""

PY=python3
command -v python3 >/dev/null || PY=python

$PY snapescape.py install

read -p "Start SNAPESCAPE now? [Y/n] " ans
if [[ "$ans" != "n" && "$ans" != "N" ]]; then
  $PY snapescape.py start --open
fi

echo ""
echo "  Commands:"
echo "    python3 snapescape.py start"
echo "    python3 snapescape.py hunt example.com"
echo ""
