#!/usr/bin/env bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

source venv/bin/activate

rm -rf build dist

pyinstaller --clean --onefile app_manager.py

mkdir -p dist/data dist/www
cp -R data/. dist/data/
cp -R www/. dist/www/