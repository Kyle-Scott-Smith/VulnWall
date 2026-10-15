#!/bin/sh
# One-time setup for src/__tests__/appHelpers.test.js and profilePrefs.test.js.
#
# Those tests exercise small pure helpers in src/App.jsx that were previously
# module-private. This prepends `export ` to their declarations so the tests
# can import them. It changes no behaviour, is safe to run twice, and the
# nine names are listed explicitly so nothing else is touched.
#
# Run from the frontend/ directory:   sh scripts/export-test-helpers.sh
set -e
FILE="${1:-src/App.jsx}"
sed -i.bak -E 's/^function (navTabsForRole|passwordError|optionLabel|toggleMulti|matchesSearch|sortRows|loadProfilePrefs|saveProfilePrefs|_fmtDate)\(/export function \1(/' "$FILE"
rm -f "$FILE.bak"
for name in navTabsForRole passwordError optionLabel toggleMulti matchesSearch sortRows loadProfilePrefs saveProfilePrefs _fmtDate; do
  grep -q "^export function $name(" "$FILE" || { echo "!! $name is not exported from $FILE" >&2; exit 1; }
done
echo "OK: 9 helpers exported from $FILE"
