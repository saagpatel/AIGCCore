#!/usr/bin/env bash
# Behavioral contract tests for the macOS release scripts. The task directory
# is intentionally retained so failures remain inspectable.
set -euo pipefail

if [[ "$(uname -s)" != "Darwin" ]]; then
  echo "SKIP: macOS release-script tests require Darwin"
  exit 0
fi

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TEST_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/aigc-release-script-test.XXXXXX")"
FIXTURE_APP="$TEST_ROOT/Fixture Release.app"
FIXTURE_DMG="$TEST_ROOT/Fixture_Release_1.0.0_aarch64.dmg"

mkdir -p "$FIXTURE_APP/Contents/MacOS"
cp /usr/bin/true "$FIXTURE_APP/Contents/MacOS/fixture-release"
plutil -create xml1 "$FIXTURE_APP/Contents/Info.plist"
plutil -insert CFBundleExecutable -string fixture-release "$FIXTURE_APP/Contents/Info.plist"
plutil -insert CFBundleIdentifier -string dev.aigccore.release-script-fixture "$FIXTURE_APP/Contents/Info.plist"
plutil -insert CFBundleName -string 'Fixture Release' "$FIXTURE_APP/Contents/Info.plist"
plutil -insert CFBundlePackageType -string APPL "$FIXTURE_APP/Contents/Info.plist"
plutil -insert CFBundleShortVersionString -string 1.0.0 "$FIXTURE_APP/Contents/Info.plist"
codesign --force --sign - "$FIXTURE_APP/Contents/MacOS/fixture-release"
codesign --force --sign - "$FIXTURE_APP"

MACOS_SIGNING_IDENTITY=- REQUIRE_MACOS_NOTARIZATION=0 \
  "$REPO_ROOT/scripts/package-macos-dmg.sh" "$FIXTURE_APP" "$FIXTURE_DMG"
[[ -f "$FIXTURE_DMG" ]]
codesign --verify --deep --strict --verbose=2 "$FIXTURE_DMG"
hdiutil verify "$FIXTURE_DMG"

set +e
guard_output="$(
  env -u APPLE_API_KEY -u APPLE_API_ISSUER -u APPLE_API_KEY_PATH \
    -u APPLE_ID -u APPLE_PASSWORD -u APPLE_TEAM_ID \
    "$REPO_ROOT/scripts/release-macos.sh" --bundles dmg 2>&1
)"
guard_status=$?
set -e
[[ $guard_status -eq 2 ]]
[[ "$guard_output" == *"owns bundle selection"* ]]

set +e
credential_output="$(
  env -u APPLE_API_KEY -u APPLE_API_ISSUER -u APPLE_API_KEY_PATH \
    -u APPLE_ID -u APPLE_PASSWORD -u APPLE_TEAM_ID \
    "$REPO_ROOT/scripts/release-macos.sh" 2>&1
)"
credential_status=$?
set -e
[[ $credential_status -eq 1 ]]
[[ "$credential_output" == *"configure complete notarization credentials"* ]]

set +e
arity_output="$("$REPO_ROOT/scripts/package-macos-dmg.sh" 2>&1)"
arity_status=$?
set -e
[[ $arity_status -eq 2 ]]
[[ "$arity_output" == usage:* ]]

echo "PASS: macOS packaging and fail-closed release preflights"
echo "retained_test_root=$TEST_ROOT"
