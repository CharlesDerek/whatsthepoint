#!/bin/sh
set -eu
# Identities must already be installed in the signing keychain; credentials never enter the repo.
: "${WTP_APP_IDENTITY:?Developer ID Application identity required}"
: "${WTP_INSTALLER_IDENTITY:?Developer ID Installer identity required}"
: "${WTP_NOTARY_PROFILE:?notarytool keychain profile required}"
[ "$#" -eq 2 ] || { echo 'Usage: sign-macos.sh binary-directory output.pkg' >&2; exit 2; }
for name in wtp wtp-native wtp-agent; do
    codesign --force --options runtime --timestamp --sign "$WTP_APP_IDENTITY" "$1/$name"
    codesign --verify --strict --verbose=2 "$1/$name"
done
# No postinstall activation: networking changes require explicit endpoint enrollment.
pkgbuild --root "$1" --identifier org.whatsthepoint.binaries --version 0.2.0 --install-location /usr/local/libexec/wtp --sign "$WTP_INSTALLER_IDENTITY" "$2"
xcrun notarytool submit "$2" --keychain-profile "$WTP_NOTARY_PROFILE" --wait
xcrun stapler staple "$2"
xcrun stapler validate "$2"
spctl --assess --type install --verbose=2 "$2"
