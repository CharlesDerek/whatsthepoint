# Signed distribution

Policy signing, release signing, and extension signing use separate keys and
signature domains. Keep all private keys outside the repository. A locally generated
key demonstrates cryptographic integrity; it is not an OS-trusted publisher identity.

## Release archives

Generate a release-specific Ed25519 key on the signing machine with
`wtp-agent keygen --output /secure/release.key`. Distribute the printed public key
through an authenticated channel independent of the downloadable archive. The portal's
policy key is stored separately and must not be used as the release key.

```sh
wtp-agent sign-file --key /secure/release.key --file release.zip --output release.zip.sig.json
python3 scripts/release/verify-artifact.py --public-key PINNED_PUBLIC_KEY --file release.zip --signature release.zip.sig.json
```

The independent verifier uses a trusted Python 3.11+ installation and OpenSSL 3.
It validates the Ed25519 signature, domain, exact filename, size, and SHA-256 digest
without executing the downloaded program. Use a trusted copy of the verifier;
a verifier downloaded alongside an untrusted artifact is not a trust anchor. Obtain
the initial verifier from reviewed/pinned source. Public-key rotation requires an
authenticated distribution process; a key bundled in an archive cannot authenticate
that same archive by itself.

`.github/workflows/signed-release.yml` runs manually on dedicated self-hosted signing
runners labeled `wtp-signing` for Linux, Windows, and macOS. Configure its `release`
environment, `WTP_RELEASE_PRIVATE_KEY` secret, and independently pinned
`WTP_RELEASE_PUBLIC_KEY` variable. The workflow builds/tests the workspace, invokes
native signing, creates an archive, verifies its detached signature independently,
and uploads build artifacts. It does not publish a release or activate an endpoint.
The normal `.github/workflows/release.yml` produces **unsigned development archives**.

For Windows, install a production code-signing certificate/private key in the
signing account's certificate store and set `WTP_WINDOWS_THUMBPRINT`. The signing
script uses the Windows SDK's SignTool with SHA-256 and an RFC 3161 timestamp, then
verifies the chain and exact publisher. See
[Microsoft SignTool](https://learn.microsoft.com/en-us/windows/win32/seccrypto/signtool).

For macOS, install Developer ID Application and Developer ID Installer identities
in the signing keychain. Set `WTP_APP_IDENTITY`, `WTP_INSTALLER_IDENTITY`, and
`WTP_NOTARY_PROFILE` to an existing `notarytool` keychain profile. The script signs
all three binaries with hardened runtime/timestamp, creates a signed package,
submits it to Apple, staples the ticket, and assesses it. No firewall activation
runs during package installation. See
[Apple's notarization workflow](https://developer.apple.com/documentation/security/customizing-the-notarization-workflow).

Production signing/notarization was not run in this Linux workspace: no publisher
certificates or Apple credentials were supplied. The scripts intentionally fail
when those prerequisites are missing.

## Browser extension

Keep one stable RSA PEM developer key for extension updates. Use a trusted Chromium
binary to package/sign the extension and generate its ID and HTTPS update manifest:

```sh
python3 scripts/release/package-extension.py --chrome /absolute/chromium --key /secure/extension.pem --base-url https://updates.example.org/wtp --output /absolute/empty-output-directory
python3 scripts/release/verify-crx.py --id PINNED_EXTENSION_ID /absolute/empty-output-directory/extension.crx
```

Packaging uses a disposable browser profile and source copy, excluding generated
metadata and private keys. Its signing-only Chromium process uses `--no-sandbox`
and loads no external page; run it on a trusted build machine. It verifies the
resulting CRX3 developer signature and emits `extension.crx`, `updates.xml`,
`extension-id.txt`, and a source ZIP for store submission. The source ZIP is not a
signed installed extension. Changing the private key changes the extension ID.
The verifier checks the pinned developer proof, not a Chrome Web Store publisher
proof; it rejects corrupted archive bytes and incorrect extension IDs.

Publishing is separate. Host the CRX and update manifest over HTTPS, or submit to the
browser store and use that store's extension ID/update URL. Adapt the supplied
managed policy template and system native-host registration to the installed ID.
Off-store installation eligibility varies by OS and enterprise management; producing
a valid CRX does not bypass Chrome/Edge distribution policies. See
[Chrome packaging/distribution](https://developer.chrome.com/docs/extensions/how-to/distribute/host-on-linux)
and [enterprise extension settings](https://support.google.com/chrome/a/answer/9867568).
The format verifier follows Chromium's
[CRX3 schema](https://chromium.googlesource.com/chromium/src/+/main/components/crx_file/crx3.proto)
and [signature verifier](https://raw.githubusercontent.com/chromium/chromium/main/components/crx_file/crx_verifier.cc).

Disposable-key packaging, independent signature validation, and corruption rejection
were executed locally. No production store publication or extension update feed was
published. Increment the extension version for updates and test the stable-ID update
path on managed endpoints before distribution.
