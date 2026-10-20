# Portal-managed browser protection

WTP now combines the DNS resolver with a Manifest V3 extension and a native OS
identity companion. Chrome, Chromium, and Edge use the same extension on Linux,
Windows, and macOS. Firefox and Safari packages are not included. The browser
integration is new software; category matching is deterministic and explainable,
not a trained classifier, reputation service, antivirus engine, or claim of
state-of-the-art threat detection.

## Enroll a desktop account

1. Build with `cargo build --release --locked`, initialize WTP if necessary, and
   run `wtp serve` as described in the README. Existing databases migrate at startup;
   back up the data directory before upgrading. The new executable also builds as
   `target/release/wtp-native` (`wtp-native.exe` on Windows).
2. In **Browser protection → Enroll a profile**, enter a display name and a group
   such as `Students`. Use one enrollment per desktop OS account. To bind the
   profile to the OS login, run `wtp-native --identity` on that desktop, enter the
   returned OS and `account_id`, and select **Native desktop identity required**.
   Unix uses the UID; Windows uses the account SID. A Chrome/Google account is not
   substituted for the OS login. The native helper runs as the browser user.
3. Copy the profile token while the portal displays it. Only its SHA-256 hash is
   retained by the server. Complete this step before installing the extension,
   which blocks navigation until configured. Browser administrators can use a
   separate management browser to avoid locking themselves out.
4. For a development installation, open `chrome://extensions` or
   `edge://extensions`, enable developer mode, and load the **extension/** folder.
   Open the extension's settings and enter the portal origin and profile token.
   HTTPS is required except for loopback development. The portal does not require
   an administrator cookie in the extension.
5. For native identity, register the helper with the installed extension ID:

   ```sh
   python3 deploy/browser/install-native.py --binary /absolute/path/wtp-native --extension-id YOUR_EXTENSION_ID --browser chrome
   ```

   On Windows use `python` and the absolute `.exe` path. The same script supports
   `--browser edge` or `--browser chromium`. `--dry-run` prints the manifest and
   destination without writing. `--uninstall` removes that registration. Moving
   the executable requires registering its new path. The helper exposes only the
   OS identity operation, with bounded native-message frames; it cannot run commands
   supplied by web pages. The extension settings display the resulting identity.
6. Visit a test URL. The portal's **Test a page** previews policy without fetching
   a website, and **Browser decisions** shows actual checks. Test previews assume
   the selected account identity matches. Use **Edit** to reassign a group or
   identity, **Revoke** to disable a credential, and **New token** to invalidate the
   old token and reactivate enrollment with a replacement.

Unpacked extensions and user-level native registration are development deployment,
not tamper-resistant installation. Do not use an administrator's browser session
as the enrollment credential.

## Ordered rules and categories

The policy order is:

1. A revoked/missing credential or required OS identity mismatch stops access.
2. Existing DNS domain rules and blocklists are a global baseline; a DNS block
   cannot be undone by a browser allow. DNS continues to have its own documented
   allow/block precedence.
3. Organization browser rules run before group rules, which run before profile
   rules. Within each scope, lower priority numbers run first; equal priorities
   use the rule ID in ascending order. **The first matching rule wins.** A broad
   organization allow therefore ends evaluation before narrower group rules.
4. If nothing matches, the organization default is allow, block, or sanitized reader.

Rules match a domain and its descendants, an origin and URL path subtree, a page
category, or every page. `https://example.com/private` matches `/private` and
`/private/report`, but not `/privateish`, another scheme, port, or host. Path
matching is case sensitive and compares decoded characters. Ambiguous encoded
separators, nested percent encodings, malformed escapes, and control characters
pause navigation rather than guessing how a server will decode them. URL fragments
are discarded; query parameters are not matchers. Common tracking parameters are
removed; application parameters are retained. Stripping trackers can invalidate
some signed links, so test the sites your deployment depends on.

Categories can use administrator-supplied domains and distinct whole-word phrases.
The phrase threshold is the number of different phrases required, not repetitions.
Domain evidence is sufficient on its own. The included adult, gambling, and social
categories are small examples to configure, not comprehensive coverage. Pages with
no category evidence get `unclassified`; a rule can send them to the reader or
block them. Category evidence may block or sanitize; it cannot grant access.
Use explicit URL/domain rules for exceptions. Rule changes are versioned, and a
stale portal editor gets a conflict instead of overwriting another administrator.

## Navigation and content inspection

The browser's declarative network rules send HTTP(S) **top-level GET navigation**
to an extension check page before requesting the destination. Address-bar entries,
ordinary clicks, new tabs, and HTTP redirects go through this gate. A successful
check grants a single exact URL in one tab, then removes the permit when navigation
commits. Permits also expire during the 30-second maintenance sweep. There is no
whole-tab or whole-domain allow window. An unreachable portal, bad response, revoked
token, or missing required identity leaves navigation paused.

For ordinary allowed pages, a content script classifies the title, description, and
up to 32,000 characters of visible text after DOM loading. It rechecks on mutations
and every 30 seconds for open tabs. Content already downloaded may have executed
before a content-based block: **post-load classification is not pre-execution
malware isolation**. Images, video, canvas content, obfuscated text, closed shadow
DOM, arbitrary subresources, downloads, and browser-internal pages are not deeply
inspected. Native messaging reports an account; it does not attest an uncompromised
machine. A modified browser or OS owner can falsify client evidence.

Top-level non-GET navigation is blocked, as are nested frames and plugin objects.
Some form submissions, SSO flows, embedded video, and other sites will consequently
need a different deployment approach. AJAX requests and subresources on an allowed
page are not individually sent to this portal policy engine. File/data/blob pages,
other browsers, other applications, and incognito are outside this extension's
coverage; incognito must be disabled by management for an enforced deployment.

## Sanitized reader

A `sanitize` decision fetches one HTML document from the extension without cookies,
a referrer, or portal credentials. Redirects, non-HTML responses, responses over
1 MB, and timeouts are rejected. The page is parsed in an extension document whose
CSP prohibits network resources. Only text nodes and newly constructed HTTP(S)
links reach the live reader. Scripts, styling, forms, images, SVG, frames, and
embedded media are excluded. Links return through the navigation check.

Reader text is categorized before display; a category block prevents rendering.
The result is a restricted reading view, not a cleaned interactive application,
a guarantee that factual content is safe, or a way to browse authenticated sites.

## Administrator-managed deployments

The implementation supports Chrome's read-only `storage.managed` values `portal`,
`token`, and `requireNative`. When a managed portal is present, local enrollment
cannot override any of these settings. Use settings appropriate to **one OS account**;
never distribute one shared profile token to every user in an organization.
On machines with several OS accounts, distribute account-specific policy via your
management system. A Linux machine policy containing one native-bound token will
only authorize the corresponding UID; it does not automatically enroll other users.

[deploy/browser/chrome-policy.example.json](../deploy/browser/chrome-policy.example.json)
is a template for an administrator to adapt and test. It forces installation,
blocks other extensions, disables incognito/guest/new browser profiles and developer
tools, disables browser DoH, and allows only the WTP system native host. Replace all
placeholders, publish a signed extension with a stable ID/update feed, and deploy
through your browser-management system. This repository does not contain a published
store listing, signing key, signed CRX, MDM enrollment, or automatic policy installer.
The template requires the native host installed with `--system`, administrator-owned
binaries and directories, and appropriate OS access controls. Review its effects on
other extensions before deploying. Verify effective settings in `chrome://policy`.

Chrome's [extension management policy](https://support.google.com/chrome/a/answer/9867568)
and [native host registration](https://developer.chrome.com/docs/extensions/develop/concepts/native-messaging)
document the platform-specific deployment requirements. Windows off-store force
installation also depends on enterprise management eligibility. For Windows use
GPO/MDM browser and extension policies; for macOS use managed preferences/configuration
profiles; for Linux install the adapted JSON as root in the browser's managed policy
directory. Edge uses its own policy and native-host registration locations.

**Endpoint enforcement:** the separate privileged `wtp-agent` now implements signed
network policies, OS firewall adapters, drift monitoring, expiry quarantine, and
rollback. See [endpoint deployment and validation](endpoint-enforcement.md). It uses
existing kernel firewalls rather than a browser-installed driver. Linux enforcement
is tested; Windows/macOS require native acceptance. Root/admin resistance, application
allowlisting, MDM enrollment, and hardware attestation remain separate boundaries.
[Signing tools](release-signing.md) package and verify releases and CRX3 extensions;
production publisher credentials and publication are operator prerequisites.

## Data and verification

The extension sends URLs, inferred category IDs, and optional OS identity to your
portal. Visible page text stays in the extension during normal checks. Preview text
is sent only when an administrator submits the diagnostic form. Browser decision
history stores origin/path, profile name, categories, action, and reason; query
strings and fragments are excluded from stored history, although URLs can contain
sensitive path segments. `query_log = false` disables new browser history as well as
DNS history. Both histories use the configured age/count retention, independently.
Tokens live in extension local/managed storage restricted to trusted extension
contexts; content scripts cannot request tokens or mint navigation permits. TLS
protects remote checks; the browser has no offline allow cache. Signed device network policy distribution is provided separately by the endpoint agent.

Run `cargo test --locked`, `cargo clippy --all-targets --locked -- -D warnings`,
`npm run check`, and `npm test`. The browser suite loads the actual extension into a
disposable Chromium profile against local test websites and verifies that blocked
requests do not reach their server, redirects recheck, tracking URLs are cleaned,
content categorization enforces rules, reader resources do not execute/load, and
revoked profiles cannot navigate. It also registers the real native helper inside the
disposable Linux browser profile and checks matching/mismatched OS accounts and
portal outages. CI builds the native helper on all supported OS
runners; local verification on Linux does not claim Windows/macOS end-to-end testing.
