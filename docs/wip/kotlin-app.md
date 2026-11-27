# Kotlin and Compose Multiplatform App

## Overview

Arkfile will grow a third client, written in Kotlin with Compose Multiplatform, for Android, Linux, Windows, and Mac, in that order. It is a native application. It does not embed a browser, a system WebView, Chrome, or Firefox. The same Kotlin sources draw the interface and implement the vault protocol on every platform. Android is a sideloaded APK. The desktops are JVM applications packaged later.

The app is a peer of the TypeScript website and of `arkfile-client`, not a replacement for either. It speaks the same OPAQUE login, the same Argon2id key derivation, the same version-2 owner envelopes, and the same chunked upload and download protocol. Files it writes must open in the other two clients, and files they write must open in it.

Nothing in this document is implemented. `arkfile-client` remains the proven command-line client, including hardware security keys and the Linux account-key agent. The website remains the browser client.

## Goal

Ship one application that looks like a sibling of the website on a phone and on three desktops, and that can register, enroll TOTP, log in, list, upload, download, and share against an existing Arkfile server without weakening the privacy model.

Android comes first, as an APK a person can install without the Play Store. Linux is the second platform, built and tried on the same kind of machine used for Arkfile development, before any Windows or Mac packaging. Windows is third. Mac is fourth. A later platform does not block an earlier one, and iOS is out of scope.

The first Android cut is the vault itself: register, TOTP enrollment and login, file list, streaming upload, streaming download, share create, and anonymous share receive. Opening a file that was encrypted with a custom password is part of that cut, because a real vault already contains those files. The custom password is asked for at the moment of use and is not retained.

## Background

The website and `arkfile-client` already agree. Unit tests, conformance fixtures, end-to-end runs, and browser tests cover OPAQUE, Argon2id, envelopes, chunk and metadata additional authenticated data, share envelopes, and the streaming transfer. A Kotlin client is in a better position than either of those two were when the second one was written: the fixtures are the specification, and a file can be round-tripped through a Go binary and through the site before the new client is trusted.

Other shapes were considered and set aside. A Trusted Web Activity or an Android WebView depends on Chromium. An embedded Firefox engine is still a browser. A Go UI toolkit could call the existing Go crypto, and it is a weaker fit for one interface that should follow the website's theme on a phone and on three desktops. Flutter could draw that interface, and the Android storage APIs that make a multi-gigabyte file safe on a low-memory phone would still have been Kotlin underneath. TypeScript cross-platform shells reuse the website by embedding a webview, which is the dependency this app exists to avoid. React Native does not run the current frontend and is not a solid Linux desktop target.

Compose Multiplatform is the UI toolkit that is at home on Android and that can share that UI with Linux, Windows, and Mac. Desktop builds run on a bundled JVM. That costs a larger download and a slower cold start than `arkfile-client`. It is an accepted cost. File transfer speed is dominated by the network, the disk, and Argon2id, not by Compose.

## Constraints and things to keep in mind

### Privacy

The server must continue to learn nothing it does not already learn. The account password is used for OPAQUE and, separately, to derive the Account Key. It is never sent to the server and never written to disk. Custom file passwords and share passwords are never written to disk either. The OPAQUE export key is not a file key.

The Account Key and any refresh token live in process memory for the work the user just authenticated. Wipe the Account Key when the user logs out, when the user locks the app, and when the process dies. Zeroing a JVM or Android byte array is best-effort. The collector may have copied it. Treat that as the same class of limit the browser already has. Do not persist the Account Key, and do not wrap it for later unlock. There is no long-lived device credential that stands in for the account password.

TOTP is the second factor this app enrolls and accepts. Hardware security keys stay on `arkfile-client`. Android's platform FIDO APIs are tied to Play Services on stock phones, and this app does not use Play Services.

A refresh token is online authorization for one server session family. The family ends after six hours without user activity, or twenty-four hours after sign-in, whichever comes first. Refresh does not count as activity and does not move the twenty-four hour mark. Those rules stay as they are. When the server returns `session_idle` or `session_absolute`, delete the local session and require OPAQUE plus TOTP again. Logout and revoke-all delete it too.

The app ships no Play Services, no Firebase, no Google billing, and no third-party analytics or crash reporter. A crash report that includes a filename, a username, or a server URL is a privacy bug.

The user must be able to point the app at a server other than the public one, including a self-hosted origin. Insecure TLS is acceptable only for loopback, matching `arkfile-client`.

### One streaming path

There is one way for this client to encrypt and upload, and one way to download and decrypt. Both stream a single plaintext chunk at a time. The chunk size and the Argon2id parameters are the values in `crypto/chunking-params.json` and `crypto/argon2id-params.json`, and the same server config endpoints the other clients already honor. Do not copy those numbers into a second source of truth.

The defining case is a person on a phone with 3 GB of RAM moving a 6 GB file. Read and write through Android's storage APIs (a content URI), not by copying the file into the app's cache first. Keep one chunk buffer. A multi-gigabyte transfer needs a foreground service so the operating system does not suspend the process. The desktop targets use ordinary files and the same chunk loop.

Argon2id should be libsodium's, which this app already links for OPAQUE, not a pure-Kotlin implementation. A pure-Kotlin Argon2id is often slower at the same memory and time cost. Its output still has to match the existing vectors, including the context salt the Go client builds in `DerivePasswordKey` (`arkfile-owner-kdf-v1`, the `"account"` or `"custom"` label, and the public salt). AES-GCM can use the platform provider. It is hardware-accelerated on Android and on the desktop JVM.

### OPAQUE and native libraries

OPAQUE stays the vendored C library: libsodium, liboprf, and libopaque, called through JNI. Do not write a second OPAQUE. The JNI surface should mirror the client operations in `auth/opaque_client.go`: registration request, registration finalize, login request, login finalize. Buffer sizes, the username, and the server identity from `/api/config/opaque` have to match what the server already checks. Wipe password bytes after the call.

Build those libraries from the vendored sources already in this repository. Android uses the NDK. Linux, Windows, and Mac each get a native build on that operating system. Cross-compiling this C stack from a single Linux host is the approach `docs/wip/cli-builder.md` already rejects for `arkfile-client`. The same preference applies here. Do not fork a second copy of the library recipes. libfido2 is not part of this app.

### Android packaging and development

The Android artifact is an APK signed with a key the project holds. People install it by allowing install of unknown apps. There is no Play Store listing, no Play App Signing, and no Google account in the distribution path. Losing the signing key means users cannot be given an update that installs over the old APK. The key is an operational secret and needs a backup.

Android Studio, the IDE, is not the required development environment. The required tools are a JDK, Gradle, the Android command-line SDK (platform, build-tools, platform-tools), and the NDK. `sdkmanager` and `./gradlew` are the build. A Compose-aware editor such as IntelliJ IDEA is a convenience for previews and the debugger. Editing this UI only inside VSCodium is possible and is unpleasant. The command-line SDK is enough to produce the APK either way.

The first phone ABI is arm64-v8a. Whether a 32-bit ABI is also shipped is unsettled. Prove a large transfer on a device or an emulator whose heap is in the same class as a 3 GB phone. A desktop JVM test does not prove the phone path.

### Desktops, after Android

Linux, Windows, and Mac share the Kotlin UI and the Kotlin protocol code. Each desktop build is a `jpackage` image with a bundled JVM, plus that platform's libsodium and libopaque. Expect a larger download and a slower cold start than the Go CLI. Idle memory is higher. That is acceptable for a laptop and worth saying in user-facing notes when those builds exist.

Platform differences stay at the edges: loading the native library, picking a file, writing a file, and storing the session file in a per-user location. Shared code should not fill up with per-platform branches.

Compose will not look like GTK, AppKit, or Win32, and it should not. It should follow the website. The tokens in `client/static/css/styles.css` are the palette: depth surfaces, current and foam for controls and secondary text, biolum for the accent, phosphor for warning, coral for error, salt for primary text, and the shared control height. Map those once. The app is a sibling of the site, not a copy of the DOM. Phone and desktop still need two layouts, compact and expanded, over those shared controls. The default desktop file dialog looks dated. Replacing it is allowed later. It is not a reason to embed a browser.

Try the Linux build on the developer's actual desktop early, including Wayland if that is what the machine runs. Compose on Linux has been the least settled of the three desktops.

### Proving the third client

The Kotlin crypto is ready for real files only after it matches the existing fixtures (Argon2, additional authenticated data, owner envelopes, share envelopes) and after a file uploaded by this app opens in `arkfile-client` and in the website, and the reverse. Run that check whenever the envelope, the additional authenticated data, or the key-derivation context changes. All three clients move together. The vectors are the specification.

Crypto and disk work run off the UI thread. Argon2id and the chunk loop on the UI dispatcher will freeze the window. That is a defect, not a tuning option.

Password rules come from `crypto/password-requirements.json` and the same policy the other clients enforce. Do not invent a looser phone password.

### What this project does not do

It does not replace `arkfile-client` or the website. It does not add a new login protocol, a new envelope version, or a new chunk size. It does not change server session lifetimes. It does not store the account password on the device. It does not enroll hardware security keys. It does not ship iOS. It does not require the Play Store or Android Studio.

## Open questions

1. Where does the Gradle project live? A directory in this repository keeps the vendored C sources and the conformance fixtures next to the client. A separate repository makes the Android SDK and Gradle noise easier to keep away from the Go server. Which one do we want?
2. Is the first Android cut confirmed as register, TOTP, login, list, streaming upload, streaming download, share create, share receive, and open-with-custom-password? Do tags, batch transfer, `.arkbackup` export and offline decrypt, billing, subscriptions, contact info, and revoke-all wait?
3. Is creating a new custom-password file in the first cut, or only opening one that already exists?
4. During a server session that is still valid, when does the in-memory Account Key get wiped? On every trip to the background, after a short idle timer, only when the user locks the app, or only when the session ends?
5. IntelliJ IDEA is the comfortable Compose editor and is not Android Studio. Is IDEA an acceptable daily driver, with Android Studio itself unused? Or is the bar "Gradle from the current editor, no JetBrains IDE"?
6. What is the minimum Android API level, and does the first APK include any ABI besides arm64-v8a?
7. What is the application id and the name shown under the icon?
8. How do sideload updates work? Manual replacement of the APK only, or an in-app check against a URL the operator publishes? An update check has to avoid becoming telemetry.
9. Where do the NDK and desktop native builds of libsodium, liboprf, and libopaque live so they reuse the vendored sources without a second build recipe?
10. For the Linux release, which package shape matters (a `jpackage` image, a deb, an AppImage, a tarball), and does "works on Wayland" count as part of done?
11. Mac notarization and Windows Authenticode are distribution friction, not protocol work. Are signed desktop builds a goal of those ports, or is an unsigned sideload enough the way the APK is?
