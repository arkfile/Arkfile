# Arkfile User FAQ

This document answers common questions about Arkfile accounts, security, and recovery. It is written for end users and may be published on the website or referenced from the arkfile-client manual. Keep in sync with `client/static/faq.html`.

## What is Arkfile?

Arkfile is a privacy-first file vault. Your files and file metadata are encrypted in your browser or via the arkfile-client command-line tool before anything is uploaded. The server stores only encrypted data and cannot read your files or learn your password. You log in with a username and password using the OPAQUE protocol, which means your password is never sent to the server during registration or login.

## What is two-factor authentication and why is it required?

Every Arkfile account must complete two-factor authentication before gaining full access. After you enter your password, you must also prove possession of a second factor. This is either a TOTP code from an authenticator app such as Ente Auth, Aegis, or Bitwarden Authenticator, or a hardware security key such as a YubiKey or Nitrokey. You choose one method at enrollment. Two-factor authentication protects your account even if someone learns your password, because they would still need your phone or security key to sign in.

## What are backup codes and why do they matter?

When you set up two-factor authentication, Arkfile gives you ten single-use backup codes. Each code is a ten-character alphanumeric secret. You should save these codes in a secure place separate from your authenticator app or security key. Backup codes are account-level recovery credentials. They work whether your normal second factor is a TOTP app or a hardware key. You can use a backup code in two ways: to sign in once without changing your enrolled second factor, or to set up a new second factor when your old one is lost. Each code works only once, so use them deliberately and save any new codes issued after re-enrollment.

## I lost my authenticator app or security key. How do I set up a new second factor?

Log in with your username and password as usual. On the second-factor screen, choose the option to set up a new second factor using a backup code. Enter one of the ten backup codes you saved during setup. If the code is valid, Arkfile will guide you through enrolling a new second factor immediately and will issue a fresh set of backup codes. Your old second factor will no longer work. Each backup code works only once, so after you recover you should save the new codes and remove the old list from wherever you stored it.

## Can I use a backup code to sign in once without changing my second factor?

Yes. After you enter your username and password, on the second-factor screen choose the option to sign in once with a backup code. Enter one of your ten backup codes. If the code is valid, you receive full access for this session. Your enrolled second factor is not changed. You will need your normal TOTP code or security key on your next login, or you can use another backup code. This is useful when you need temporary access and still have your second factor available elsewhere, or when you are not ready to re-enroll yet. Each backup code still works only once.

## I lost my backup codes too. Can I still recover my account?

If you have lost both your second factor and all backup codes, you cannot recover access on your own. Arkfile does not offer email-based password or two-factor reset because it does not require or store your email address. Contact the instance administrator using the admin contact details shown on the Arkfile site (Contact Admin in the footer). The admin can verify your identity out-of-band and reset your two-factor authentication so you can log in with your password and enroll a new second factor. This is a last resort and is only appropriate when the admin is confident they are speaking with the real account holder.

## Should I save contact information in my account?

Saving contact information is optional but strongly recommended if you might ever need admin-assisted account recovery. Under Contact Info in the app, you can provide a display name, one or more contact methods such as email or Signal, and optional notes for the administrator. This information is encrypted on the server and readable only by the instance admin. It is used solely for account-related communication. If you request a two-factor reset, the admin will try to verify your identity by matching your request against contact methods you previously saved. Arkfile does not block normal usage if you choose not to provide contact information.

## I forgot my password. Can the admin reset it?

No. Arkfile has no password reset flow by design. Your password is never stored on the server and cannot be recovered or changed through the admin. The same password is also used on your device to derive the encryption key that protects your files. If you forget your password, your encrypted files cannot be decrypted. Treat your Arkfile password with the same care as a master encryption passphrase.

## Can I use Tor Browser with Arkfile?

Yes. Tor Browser is a supported browser for Arkfile. TOTP-based two-factor authentication works normally in Tor Browser because it uses a standard six-digit code entry field. Hardware security key login through the web application does not work in stock Tor Browser because Tor Browser disables WebAuthn and FIDO2 by default to reduce browser fingerprinting. If you use Tor Browser as your primary browser, choose TOTP at enrollment, or use the arkfile-client command-line tool with a hardware security key connected via USB. Do not change Tor Browser security settings to enable WebAuthn unless you understand the fingerprinting tradeoff.

## What is the difference between the web app and arkfile-client?

The web app runs in your browser and handles encryption, upload, download, and account management through the Arkfile website. The arkfile-client tool is a command-line program for the same operations: encrypting and uploading files, downloading and decrypting files, and logging into your account. Both use the same OPAQUE authentication and the same two-factor requirements. Both support TOTP and hardware security keys (e.g. YubiKey or Nitrokey), signing in once with a backup code, and re-enrolling a new second factor with a backup code. The browser uses WebAuthn for hardware keys; arkfile-client uses a direct USB connection. Choose whichever client fits your workflow; the security model is the same.

## How do I contact the administrator?

The administrator contact details for your Arkfile instance are shown on the site. Look for Contact Admin in the footer on the homepage or when you are logged in. The exact address or channel depends on how your instance operator configured the deployment. If your account is awaiting approval, admin contact information is also shown on the pending-approval screen.

## What happens when an admin resets my two-factor authentication?

An administrator can clear your enrolled second factor and backup codes using the arkfile-admin reset-user-mfa command. This force-logs you out of all active sessions. The next time you log in with your password, Arkfile will prompt you to set up two-factor authentication again as if you were completing registration. You will receive a new TOTP secret or register your security key again, along with a new set of backup codes. The admin should only perform this reset after verifying that the account is actually yours out-of-band. Your files and password are not affected; only the second-factor enrollment is cleared.

## Can I have both TOTP and a hardware security key?

Each account can enroll one second factor at a time: either TOTP or a hardware security key, not both. A future release plans to allow up to three second-factor credentials per account, such as one TOTP app plus two labeled security keys. Backup codes remain recommended regardless of which method you use.

## Do I need to enter a PIN on my security key every time I log in?

That depends on your key and how it is configured. Arkfile requests user verification as preferred rather than required. That usually means a single touch on your YubiKey or Nitrokey is enough, similar to Proton Mail or Bitwarden. If your key is configured to require a PIN on every operation, you will be prompted accordingly. Your PIN never leaves the device and is not sent to Arkfile or the server.
