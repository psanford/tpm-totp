# tpm-totp

tpm-totp is a totp (and hotp) two factor agent that stores the 2fa secret in your system's TPM.

Storing the [TH]OTP secret in the TPM prevents it from being extracted from your disk and used on another system.

# Copying

The tpm-totp is a fork of rsc.io/2fa with the secret storage moved from disk into the TPM.

License 3-clause BSD. See LICENSE file for copyright notice.

## Usage

```
 tpm-totp -add [-7] [-8] [-hotp] name
 tpm-totp -list
 tpm-totp [-clip] name

“tpm-totp -add name” adds a new key to the tpm-totp keychain with the given name.
It prints a prompt to standard error and reads a two-factor key from standard input.
Two-factor keys are short case-insensitive strings of letters A-Z and digits 2-7.

By default the new key generates time-based (TOTP) authentication codes;
the -hotp flag makes the new key generate counter-based (HOTP) codes instead.

By default the new key generates 6-digit codes; the -7 and -8 flags select
7- and 8-digit codes instead.

“tpm-totp -list” lists the names of all the keys in the keychain.

“tpm-totp name” prints a two-factor authentication code from the key with the
given name. If “-clip” is specified, tpm-totp also copies the code to the system
clipboard.

With no arguments, tpm-totp prints two-factor authentication codes from all
known time-based keys.

The default time-based authentication codes are derived from a hash of
the key and the current time, so it is important that the system clock have
at least one-minute accuracy.

The keychain is stored unencrypted in the text file $HOME/.tpm-totp.

Example

During GitHub 2FA setup, at the “Scan this barcode with your app” step,
click the “enter this text code instead” link. A window pops up showing
“your two-factor secret,” a short string of letters and digits.

Add it to tpm-totp under the name github, typing the secret at the prompt:

 $ tpm-totp -add github
 tpm-totp key for github: nzxxiidbebvwk6jb
 $

Then whenever GitHub prompts for a TPM-TOTP code, run tpm-totp to obtain one:

 $ tpm-totp github
 268346
 $

Or to type less:

 $ tpm-totp
 268346	github
 $

```
