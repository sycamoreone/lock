Lock
=====

Lock is an implementation of the github.com/kaepora/miniLock encrypted container format. It comes without a user interface and is still missing most of the features in minilock.

Disclaimer
---------

This is proof-of-concept quality code at best and it should be assumed that nobody but the author ever looked at it. Please  use the official miniLock plugin, if you are looking for a secure encryption software.

TODO
-----

- [x] Derive keys from email address and passphrase.
- [x] Decrypt files.
- [ ] Encrypt files.
- [ ] Suggest seven-word passphrases.
- [ ] Estimate entropy using [zxcvbn](https://github.com/dropbox/zxcvbn).
- [ ] Provide a usable CLI based client.
