# ChaCha20

A pure Ruby implementation of the Salsa20 and ChaCha20 stream ciphers. Supports arbitrary seeking inside the keystream.

## Installation

For the time being, this is not on rubygems.org. Point your Gemfile to this repository.

## Usage

Initialize a new cipher with a 32-bit key and an 8-bit nonce:

```ruby
cipher = ChaCha20::Cipher.new(key: key, nonce: nonce)
```

You can then encrypt or decrypt data with the `encrypt` and `decrypt` methods:

```ruby
ciphertext = cipher.encrypt(plaintext)
plaintext = cipher.decrypt(ciphertext)
```
