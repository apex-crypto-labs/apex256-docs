# APEX-256 Public Documentation

This repository contains the high-level integration guides and API documentation for **APEX-256**, **APEX-AEAD**, and the wider cryptographic ecosystem (including the mbedTLS plugin and Python SDK).

> **Important:** APEX-256 is commercial intellectual property. The actual source code headers, Python wheels, and OTA packagers are available exclusively via the [APEX Developer Portal](https://apex256.io) for authenticated evaluators.

## 1. APEX-AEAD C API (Bare-Metal)

The core APEX-256 engine provides a formal Encrypt-then-MAC (EtM) Authenticated Encryption with Associated Data (AEAD) construction, bound to the proprietary APEX-HASH sponge.

### 1.1. Encryption
```c
// apex_aead_encrypt
// Provides IND-CCA2 security with zero dynamic allocation.
void apex_aead_encrypt(
    const uint8_t key[32],       // 256-bit symmetric key
    const uint8_t nonce[8],      // 64-bit unique nonce
    const uint8_t* ad,           // Associated Data (unencrypted, authenticated)
    size_t ad_len,               // Length of AD in bytes
    uint8_t* buffer,             // Plaintext in, Ciphertext out (in-place)
    size_t length,               // Length of plaintext buffer
    uint8_t mac_out[32]          // 256-bit APEX-HASH authentication tag output
);
```

### 1.2. Decryption
```c
// apex_aead_decrypt
// Strict Release of Unverified Plaintext (RUP) mitigation. Returns 0 on success.
int apex_aead_decrypt(
    const uint8_t key[32],       // 256-bit symmetric key
    const uint8_t nonce[8],      // 64-bit unique nonce
    const uint8_t* ad,           // Associated Data
    size_t ad_len,               // Length of AD
    uint8_t* buffer,             // Ciphertext in, Plaintext out (in-place)
    size_t length,               // Length of ciphertext
    const uint8_t expected_mac[32] // The 256-bit tag to verify
);
```
*Note: If the `expected_mac` does not match the calculated MAC in constant-time, the `buffer` is aggressively zeroed out before returning `-1`, preventing accidental downstream processing of forged payloads.*

## 2. Python Cloud SDK (C-Extension)

For cloud backends ingesting millions of IoT telemetry packets, the Python SDK uses a native C++ extension that releases the GIL and operates directly on PyBytes.

```python
import apex256

key = bytes.fromhex("...")
nonce = b'\x00' * 8
ad = b"device_id=7482"
plaintext = b"temperature=22.4"

# Encrypt
ciphertext, mac = apex256.aead_encrypt(key, nonce, ad, plaintext)

# Decrypt
try:
    verified_plaintext = apex256.aead_decrypt(key, nonce, ad, ciphertext, mac)
    print("Success:", verified_plaintext)
except ValueError as e:
    print("Authentication failed or forgery detected:", e)
```

## 3. Integration Modules

Apex Research Labs provides drop-in wrappers for standard protocols, available on the developer portal:
* **mbedTLS Cipher Suite Plugin**: Register `MBEDTLS_CIPHER_APEX256_AEAD` directly into your existing TLS stack.
* **Encrypted OTA Packager**: Python CLI to package firmware binaries with APEX-256 for secure bootloaders.
* **Zephyr RTOS Crypto API**: Native subsystem bindings.

Contact **info@apex256.com** to initiate commercial due diligence, sign the Evaluation NDA, and provision your developer keys on [apex256.io](https://apex256.io).
