# APEX-256 Public API & Architecture Documentation (v2.1.4.1)

This repository provides high-level architectural documentation and public C++ API signatures for the **APEX-256** cryptographic suite (`apex256_nano.h`), developed by **Apex Research Labs, LLC** (Inventor: Diab Anthony Sheteyh).

> **Important:** APEX-256 is proprietary commercial intellectual property protected by 5 pending U.S. Provisional Patent Applications. The implementation header (`apex256_nano.h`), hardware starter projects, and verification harnesses are available exclusively to authenticated licensees via the [APEX Developer Portal (apex256.io)](https://apex256.io) under an executed Evaluation NDA.

---

## 1. Single-Header C/C++ SDK Architecture (`Apex256Nano`)

The APEX-256 SDK is delivered as a zero-dependency, single-header C++ library (`apex256_nano.h`) engineered for bare-metal microcontrollers (`ARM Cortex-M4`, `ESP32-S3`, `nRF52840`, `RP2040`, `RISC-V`) and high-throughput native hosts:

* **32-Byte Core State:** Operates entirely in four 64-bit registers (`0 bytes` heap allocation, zero `malloc`/`free`, zero lookup tables).
* **Constant-Time Execution:** Branchless 24-round coupled initialization and branchless keystream generation (Dudect Welch's $|t| = 1.12 < 4.5$).
* **Build Forge Module Stripping:** Using the [APEX Build Forge](https://apex256.io/forge), licensees can compile custom headers containing only the primitives required for their target hardware, physically stripping unused `#ifdef` blocks to minimize Flash usage.
* **3-Layer Zero-Callback Fingerprinting (3LZCF):** Every compiled or downloaded SDK artifact is sealed with three zero-telemetry provenance layers (Layer 1 HMAC Manifest & Preprocessor Seal, Layer 2 Dead-Strip-Resistant `.rodata` `APX3` Binary Beacon, and Layer 3 Blinded Constant-Folded Algebraic Splits) with **zero runtime cycle overhead** and **100% bit-exact KAT invariance**.

---

## 2. Core Stream Cipher & AEAD API Signatures

All primitives are encapsulated within `class Apex256Nano`.

### 2.1. Core Stream Cipher (`1:1` Payload Density)

```cpp
#include "apex256_nano.h"

Apex256Nano engine;

// Initialize 256-bit key (32 bytes) + 64-bit unique session nonce (8 bytes).
// Executes the branchless 24-round coupled burn-in and Z3 fixed-point guard.
void engine.init(const uint8_t key[32], const uint8_t nonce[8]);

// In-place XOR keystream encryption / decryption (zero byte expansion).
void engine.process_payload(uint8_t* buffer, size_t length);

// Constant-time volatile state scrubbing (FIPS 140-3 zeroization).
void engine.zeroize();
```

### 2.2. Authenticated Encryption with Associated Data (`APEX-AEAD`)

`APEX-AEAD` implements a domain-separated Encrypt-then-MAC (EtM) construction anchored to the coupled 256-bit `APEX-HASH` Rate-Capacity sponge (`64-bit` rate + `192-bit` hidden capacity):

```cpp
// Encrypts `buffer` in-place and computes a 256-bit (32-byte) authentication tag (`mac_out`)
// over the key, nonce, associated data (`ad`), ciphertext, and 64-bit LE length block.
void engine.apex_aead_encrypt(
    const uint8_t key[32],       // 256-bit symmetric key
    const uint8_t nonce[8],      // 64-bit unique nonce
    const uint8_t* ad,           // Associated Data (authenticated, unencrypted)
    size_t ad_len,               // Length of AD in bytes
    uint8_t* buffer,             // Plaintext in -> Ciphertext out (in-place)
    size_t length,               // Payload length in bytes
    uint8_t mac_out[32]          // 256-bit authentication tag output
);

// Verifies `mac_in` over the ciphertext in constant time BEFORE decrypting.
// Returns 0 on authentic decryption, or -1 on authentication failure.
int engine.apex_aead_decrypt(
    const uint8_t key[32],       // 256-bit symmetric key
    const uint8_t nonce[8],      // 64-bit unique nonce
    const uint8_t* ad,           // Associated Data
    size_t ad_len,               // Length of AD in bytes
    uint8_t* buffer,             // Ciphertext in -> Plaintext out (only if MAC valid)
    size_t length,               // Payload length in bytes
    const uint8_t mac_in[32]     // 256-bit authentication tag to verify
);
```

> **Release of Unverified Plaintext (RUP) Immunity:** `apex_aead_decrypt` recomputes and verifies the 256-bit authentication tag over the ciphertext in constant time *before* initializing the keystream or modifying `buffer`. If verification fails (`diff != 0`), it returns `-1` immediately without ever computing or exposing unverified plaintext.

---

## 3. Modular Companion Primitives (`#ifdef` Configurable)

Licensees can selectively include any combination of the following companion primitives in the Build Forge:

| Preprocessor Flag | Primitive | Public Member Methods |
|---|---|---|
| `APEX256_INCLUDE_HASH` | **APEX-HASH** (256-Bit Coupled Sponge) | `hash_init()`, `hash_absorb(data, len)`, `hash_squeeze(out_hash)` |
| `APEX256_INCLUDE_AEAD` | **APEX-AEAD** (Encrypt-then-MAC) | `apex_aead_encrypt(...)`, `apex_aead_decrypt(...)` |
| `APEX256_INCLUDE_DRBG` | **APEX-DRBG** (Backtracking-Resistant DRBG) | `drbg_instantiate(entropy, len)`, `drbg_reseed(entropy, len)`, `drbg_generate(out, len)` |
| `APEX256_INCLUDE_VFS` | **APEX-VFS** (O(1) Sector Disk Encryption) | `vfs_seek_sector(file_key, sector_index, write_epoch)`, `vfs_process_sector(sector_buf)` |
| `APEX256_INCLUDE_CFB` | **APEX-CFB** (64-Bit Rotated Cipher Feedback) | `process_payload_cfb_tx(buf, len)`, `process_payload_cfb_rx(buf, len)` |
| `APEX256_INCLUDE_FPE` | **APEX-FPE** (Branchless Numeric ASCII FPE) | `process_payload_fpe_tx(str, len)`, `process_payload_fpe_rx(str, len)` |
| `APEX256_INCLUDE_STEALTH` | **APEX-STEALTH** (EM / Power SCA Equalizer) | `process_payload_stealth(buf, len)` |

---

## 4. Portal Engineering Tools & Starter Projects

Authenticated evaluators on [apex256.io](https://apex256.io) have access to:

* **Build Forge (`/forge`):** Custom header compilation with `#ifdef` AST stripping and 3LZCF provenance sealing.
* **Hardware Starter Kits (`/starter-projects`):** Ready-to-flash reference projects for **ESP32-S3 (ESP-IDF)**, **Nordic nRF52840 (Zephyr)**, **STM32F4 Cortex-M4 (CubeIDE / Bare-Metal)**, and **Raspberry Pi Pico (RP2040 SDK)**.
* **Embedded Calculators & Diagnostics:**
  * **Packet & MTU Budgeter (`/tools/packet-budgeter`):** LoRaWAN, BLE, and satellite airtime/battery analyzer.
  * **DMA & Zero-Copy Alignment (`/tools/dma-calc`):** Cache-line and ping-pong DMA buffer planner.
  * **RTOS Stack Sizer (`/tools/rtos-sizer`):** FreeRTOS, Zephyr, and ThreadX task stack calculator.
  * **KAT Output Sandbox (`/tools/kat-verifier`) & 3LZCF Artifact Verifier (`/tools/verify-artifact`).**

---

## 5. Request Evaluation Access

* **Public & Defense Portal:** [https://apex256.com](https://apex256.com)
* **Developer Portal & Build Forge:** [https://apex256.io](https://apex256.io)
* **Public Security & Engineering Ledger:** [https://apex256.io/security-ledger](https://apex256.io/security-ledger)
* **Contact:** **info@apex256.com**
