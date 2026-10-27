# APEX-256 Public API & Architecture Documentation (v2.2.7.3)

This repository provides high-level architectural documentation and public C++ API signatures for the **APEX-256** cryptographic suite (`apex256_nano.h`), developed by **Apex Research Labs, LLC** (Inventor: Diab Anthony Sheteyh).

> **Important:** APEX-256 is proprietary commercial intellectual property protected by pending U.S. and International Patent Applications. The implementation header (`apex256_nano.h`), hardware starter projects, and verification harnesses are available exclusively to authenticated licensees via the [APEX Developer Portal (apex256.io)](https://apex256.io) under an executed Evaluation NDA.

---

## 1. Single-Header C/C++ SDK Architecture (`Apex256Nano`)

The APEX-256 SDK is delivered as a zero-dependency, single-header C++ library (`apex256_nano.h`) engineered for bare-metal microcontrollers (`ARM Cortex-M4/M7`, `ESP32-S3`, `nRF52840`, `RP2040`, `RISC-V`), synthesizable FPGA RTL cores, and high-throughput native hosts:

* **40-Byte Self-Contained Zero-Allocation Context:** Operates in a `40-byte` self-contained `Apex256Nano` context (`32-byte` / `256-bit` four-register core manifold and 8 bytes of companion control metadata; `0 bytes` dynamic heap allocation, `0 bytes` static `.bss`/`.tbss`/`.data`, zero `malloc`/`free`, zero lookup tables).
* **Ephemeral Hardware Multiplier Masking (Wave 15):** Bit-exact side-channel operand blinding across the 64-bit modular multiplier datapath (`CPA |r| = 0.0024`, Welch `|t| = 0.74 < 4.50`, `100%` wire-compatible with standard Known Answer Tests).
* **Extended 256-Bit Nonce (`X256`) & Forward-Secrecy Keyframe Ratcheting (Wave 15):** `init_x256`, `init_stealth_x256`, `init_wide_x256`, and `apex_aead_encrypt_x256` / `decrypt_x256` expand random-nonce birthday safety from `2^32` to `2^128` messages with zero added RAM. `process_payload_ratcheted` and `ratchet_stream` execute an irreversible one-way state transition every 256 bytes (`100%` chunk-split invariant) so a physical RAM capture cannot be inverted to recover prior keystream.
* **Full-State 256-Bit Companion Mode Architecture (`F256`, Wave 16):** Reclaims all 256 bits of active state across `HASH-W64`, `CFB-256`, `VFS-256` (with bijective 256-bit sector tweak isolation), and `DRBG-256` while keeping the `40-byte` context unchanged.
* **Word-Rate Sponge (`W64`) & Feedforward Multi-Byte Stream Extraction (Wave 16):** `process_payload_fast`, `hash_*_w64`, `apex_aead_*_w64`, and `vfs_process_sector_fast` deliver `4x` to `8x` throughput acceleration across bulk stream encryption, hashing, MAC, KDF, VFS sector processing, and AEAD while preserving `100%` streaming chunk invariance and `1:1` byte-stream compatibility.
* **Waves 1 - 16 & 38-Tool Formal Verification Battery:** Certified across 16 cryptanalysis waves, a 38-tool external formal/SMT/SAT/MILP/SCA/RTL battery (Bitwuzla, cvc5, CaDiCaL, Coq, F*, HiGHS, SCALib, Lascar, VerFI, SymbiYosys), and a 7-engine reduced-round security-margin certification (`4.0x` to `24.0x` safety margin across the 24-round initialization schedule).
* **Build Forge Module Stripping & 3LZCF v3.1 Provenance:** Using the [APEX Build Forge](https://apex256.io/forge), licensees compile custom headers containing only the primitives required for their target hardware, sealed with **3-Layer Zero-Callback Fingerprinting (`3LZCF v3.1`)** and a 4-source compile-time target-architecture silicon interlock (`universal`, `xtensa-lx7`, `riscv32`, `arm-cortex`, `x86_64`, `avr`, `fpga-verilog`) with **zero runtime cycle overhead** and **100% bit-exact KAT invariance**.

---

## 2. Core Stream Cipher, X256, Ratcheting, Fast Stream & AEAD API Signatures

All primitives are encapsulated within `class Apex256Nano` (`sizeof(Apex256Nano) == 40`).

### 2.1. Core Stream Cipher, Extended 256-Bit Nonce (`X256`), Forward-Secrecy Ratcheting & Fast Stream (`1:1` Payload Density)

```cpp
#include "apex256_nano.h"

Apex256Nano engine;

// Standard 64-bit nonce initialization: 256-bit key (32 bytes) + 64-bit unique session nonce (8 bytes).
// Executes the branchless 24-round coupled burn-in, Z3 fixed-point guard, and hardware multiplier masking.
void engine.init(const uint8_t key[32], const uint8_t nonce[8]);

// Extended 256-bit nonce (X256) initialization: 256-bit key (32 bytes) + 256-bit nonce (32 bytes).
// Expands random-nonce birthday safety from 2^32 to 2^128 messages with zero added RAM.
void engine.init_x256(const uint8_t key[32], const uint8_t nonce256[32]);

// Standard in-place XOR keystream encryption / decryption (zero byte expansion, 100% chunk-invariant).
void engine.process_payload(uint8_t* buffer, size_t length);

// Forward-secrecy keyframe ratcheted stream processing: executes an irreversible one-way
// state transition every 256 bytes (100% chunk-split invariant) plus an explicit ratchet API.
void engine.process_payload_ratcheted(uint8_t* buffer, size_t length);
void engine.ratchet_stream();

// High-throughput one-way feedforward multi-byte stream extraction (4x to 8x bulk speedup,
// 100% arbitrary chunk-split invariant, 1:1 byte-stream density).
void engine.process_payload_fast(uint8_t* buffer, size_t length);

// Self-contained 40-byte checkpoint export/restore & FIPS 140-3 zeroization.
void engine.export_state(uint8_t out_state[40]) const;
void engine.zeroize();
```

### 2.2. Authenticated Encryption with Associated Data (`APEX-AEAD`, `AEAD-X256` & `AEAD-W64`)

`APEX-AEAD` implements a domain-separated Encrypt-then-MAC (EtM) construction with strict Release of Unverified Plaintext (RUP) immunity and dual-accumulator fault-resistant tag verification across standard 64-bit nonce, extended 256-bit nonce (`X256`), and word-rate accelerated (`W64`) envelopes:

```cpp
// Standard 64-bit nonce Encrypt-then-MAC (in-place encryption + 256-bit authentication tag).
void engine.apex_aead_encrypt(
    const uint8_t key[32],       // 256-bit symmetric key
    const uint8_t nonce[8],      // 64-bit unique nonce
    const uint8_t* ad,           // Associated Data (authenticated, unencrypted)
    size_t ad_len,               // Length of AD in bytes
    uint8_t* buffer,             // Plaintext in -> Ciphertext out (in-place)
    size_t length,               // Payload length in bytes
    uint8_t mac_out[32]          // 256-bit authentication tag output
);

// Verifies `mac_in` in constant time BEFORE decrypting (strict RUP immunity).
// Returns 0 on authentic decryption, or -1 on authentication failure.
int engine.apex_aead_decrypt(
    const uint8_t key[32],
    const uint8_t nonce[8],
    const uint8_t* ad,
    size_t ad_len,
    uint8_t* buffer,
    size_t length,
    const uint8_t mac_in[32]
);

// Extended 256-bit nonce (X256) AEAD (2^128 random-nonce birthday bound):
void engine.apex_aead_encrypt_x256(
    const uint8_t key[32], const uint8_t nonce256[32],
    const uint8_t* ad, size_t ad_len, uint8_t* buffer, size_t length, uint8_t mac_out[32]
);
int engine.apex_aead_decrypt_x256(
    const uint8_t key[32], const uint8_t nonce256[32],
    const uint8_t* ad, size_t ad_len, uint8_t* buffer, size_t length, const uint8_t mac_in[32]
);

// High-throughput Word-Rate (W64) + Fast Stream AEAD (64-bit nonce and 256-bit X256 nonce variants):
void engine.apex_aead_encrypt_w64(
    const uint8_t key[32], const uint8_t nonce[8],
    const uint8_t* ad, size_t ad_len, uint8_t* buffer, size_t length, uint8_t mac_out[32]
);
int engine.apex_aead_decrypt_w64(
    const uint8_t key[32], const uint8_t nonce[8],
    const uint8_t* ad, size_t ad_len, uint8_t* buffer, size_t length, const uint8_t mac_in[32]
);
void engine.apex_aead_encrypt_x256_w64(
    const uint8_t key[32], const uint8_t nonce256[32],
    const uint8_t* ad, size_t ad_len, uint8_t* buffer, size_t length, uint8_t mac_out[32]
);
int engine.apex_aead_decrypt_x256_w64(
    const uint8_t key[32], const uint8_t nonce256[32],
    const uint8_t* ad, size_t ad_len, uint8_t* buffer, size_t length, const uint8_t mac_in[32]
);
```

> **Release of Unverified Plaintext (RUP) Immunity:** All `apex_aead_decrypt*` variants recompute and verify the 256-bit authentication tag over the ciphertext across dual redundant accumulators in constant time *before* initializing the keystream or modifying `buffer`. If verification fails, decryption aborts immediately (`-1`) without exposing unverified plaintext.

---

## 3. Modular Companion Primitives (`#ifdef` Configurable)

Licensees can selectively include any combination of the following companion primitives in the Build Forge:

| Preprocessor Flag | Primitive | Public Member Methods |
|---|---|---|
| `APEX256_INCLUDE_HASH` | **APEX-HASH & HASH-W64** (256-Bit Coupled Sponge, MAC & KDF) | `hash_init()`, `hash_absorb(data, len)`, `hash_squeeze(out)`, `hash_mac(...)`, `hash_kdf(...)`, plus full 256-bit word-rate `hash_init_w64()`, `hash_absorb_w64(data, len)`, `hash_squeeze_w64(out)`, `hash_mac_w64(...)`, `hash_kdf_w64(...)` |
| `APEX256_INCLUDE_AEAD` | **APEX-AEAD, AEAD-X256 & AEAD-W64** (Encrypt-then-MAC) | `apex_aead_encrypt(...)`, `apex_aead_decrypt(...)`, `apex_aead_encrypt_x256(...)`, `apex_aead_decrypt_x256(...)`, `apex_aead_encrypt_w64(...)`, `apex_aead_decrypt_w64(...)`, `apex_aead_encrypt_x256_w64(...)`, `apex_aead_decrypt_x256_w64(...)` |
| `APEX256_INCLUDE_DRBG` | **APEX-DRBG & DRBG-256** (Backtracking-Resistant DRBG) | `drbg_instantiate(entropy, len)`, `drbg_reseed(entropy, len)`, `drbg_generate(out, len)`, plus full 256-bit `drbg_instantiate_256(entropy, len)`, `drbg_reseed_256(entropy, len)`, `drbg_generate_256(out, len)` |
| `APEX256_INCLUDE_VFS` | **APEX-VFS & VFS-256** (`O(1)` Sector Disk Encryption) | `vfs_seek_sector(file_key, sector_index, write_epoch)`, `vfs_process_sector(sector_buf)`, plus bijective 256-bit sector tweak `vfs_seek_sector_256(file_key, sector_index, write_epoch)` and `vfs_process_sector_fast(sector_buf, len)` |
| `APEX256_INCLUDE_CFB` | **APEX-CFB & CFB-256** (Rotated Cipher Feedback) | `process_payload_cfb_tx(buf, len)`, `process_payload_cfb_rx(buf, len)`, plus full 256-bit state `process_payload_cfb256_tx(buf, len)`, `process_payload_cfb256_rx(buf, len)` |
| `APEX256_INCLUDE_FPE` | **APEX-FPE** (Branchless Numeric ASCII FPE) | `init_fpe(key, tweak)`, `process_payload_fpe_tx(str, len)`, `process_payload_fpe_rx(str, len)` |
| `APEX256_INCLUDE_W32` | **APEX-W32** (32-Bit Sub-Word Cached Wide Stream) | `init_wide(key, nonce)`, `init_wide_x256(key, nonce256)`, `next_keystream_u32()`, `process_payload_wide(buf, len)` |
| `APEX256_INCLUDE_STEALTH` | **APEX-STEALTH** (EM / Power SCA Equalizer) | `init_stealth(key, nonce)`, `init_stealth_x256(key, nonce256)`, `process_payload_stealth(buf, len)` |
| `APEX256_INCLUDE_TAMPER` | **APEX-TAMPER** (Active Memory Integrity Guard) | `tamper_init(key, region, len)`, `tamper_verify_and_ratchet(...)` |

---

## 4. Portal Engineering Tools & Starter Projects

Authenticated evaluators on [apex256.io](https://apex256.io) have access to:

* **Build Forge (`/forge`):** Custom header compilation with preprocessor module stripping, BYOB custom hardware profiles, `3LZCF v3.1` provenance sealing, and 4-source compile-time architecture interlocks.
* **Hardware Starter Kits (`/starter-projects`):** Ready-to-flash reference projects for **ESP32-S3 (ESP-IDF)**, **Nordic nRF52840 (Zephyr)**, **STM32F4/H7 Cortex-M4/M7 (CubeIDE / Bare-Metal)**, **RISC-V (GD32VF103 / FE310)**, **Linux Userspace**, and **Synthesizable Verilog-2005 FPGA Soft-Core & AXI4-Stream Wrapper**.
* **Cloud & Middleware SDKs (`/sdks/cloud`, `/sdks/middleware`, `/sdks/secure-boot`):** Reference bindings for Python C-Extension, Rust, Go, Node.js, zero-heap 16-slot mbedTLS / WolfSSL wrappers, and Anti-Rollback OTA Secure Bootloader templates.
* **Embedded Calculators & Diagnostics:**
  * **Packet & MTU Budgeter (`/tools/packet-budgeter`):** LoRaWAN, BLE, and satellite airtime/battery analyzer.
  * **DMA & Zero-Copy Alignment (`/tools/dma-calc`):** 64-bit BigInt cache-line and ping-pong DMA buffer planner.
  * **RTOS Stack Sizer (`/tools/rtos-sizer`):** FreeRTOS, Zephyr, and ThreadX task stack calculator.
  * **OTA Firmware Packager (`/tools/ota-packager`) & Key Lifecycle Planner (`/tools/key-lifecycle`).**
  * **Renode/QEMU Emulation Harnesses (`/tools/emulation-harnesses`) & Factory Provisioning (`/tools/provisioning`).**
  * **KAT Output Sandbox (`/tools/kat-verifier`) & 3LZCF Artifact Verifier (`/tools/verify-artifact`).**

---

## 5. Request Evaluation Access

* **Public & Defense Portal:** [https://apex256.com](https://apex256.com)
* **Developer Portal & Build Forge:** [https://apex256.io](https://apex256.io)
* **Public Security & Engineering Ledger:** [https://apex256.io/security-ledger](https://apex256.io/security-ledger)
* **Contact:** **info@apex256.com**
