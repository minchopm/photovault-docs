# PhotoVault: Encrypt & Compress — Security Architecture & `.pvsecure` Format Specification

Official public security architecture documentation and portable archive envelope specification (`.pvsecure`, `PVSHAR01`) for **[PhotoVault: Encrypt & Compress](https://apps.apple.com/us/app/photovault-encrypt-compress/id6824412013)** (`App Store ID: 6824412013`), developed by **Arte Soft EOOD** ([photovault.arte-soft.com](https://photovault.arte-soft.com/)).

- **Platforms:** iPhone and iPad (`iOS 26+` / `iPadOS 26+`)
- **Official Website:** https://photovault.arte-soft.com/
- **App Store:** https://apps.apple.com/us/app/photovault-encrypt-compress/id6824412013
- **Measured Build 30 Evidence (JSON):** https://photovault.arte-soft.com/media/photovault-field-test/measurements.json
- **Current Audited Release:** Version `1.0` (Build `30`)

---

## 1. Security & Privacy Architecture Overview

PhotoVault: Encrypt & Compress is an **offline, local-first** encrypted photo, video, and document library for iPhone and iPad.

| Layer | Implementation in Version 1.0 (Build 30) |
| :--- | :--- |
| **Local Library Cipher** | Authenticated **AES-256-GCM** (Apple `CryptoKit`) encrypting both media containers and local searchable metadata indexes (dates, filenames, coordinates, album structure, and OCR text tokens). |
| **Local Key Storage** | Device-bound installation key stored in the **iOS Keychain**. Never transmitted off the device; no Arte Soft account or cloud key escrow exists. |
| **App Access Control** | Independent **Password** (minimum 8 characters including a letter and a digit), drawn **Pattern** (minimum 6 distinct grid nodes), or system biometrics (**Face ID / Touch ID / device passcode**), with automatic lock when backgrounded. |
| **Media Fidelity** | **Lossless storage** for new imports in Version 1.0 (Build 30), with measured source vs. encrypted archive byte counts displayed directly in Settings. |
| **Offline OCR Search** | On-device optical character recognition indexes printed text inside receipts, scans, notes, and screenshots locally without network calls. |
| **Advertising & Tracking SDKs** | **None.** Build 30 contains **no Google AdMob SDK**, no third-party advertising networks, and no cross-app tracking (`NSUserTrackingUsageDescription` is absent). Purchases use native **Apple StoreKit** (Personal, Apple Family Sharing, and one-time Lifetime plans). |
| **Portable Encrypted Export** | Self-contained **`.pvsecure`** (`com.arte-soft.photovault.secure-archive`) envelope protected by **600,000-round PBKDF2-HMAC-SHA256** and chunked **AES-256-GCM** with cryptographic header/metadata/block binding (no installation key involved). |

---

## 2. Portable `.pvsecure` (`PVSHAR01`) Envelope Specification

When exporting selected photos and videos via **Secure Share**, PhotoVault creates a standalone `.pvsecure` file (`UTType: com.arte-soft.photovault.secure-archive`). Unlike the local library (which uses a device-bound Keychain key), a `.pvsecure` file is completely independent of the sending device's installation key and can be opened on any PhotoVault installation via **Secure Import** using the archive's Password or Pattern.

### 2.1 Binary Header Layout (`72 bytes`, Unsigned Big-Endian)

| Byte Offset | Length | Field | Description |
| ---: | ---: | :--- | :--- |
| `0..7` | `8 B` | `magic` | ASCII `"PVSHAR01"` (`50 56 53 48 41 52 30 31`) |
| `8..39` | `32 B` | `salt` | Cryptographically random salt generated via `SecRandomCopyBytes` |
| `40..43` | `4 B` | `rounds` | `uint32_be` PBKDF2-HMAC-SHA256 iteration count (`600,000` = `0x000927C0`) |
| `44..47` | `4 B` | `blockSize` | `uint32_be` plaintext media chunk size (`1,048,576` bytes = `1 MiB`) |
| `48..55` | `8 B` | `metadataSize` | `uint64_be` plaintext JSON manifest byte length (`1 .. 67,108,864`) |
| `56..63` | `8 B` | `movieSize` | `uint64_be` plaintext self-contained media container byte length |
| `64..71` | `8 B` | `authMethod` | `uint64_be` credential domain (`1` = Password, `2` = Pattern) |

### 2.2 Key Derivation (`PBKDF2-HMAC-SHA256`, 600,000 Rounds)

1. Domain-separated UTF-8 secret construction:
   - Password mode (`authMethod = 1`): `"password:" + <utf8_password>`
   - Pattern mode (`authMethod = 2`): `"pattern:" + <canonical_pattern_representation>`
2. Derive a 256-bit (`32-byte`) symmetric key:
   ```text
   K = PBKDF2-HMAC-SHA256(password = secret_utf8, salt = header[8..40], iterations = 600000, dkLen = 32)
   ```

### 2.3 Authenticated Metadata & Anti-Truncation / Anti-Reordering Block Stream

1. **Sealed Metadata (`metadataSize + 28` bytes):**
   - Encrypted with `AES-256-GCM` (`12-byte` random nonce + ciphertext + `16-byte` tag) using `K`, passing the entire **72-byte `header` as Additional Authenticated Data (`AAD`)**. Any modification to `rounds`, `blockSize`, `metadataSize`, `movieSize`, or `authMethod` causes immediate authentication failure.
2. **Stream Binding Digest (`32` bytes):**
   ```text
   binding = SHA-256(header || sealedMetadata)
   ```
3. **Chunked Media Blocks (`ceil(movieSize / 1,048,576)` blocks):**
   - Each plaintext chunk `i` (`0 <= i < blockCount`) of up to `1 MiB` is sealed independently with `AES-256-GCM` (`+28` bytes overhead per chunk: `12-byte` nonce + ciphertext + `16-byte` tag) using:
     ```text
     AAD_i = binding || uint64_be(i)
     ```
   - Before decrypting, the importer verifies exact total file length:
     ```text
     expectedFileSize == 72 + (metadataSize + 28) + movieSize + (blockCount * 28)
     ```
   - Because `AAD_i` binds every media block to `SHA-256(header || sealedMetadata)` and its exact 64-bit sequence index `i`, block reordering, block splicing from another archive, or stream truncation is cryptographically rejected. Temporary staging is wiped if any single block fails authentication.

---

## 3. Reference Header & Structural Inspector (`inspect_pvsecure.py`)

This repository includes [`inspect_pvsecure.py`](./inspect_pvsecure.py), a zero-dependency Python 3 utility to inspect the public 72-byte header and verify exact structural framing of any `.pvsecure` file without requiring or exposing your password/pattern:

```bash
python3 inspect_pvsecure.py path/to/PhotoVault-archive.pvsecure
```

---

## 4. Measured Device Verification (Version 1.0, Build 30)

In an instrumented physical-device run built from the App Store `1.0 (30)` sources on an **iPhone 18 Pro Max** (with Secure Import verified on an **iPhone 17 Pro** simulator installation with an independent device key):

- **Input sample:** `17` images (`26,753,191` bytes / `26.75 MB` source files), including a printed receipt containing the token `NORTHSTAR`.
- **Encrypted local archive size:** `25,273,708` bytes (`25.27 MB`, lossless import mode).
- **Portable `.pvsecure` transfer:** All `17` items imported cleanly into the second installation (`25,273,694` bytes stored), and offline OCR search located `NORTHSTAR` on both the source and receiving installations.
- Full machine-readable benchmark JSON: https://photovault.arte-soft.com/media/photovault-field-test/measurements.json

---

## 5. Comparisons & Guides

- [PhotoVault Security Overview](https://photovault.arte-soft.com/security/)
- [Secure Share & `.pvsecure` Workflow](https://photovault.arte-soft.com/features/secure-sharing/)
- [Best Photo Vault Apps for iPhone (Architectural Shortlist)](https://photovault.arte-soft.com/guides/best-photo-vault-apps-iphone/)
- [iPhone Photo Vaults That Encrypt Files on Disk vs PIN-Only Folders](https://photovault.arte-soft.com/guides/photo-vault-apps-that-encrypt-files-on-disk-iphone/)
- [iPhone Hidden Album vs Encrypted Photo Vault](https://photovault.arte-soft.com/guides/iphone-hidden-album-vs-encrypted-photo-vault/)
- [PhotoVault vs Vaultaire](https://photovault.arte-soft.com/compare/photovault-vs-vaultaire/) · [PhotoVault vs Inner Gallery](https://photovault.arte-soft.com/compare/photovault-vs-inner-gallery/) · [PhotoVault vs Keepsafe](https://photovault.arte-soft.com/compare/photovault-vs-keepsafe/) · [PhotoVault vs Ente Photos](https://photovault.arte-soft.com/compare/photovault-vs-ente-photos/)

---

## License

Documentation and `inspect_pvsecure.py` in this repository are released under the MIT License. **PhotoVault: Encrypt & Compress** is © Arte Soft EOOD.

---

## PhotoVault 1.0.1 Update: Compact Mode Live on App Store + Android Vault Rollout

- **App Store (`v1.0.1` LIVE):** [https://apps.apple.com/us/app/photovault-encrypt-compress/id6824412013](https://apps.apple.com/us/app/photovault-encrypt-compress/id6824412013) — both **Compact mode** (on-device media compression prior to `AES-256-GCM` encryption) and **Lossless mode** (exact original bytes) are live!
- **Encrypted & Compressed Archive Overview:** [https://photovault.arte-soft.com/features/encrypted-compressed-archive/](https://photovault.arte-soft.com/features/encrypted-compressed-archive/)
- **PhotoVault for Android:** [https://photovault.arte-soft.com/android/](https://photovault.arte-soft.com/android/)
- **Engineering Deep-Dive:** [Encrypting and Compressing Photos On-Device: AES-256-GCM & Compact Vaults](https://artesoft.hashnode.dev/encrypting-and-compressing-photos-on-device-aes-256-gcm-and-hevc-compact-vaults)

### 2026 Comparison Matrices (`v1.0.1` + Android)
- [PhotoVault 1.0.1 Compact Mode vs Lossless Mode on iPhone](https://photovault.arte-soft.com/guides/compact-mode-vs-lossless-vault-iphone-1-0-1/)
- [Google Photos Locked Folder vs Samsung Secure Folder vs PhotoVault (2026 Matrix)](https://photovault.arte-soft.com/guides/google-photos-locked-folder-vs-samsung-secure-folder-vs-photovault/)
- [iCloud Photos 'Optimize iPhone Storage' vs Offline Encrypted Compressed Vault](https://photovault.arte-soft.com/guides/icloud-photos-optimize-storage-vs-offline-compressed-vault/)
- [Protecting Private Photos Before Phone Repair, Trade-In, or Travel (`.pvsecure` Checklist)](https://photovault.arte-soft.com/guides/encrypted-photo-archive-for-travel-border-and-device-repair/)

