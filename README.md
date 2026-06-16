# CAN XL — Session Key Distribution

A C++ model of **Phase 1 (Key Distribution)** of a CAN XL in-vehicle security
architecture. A *Master ECU* generates key-derivation parameters, every ECU
independently derives the **same session key `K_S`** from a shared master key
`K_M`, proves it without ever sending `K_S`, and the Master tracks, retries, and
finally confirms the whole fleet.

> Builds & runs on **macOS** and inside the **Linux dev container**. 22 unit tests, both environments green.

---

## How it works (step by step)

```mermaid
sequenceDiagram
    participant M as Master ECU
    participant E as ECU
    M->>M: 1. derive own K_S
    M->>E: 2. distribute params (mark ECU "waiting")
    M->>M: 3. start Twait timer
    E->>E: 4. derive the SAME K_S
    E->>M: 5. ACK = proof tag (K_S never sent)
    M->>M: 6. verify tag + freshness → confirm ECU
    Note over M: timeout? → retry missing ECUs (max 3) → abort
    M->>E: 7. all confirmed → fire callback
```

| # | What happens | Function in this code |
|---|--------------|-----------------------|
| 1 | Master derives its own `K_S` | `setNonce()` + `calculateSessionKeyKBKDF()` |
| 2 | Master sends params to each ECU | `markDataSent(ecuId)` → state `WAITING_THE_RESPONSE` |
| 3 | Master starts the wait timer | `SessionKeysInputsAreSent()` |
| 4 | Each ECU derives the **same** `K_S` | `calculateSessionKeyKBKDF()` |
| 5 | ECU builds an ACK proof tag | `calculateSessionKeyTag(ecuId, nonce)` |
| 6 | Master verifies tag + freshness, confirms ECU | `markResponseReceived(ecuId, tag, nonce)` → `checkSessionKeyIsCorrect()` |
| — | Missing ECU on timeout → resend (≤ 3) → abort | `checkECUs()` → `resentTheMessage()` |
| 7 | All ECUs confirmed → notify the app | `setOnAllConfirmed()` → `allConfirmed()` |

Each ECU's status lives in a tracking table (`std::map<ECU_ID, ECUMode>`) moving
through: `INITIAL_STATE → WAITING_THE_RESPONSE → RECEIVED_THE_RESPONSE`
(or `RESENT_THE_INPUTS` while retrying).

---

## Key derivation: KBKDF & HKDF

The session key is a pure function of the inputs, so **every ECU derives the
identical key** (no per-instance randomness):

```
K_S = KDF( K_M , Label , Context )      Context = ECU_ID ‖ Counter (nonce)
```

Two interchangeable algorithms are provided:

| KDF | Standard | Primitive | Role |
|-----|----------|-----------|------|
| **KBKDF** | NIST SP 800-108 (Counter mode) | CMAC-AES | **default** |
| **HKDF**  | RFC 5869 | HMAC-SHA256 | alternative |

A fresh **Counter** in the nonce yields a fresh `K_S` each session (forward
secrecy); the same Counter always yields the same key (so ECUs agree).

---

## Security notes

- **Key confirmation** — an ECU proves it derived the right key by sending
  `HMAC(K_S, ECU_ID ‖ SHA256(K_S) ‖ nonce)` truncated to 64 bits. `K_S` never
  travels on the bus; the Master re-computes the tag and compares.
- **Replay protection** — the Master keeps the highest accepted nonce counter
  per ECU (`last_nonce_counter`) and rejects any counter `≤` it.
- **⏱ Timing-attack safe** — tags are compared with **`CRYPTO_memcmp`**, not
  `==`. A normal compare returns early on the first differing byte, leaking
  timing an attacker could exploit; `CRYPTO_memcmp` takes constant time
  regardless of where (or whether) the bytes differ.

---

## Build & run

```bash
# macOS
cmake --preset vscode && cmake --build --preset vscode
./build/cankeydist          # demo
ctest --preset vscode       # tests

# Linux / dev container
cmake --preset container && cmake --build --preset container
./build-linux/cankeydist
ctest --preset container
```

Requires **OpenSSL ≥ 3.0** (for the `EVP_KDF` KBKDF/HKDF API) and CMake ≥ 3.20.

---

## Benchmarks

Timed with `std::chrono::steady_clock`. Each operation runs in a batch of tens
of thousands of calls (with warm-up), and the whole batch is **repeated 20×** so
the charts can show **min / mean / max** — capturing system-level jitter
(frequency scaling, scheduling), not just a single average. Numbers are from a
desktop CPU with AES-NI: **relative** and **scaling** results are meaningful;
absolute `Tcomp` would have to be measured on the target HSM.

**Per-operation cost** — each crypto step measured separately:

![Per-operation cost](docs/images/operations.png)

**Tcomp (one ECU's work = KDF + HMAC tag)** — KBKDF is the default and also the
cheaper KDF here:

![KBKDF vs HKDF](docs/images/tcomp.png)

**Scaling with N** — the Master's cost grows linearly (`O(N)`); worst case
(≤ 3 retries per ECU) is ~4× best case:

![Scaling with N](docs/images/scaling.png)

Reproduce:

```bash
cmake -S . -B build-release -DCMAKE_BUILD_TYPE=Release -G Ninja
cmake --build build-release
./build-release/cankeydist_bench_ops       --csv > docs/data/operations.csv
./build-release/cankeydist_bench_scenarios --csv > docs/data/scenarios.csv
python3 scripts/plot_benchmarks.py          # writes docs/images/*.png
```
