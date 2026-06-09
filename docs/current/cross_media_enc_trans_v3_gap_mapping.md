# Cross-media V0.3 gap mapping

> Source blueprint: `docs/current/cross_media_enc_trans_imple_guide_v3.md`  
> Mapping date: 2026-06-09  
> Scope for this pass: gap mapping plus P0-B0/B1 only.  
> Explicitly out of scope: QR/OCR/SOX1 behavior changes and release/promotion/evidence expansion.

## 1. Current state summary

The repository already has a working cross-media product path under
`enc2sop/crossmedia/`:

```text
bytes
  -> SOX1 encrypted string
  -> QR pages/photos
  -> recovered SOX1
  -> decrypted bytes
```

The V0.3 blueprint is still valid, but its phase order must be interpreted
against the current codebase: most P0-A items are already implemented, while the
next unfinished area is the Code Protection Layer registration and dependency
boundary.

## 2. V0.3 phase mapping

| V0.3 item | Current evidence | Status | Next action |
|---|---|---:|---|
| P0-A0 CLI decoupling | `soenc.py cm --help` delegates lazily through `enc2sop.cli._run_cross_media`; `soenc.py transport --help` uses legacy plugin surface. | Mostly done | Keep protected/build deps out of `cm` and `transport` startup. |
| P0-A1 SOX1 envelope | `enc2sop/crossmedia/crypto_envelope.py` | Done | No change in this pass. |
| P0-A2 QR-first render/scan | `enc2sop/crossmedia/qr_transport.py`, `enc2sop/crossmedia/image_scan.py` | Done | No change in this pass. |
| P0-A3 send/receive | `enc2sop/crossmedia/cli.py` exposes `send` and `receive`. | Done | No change in this pass. |
| P0-A4 scan report / retake plan | Existing QR reassembly and receive reports include missing/bad image diagnostics. | Done enough for current pass | No change in this pass. |
| P0-A5 no-secret-leakage | Covered by existing cross-media tests and manifest/report fields. | Mostly done | Dedicated no-secret-leakage test file can be added later if desired. |
| P0-A6 crossmedia smoke | `scripts/crossmedia_smoke.ps1`, `scripts/crossmedia_smoke.sh`, simulated capture script. | Done | Linux/macOS real shell execution remains environment validation. |
| P0-B0 Code Protection Layer registration | `encryption_helper.py`, `decryption_helper.py`, `py2_linux_rec_opera.py` existed but lacked explicit V0.3 boundary comments. | This pass | Add explicit responsibility and non-goal comments. |
| P0-B1 protect/build and cm/transport decoupling | `encryption_helper` is already lazy-loaded for protect/build/package/verify/release handlers; parser still imported build config/toolchain helpers before this pass. | This pass | Keep config/toolchain imports behind build handlers; assert help remains lightweight. |
| P0-B2 code-protection smoke | Not part of current requested scope. | Pending | Future pass only. |
| P0-B3 dist no-source-leakage | Not part of current requested scope. | Pending | Future pass only. |
| P0-B4 local-embedded insecure marker | Not part of current requested scope. | Pending | Future pass only. |
| P0-B5 license-file externalization | Existing runtime supports license-file concepts; full policy hardening is not in current scope. | Pending | Future pass only. |
| P0-B6 runtime integrity smoke | Existing runtime/build manifests have integrity concepts; dedicated smoke is not in current scope. | Pending | Future pass only. |

## 3. P0-B0 Code Protection Layer registration

The Code Protection Layer is defined as:

```text
encryption_helper.py
  Owns source selection, snippet encryption, protected staging generation,
  build manifests, and package/release integrity helpers.

decryption_helper.py
  Owns protected-module runtime payload decryption, compile/exec injection,
  license-file lookup, and runtime integrity checks.

py2_linux_rec_opera.py
  Owns Cython/native packaging of protected staging into .so/.pyd artifacts.
```

Non-goals and boundaries:

```text
These files are not OCR/QR scanners.
These files are not SOX1 cross-media recovery.
These files do not replace SOX1 data encryption.
Cython/.so/.pyd raises reverse-engineering cost only and is not absolute secrecy.
cm/transport help and startup must not import these files.
```

## 4. P0-B1 dependency boundary

Allowed import direction:

```text
protect/build/package/verify/release -> encryption_helper/decryption_helper/py2_linux_rec_opera/toolchain_profile
cm/send/receive/help                 -> enc2sop.crossmedia only
transport/help                       -> plugin registry only
transport subcommands                -> legacy transport plugin when actually invoked
```

Forbidden for help/startup:

```text
soenc cm --help must not import encryption_helper, decryption_helper, py2_linux_rec_opera, or promotion modules.
soenc transport --help must not import encryption_helper, decryption_helper, py2_linux_rec_opera, Cython, or native build helpers.
```

## 5. Next recommended pass

After this P0-B0/B1 pass, continue with:

```text
P0-B2: code-protection smoke
```

Do not start P0-B3/B4 until the smoke proves:

```text
original .py -> protected staging -> .so/.pyd -> import -> behavior matches
```
