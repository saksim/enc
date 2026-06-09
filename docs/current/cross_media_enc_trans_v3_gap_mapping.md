# Cross-media V0.3 gap mapping

> Source blueprint: `docs/current/cross_media_enc_trans_imple_guide_v3.md`  
> Mapping date: 2026-06-09  
> Current pass update: P0-B2 smoke script and blocked-state evidence.  
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
| P0-B0 Code Protection Layer registration | `encryption_helper.py`, `decryption_helper.py`, `py2_linux_rec_opera.py` now have explicit V0.3 Code Protection Layer boundary comments. | Done | Keep responsibilities documented separately from QR/OCR/SOX1. |
| P0-B1 protect/build and cm/transport decoupling | `cm` and `transport` help paths stay decoupled from code-protection heavy imports; covered by CLI regression tests. | Done | Keep config/toolchain imports behind protect/build handlers. |
| P0-B2 code-protection smoke | `scripts/smoke_code_protection.py` now creates `demo_module.py`, runs `soenc.py protect`, probes native deps, runs `soenc.py build` when possible, then imports native artifacts from a clean directory. | Script added; strict native proof currently blocked on this host | Fix native build environment (`setuptools`/`backports.tarfile` conflict and missing `Cython`) or run on a prepared native-build host. |
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

## 5. P0-B2 smoke contract

`scripts/smoke_code_protection.py` is the V0.3 Code Protection Layer smoke entry:

```text
original .py -> protected staging -> .so/.pyd -> clean import -> behavior match
```

The smoke intentionally has two modes:

```text
strict mode:
  python scripts/smoke_code_protection.py
  returns non-zero if native packaging cannot be proven

evidence mode for non-build hosts:
  python scripts/smoke_code_protection.py --allow-blocked
  returns zero only to record a BLOCKED diagnostic report
```

Current host evidence:

```text
protect step: passed
native dependency probe: blocked
missing/broken: setuptools, Cython
setuptools error: ImportError importing backports.tarfile from the current Python environment
```

The script does not modify QR/OCR/SOX1 behavior and does not add release,
promotion, or evidence-platform capability.

## 6. Next recommended pass

After the native build environment is available, rerun:

```text
python scripts/smoke_code_protection.py
```

Only after strict P0-B2 passes should the next implementation target be:

```text
P0-B3: dist no-source-leakage
P0-B4: local-embedded explicit insecure marker
```
