# 6_so_enc Usage Manual

## 1. What This Flow Is

This toolchain is not a runtime obfuscator. It is a build flow:

```text
original .py
-> encrypted staging .py
-> batch Cython compile
-> Windows: .pyd / Linux: .so
```

Main roles:

1. `encryption_helper.py`
   - scans target `.py` files
   - chooses which top-level functions or classes to protect
   - writes encrypted staging `.py`
   - can call `py2_linux_rec_opera.py` for compile
2. `decryption_helper.py`
   - provides the runtime decrypt template
3. `py2_linux_rec_opera.py`
   - batch-compiles staging trees with Cython

## 2. Verified Compatibility

Verified on `2026-04-26`:

1. Python 3.6
   - directory mode runs
   - `scope.json` with `UTF-8 BOM` runs
   - source files with `UTF-8 BOM` run
   - `--compile --dist-dir` produced importable `.pyd`
2. Python 3.11
   - same flow runs
   - current regression suite reports `12 passed`

Current Python 3.6 compile smoke result:

```text
mod1.add(2, 3) -> 15
mod1.Box(5).total() -> 15
mod2.use_it() -> 13
```

## 3. Requirements

### Python packages

Required:

```text
Python 3.6+
Cython
pycryptodome
setuptools
```

Install example:

```powershell
& 'D:\code_environment\anaconda_all_css\py36\python.exe' -m pip install Cython pycryptodome setuptools
& 'D:\code_environment\anaconda_all_css\py311\python.exe' -m pip install Cython pycryptodome setuptools
```

### Windows compile environment

To build `.pyd`, you also need:

```text
Visual Studio C++ Build Tools
Windows SDK
```

Important:

1. `encryption_helper.py` has a machine-specific default `--python-exe`.
2. `py2_linux_rec_opera.py` also has hard-coded Windows MSVC and SDK paths.

For a new machine:

1. always pass `--python-exe`
2. check these constants in `py2_linux_rec_opera.py`
   - `WINDOWS_CL_PATH`
   - `WINDOWS_RC_PATH`
   - `WINDOWS_INCLUDE`
   - `WINDOWS_LIB`

## 4. File Encoding Rules

The flow now accepts:

1. `UTF-8`
2. `UTF-8 BOM`

This applies to:

1. protected Python source files
2. `scope.json`
3. project Markdown docs

That means:

1. UTF-8 from VS Code is fine
2. BOM output from older Windows tools is also fine

## 5. Fastest Commands

### 5.1 Single-file mode

Use this when you want to protect selected top-level symbols in one file:

```powershell
& 'D:\code_environment\anaconda_all_css\py36\python.exe' .\encryption_helper.py `
  -t .\demo.py `
  -o .\demo_out `
  --function secret_add `
  --class SecretBox
```

Rules:

1. `--function` only accepts top-level function names
2. `--class` only accepts top-level class names
3. if you do not pass them, all top-level functions and classes are protected

### 5.2 Directory mode

Do not mix directory mode with `--function` or `--class`. Use `--scope-config`.

```powershell
& 'D:\code_environment\anaconda_all_css\py36\python.exe' .\encryption_helper.py `
  -t .\my_project `
  -o .\my_project_enc `
  --scope-config .\my_project\scope.json `
  --python-exe 'D:\code_environment\anaconda_all_css\py36\python.exe'
```

### 5.3 Directory mode plus compile and release output

```powershell
& 'D:\code_environment\anaconda_all_css\py36\python.exe' .\encryption_helper.py `
  -t .\my_project `
  -o .\my_project_enc `
  --scope-config .\my_project\scope.json `
  --compile `
  --dist-dir .\my_project_release `
  --python-exe 'D:\code_environment\anaconda_all_css\py36\python.exe'
```

### 5.4 Keep original package namespace while using any output folder

Use this when your source folder name and runtime namespace must be different.

Scenario:

1. source directory name is `A_py`
2. runtime/import namespace must stay `A`
3. staging physical folder can be any name, e.g. `other_enc_middle`

Command:

```powershell
& 'D:\code_environment\anaconda_all_css\py36\python.exe' .\encryption_helper.py `
  -t .\A_py `
  -o .\other_enc_middle `
  --namespace-root A `
  --scope-config .\A_py\scope.json `
  --compile `
  --dist-dir .\release_A `
  --python-exe 'D:\code_environment\anaconda_all_css\py36\python.exe'
```

Effect:

1. files are written under `other_enc_middle\A\...`
2. compiled outputs are generated under `release_A\A\...`
3. import namespace remains `A.xxx`, independent from `other_enc_middle`

### 5.5 One-switch namespace inference (A_py -> A)

If your folder naming convention is like `A_py`, you can avoid manually passing `--namespace-root A`.

Command:

```powershell
& 'D:\code_environment\anaconda_all_css\py36\python.exe' .\encryption_helper.py `
  -t .\A_py `
  -o .\other_enc_middle `
  --infer-namespace `
  --scope-config .\A_py\scope.json `
  --compile `
  --dist-dir .\release_A `
  --python-exe 'D:\code_environment\anaconda_all_css\py36\python.exe'
```

Current inference strips common suffixes:

1. `_py`, `-py`, `.py`
2. `_src`, `-src`
3. `_source`, `-source`

If inference is not what you want, pass explicit `--namespace-root`.

## 6. How `scope.json` Works

Example:

```json
{
  "pkg/mod2.py": {
    "functions": ["use_it"],
    "all": false
  },
  "pkg/mod3.py": {
    "classes": ["SecretBox"],
    "all": false
  },
  "pkg/mod4.py": {
    "all": true
  }
}
```

Meaning:

1. `pkg/mod2.py`
   - protect only `use_it`
2. `pkg/mod3.py`
   - protect only `SecretBox`
3. `pkg/mod4.py`
   - protect all top-level functions and classes

If a file is missing from `scope.json`, the default behavior is:

1. protect all top-level functions and classes in that file

## 7. Precheck, Skip, and Compile

### 7.1 Precheck only

```powershell
& 'D:\code_environment\anaconda_all_css\py36\python.exe' .\encryption_helper.py `
  -t .\my_project `
  --precheck-only `
  --python-exe 'D:\code_environment\anaconda_all_css\py36\python.exe'
```

### 7.2 Skip broken source files

```powershell
& 'D:\code_environment\anaconda_all_css\py36\python.exe' .\encryption_helper.py `
  -t .\my_project `
  -o .\my_project_enc `
  --skip-bad-files `
  --python-exe 'D:\code_environment\anaconda_all_css\py36\python.exe'
```

### 7.3 Run the batch compiler directly

```powershell
& 'D:\code_environment\anaconda_all_css\py36\python.exe' .\py2_linux_rec_opera.py .\my_project_enc
```

## 8. Output Layout

### Staging output

Typical `--output-dir`:

```text
my_project_enc/
  build_manifest.json
  pkg/
    mod1.py
    mod2.py
    enc_rt_xxxxxxxx.py
```

With `--namespace-root A`, layout becomes:

```text
other_enc_middle/
  build_manifest.json
  A/
    __init__.py
    pkg/
      mod1.py
      mod2.py
      enc_rt_xxxxxxxx.py
```

### Release output

Typical `--dist-dir`:

```text
my_project_release/
  build_manifest.json
  pkg/
    __init__.py
    mod1.pyd or mod1.so
    mod2.pyd or mod2.so
    enc_rt_xxxxxxxx.pyd or enc_rt_xxxxxxxx.so
```

## 9. Hard Rules

1. `--output-dir` must not be inside `--target`
2. `--dist-dir` must be different from `--output-dir`
3. `--dist-dir` requires `--compile`
4. `--precheck-only` cannot be combined with `--compile` or `--dist-dir`
5. directory mode must use `--scope-config`, not `--function` or `--class`
6. `--namespace-root` only supports directory targets
7. `--infer-namespace` only supports directory targets

## 10. Common Errors

### 10.1 `No module named Cython`

```powershell
& 'D:\code_environment\anaconda_all_css\py36\python.exe' -m pip install Cython
```

### 10.2 `No module named Crypto`

```powershell
& 'D:\code_environment\anaconda_all_css\py36\python.exe' -m pip install pycryptodome
```

### 10.3 `output_dir must not be inside target directory`

Cause:

1. your generated files would be scanned again on the next pass
2. the tree would contaminate itself

Correct layout:

```text
target     = .\my_project
output_dir = .\my_project_enc
```

### 10.4 Cleanup warnings after compile

If you see `warning: skip removing ...`, that usually means Windows is still holding generated `.c` or temp files.

The real success criteria are:

1. `.pyd` or `.so` exists
2. the module imports
3. the imported functions return the expected values

## 11. Recommended Handoff Order

1. run `--help`
2. run `--precheck-only`
3. run a tiny directory-mode smoke test
4. enable `--compile --dist-dir`

If you also need OCR or image transport, continue with [QRCODE_AIRGAP_MANUAL.md](/D:/Download/gaming/new_program/data_helper/6_so_enc/QRCODE_AIRGAP_MANUAL.md).
