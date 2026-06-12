<#
.SYNOPSIS
Run the non-OCR Mainline Beta gate from docs/current/non_ocr_code_protection_launch_strategy_20260612.md.

.DESCRIPTION
This script intentionally excludes OCR / cross-media tests. It verifies the code
protection line: protect/build/package/verify/release, promotion governance,
strict native smoke, runtime integrity smoke, dist no-source-leak, key providers,
and hardening defaults.
#>
[CmdletBinding()]
param(
    [string]$Python = "python",
    [string]$NativePython = "",
    [switch]$SkipStrictNativeSmoke
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$scriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot = Resolve-Path (Join-Path $scriptRoot "..")

function Invoke-MainlineStep {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][scriptblock]$ScriptBlock
    )
    Write-Host "==> $Name"
    & $ScriptBlock
    if ($LASTEXITCODE -ne 0) {
        throw "$Name failed with exit code $LASTEXITCODE"
    }
}

$nonOcrTests = @(
    "tests\test_encryption_helper.py",
    "tests\test_decryption_helper.py",
    "tests\test_key_provider.py",
    "tests\test_soenc_config.py",
    "tests\test_soenc_cli.py",
    "tests\test_toolchain_profile.py",
    "tests\test_dist_no_source_leakage.py",
    "tests\test_protect_hardening.py",
    "tests\test_runtime_integrity_smoke.py",
    "tests\test_code_protection_smoke.py",
    "tests\test_promotion_bundle.py",
    "tests\test_promotion_artifacts.py",
    "tests\test_release_promotion_workflow.py",
    "tests\test_non_ocr_release_gate.py",
    "tests\test_promotion_evidence.py"
)

Push-Location $repoRoot
try {
    Invoke-MainlineStep "non-OCR mainline pytest" {
        & $Python -B -m pytest -q @nonOcrTests
    }

    if (-not $SkipStrictNativeSmoke) {
        $nativePythonToUse = $NativePython
        $defaultNativePython = "D:\code_environment\anaconda_all_css\py312\python.exe"
        if ([string]::IsNullOrWhiteSpace($nativePythonToUse)) {
            if (Test-Path -LiteralPath $defaultNativePython) {
                $nativePythonToUse = $defaultNativePython
            }
            else {
                $nativePythonToUse = $Python
                Write-Warning "Default native Python not found; falling back to '$Python'. Pass -NativePython for strict parity."
            }
        }
        Invoke-MainlineStep "strict native code protection smoke" {
            & $nativePythonToUse -B "scripts\smoke_code_protection.py" --python-exe $nativePythonToUse
        }
    }

    Invoke-MainlineStep "runtime integrity smoke" {
        & $Python -B "scripts\smoke_runtime_integrity.py"
    }

    Invoke-MainlineStep "non-OCR release gate config-only" {
        & $Python -B "scripts\non_ocr_release_gate.py" --config "soenc.production.toml" --config-only
    }

    Write-Host "MAINLINE_BETA_SMOKE_OK"
}
finally {
    Pop-Location
}
