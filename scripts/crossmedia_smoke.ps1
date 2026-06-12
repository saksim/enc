$ErrorActionPreference = 'Stop'

$root = (Resolve-Path -LiteralPath '.').Path
if ($env:SOENC_CM_SMOKE_WORK) {
    $work = $env:SOENC_CM_SMOKE_WORK
} else {
    $suffix = "{0}_{1}" -f ([DateTime]::UtcNow.ToString('yyyyMMddHHmmss')), ([System.Guid]::NewGuid().ToString('N').Substring(0, 8))
    $work = Join-Path $root ".tmp_crossmedia_smoke_$suffix"
}

function Assert-LastExitCode {
    param(
        [Parameter(Mandatory = $true)][string]$Step
    )
    if ($LASTEXITCODE -ne 0) {
        throw "$Step failed with exit code $LASTEXITCODE"
    }
}

function Assert-AllowedChild {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string[]]$Roots
    )
    $resolvedPath = (Resolve-Path -LiteralPath $Path).Path
    foreach ($allowedRoot in $Roots) {
        $rootWithSep = $allowedRoot
        if (-not $rootWithSep.EndsWith([System.IO.Path]::DirectorySeparatorChar)) {
            $rootWithSep = $rootWithSep + [System.IO.Path]::DirectorySeparatorChar
        }
        if ($resolvedPath.StartsWith($rootWithSep, [System.StringComparison]::OrdinalIgnoreCase)) {
            return $resolvedPath
        }
    }
    throw "refuse to operate outside allowed smoke roots: $resolvedPath"
}

$allowedRoots = @($root)

if ($env:SOENC_CM_SMOKE_WORK -and (Test-Path -LiteralPath $work)) {
    $resolvedWork = Assert-AllowedChild -Path $work -Roots $allowedRoots
    try {
        Remove-Item -LiteralPath $resolvedWork -Recurse -Force
    } catch {
        $suffix = [DateTime]::UtcNow.ToString('yyyyMMddHHmmss')
        $work = Join-Path $root ".tmp_crossmedia_smoke_$suffix"
        Write-Warning "Could not clean previous smoke directory; using $work. Cause: $($_.Exception.Message)"
    }
}
New-Item -ItemType Directory -Path $work -Force | Out-Null

$keyFile = Join-Path $work 'key.bin'
$plainFile = Join-Path $work 'plain.txt'
$sendDir = Join-Path $work 'send'
$photosDir = Join-Path $work 'photos'
$receiveDir = Join-Path $work 'receive'
$restoredFile = Join-Path $work 'restored.txt'

python soenc.py cm keygen --key-file "$keyFile"
Assert-LastExitCode -Step 'cm keygen'

$utf8NoBom = New-Object System.Text.UTF8Encoding($false)
[System.IO.File]::WriteAllText($plainFile, 'hello cross media encrypted transport', $utf8NoBom)

python soenc.py cm send `
    --input "$plainFile" `
    --key-file "$keyFile" `
    --output-dir "$sendDir" `
    --mode qr
Assert-LastExitCode -Step 'cm send'

python scripts/simulate_capture_distortions.py `
    --input "$sendDir/pages" `
    --output "$photosDir" `
    --jpeg-quality 85 `
    --rotate-deg 1.0
Assert-LastExitCode -Step 'simulate capture'

python soenc.py cm receive `
    --image-input "$photosDir" `
    --key-file "$keyFile" `
    --output "$restoredFile" `
    --work-dir "$receiveDir"
Assert-LastExitCode -Step 'cm receive'

$plainHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $plainFile).Hash
$restoredHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $restoredFile).Hash
if ($plainHash -ne $restoredHash) {
    throw "SHA256 mismatch: plain=$plainHash restored=$restoredHash"
}

Write-Host "sha256=$plainHash"
Write-Host 'CROSSMEDIA_SMOKE_OK'
