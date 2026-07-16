# Test script for complete .data section restoration
# This tests the new approach of restoring the entire .data section

$ErrorActionPreference = "Stop"

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  Data Section Restoration Test" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Configuration
$SAMPLE = "D:\Tools\RE\dumps\runtime\testapp.exe"
$OUTPUT = "D:\Claude project\testapp_DATA_RESTORE.exe"
$MIDA_CLI = "D:\Claude project\magicmida-rs\target\release\mida-cli.exe"

# Check if sample exists
if (-not (Test-Path $SAMPLE)) {
    Write-Host "[ERROR] Sample not found: $SAMPLE" -ForegroundColor Red
    exit 1
}

# Check if mida-cli exists
if (-not (Test-Path $MIDA_CLI)) {
    Write-Host "[ERROR] mida-cli not found. Building..." -ForegroundColor Yellow
    Push-Location "D:\Claude project\magicmida-rs"

    # Try to build using build.sh (Git Bash)
    if (Test-Path "build.sh") {
        Write-Host "[INFO] Running build.sh..." -ForegroundColor Cyan
        bash build.sh
        if ($LASTEXITCODE -ne 0) {
            Write-Host "[ERROR] Build failed" -ForegroundColor Red
            Pop-Location
            exit 1
        }
    } else {
        Write-Host "[ERROR] build.sh not found" -ForegroundColor Red
        Pop-Location
        exit 1
    }

    Pop-Location

    if (-not (Test-Path $MIDA_CLI)) {
        Write-Host "[ERROR] Build succeeded but mida-cli not found" -ForegroundColor Red
        exit 1
    }
}

Write-Host "[1/3] Starting ScyllaHide..." -ForegroundColor Green
Write-Host ""

# Find x64dbg
$x64dbgPath = "D:\Tools\RE\x64dbg\x64\x64dbg.exe"
if (-not (Test-Path $x64dbgPath)) {
    Write-Host "[ERROR] x64dbg not found at: $x64dbgPath" -ForegroundColor Red
    exit 1
}

# Start x64dbg with ScyllaHide
$x64dbg = Start-Process -FilePath $x64dbgPath `
    -ArgumentList $SAMPLE `
    -PassThru `
    -WindowStyle Minimized

Write-Host "      PID: $($x64dbg.Id)" -ForegroundColor Gray
Write-Host "      Waiting for debugger to initialize (3 seconds)..." -ForegroundColor Gray
Start-Sleep -Seconds 3

Write-Host ""
Write-Host "[2/3] Running unpacker with .data section restoration..." -ForegroundColor Green
Write-Host ""

# Run mida-cli with correct syntax
Push-Location "D:\Claude project\magicmida-rs"

Write-Host "Command: $MIDA_CLI /unpack `"$SAMPLE`" --output `"$OUTPUT`" --verbose" -ForegroundColor Gray
Write-Host ""

& $MIDA_CLI /unpack $SAMPLE --output $OUTPUT --verbose

if ($LASTEXITCODE -ne 0) {
    Write-Host ""
    Write-Host "[ERROR] Unpacker failed with exit code: $LASTEXITCODE" -ForegroundColor Red

    # Kill x64dbg
    Stop-Process -Id $x64dbg.Id -Force -ErrorAction SilentlyContinue
    Pop-Location
    exit 1
}

Pop-Location

Write-Host ""
Write-Host "[3/3] Testing unpacked executable..." -ForegroundColor Green
Write-Host ""

# Kill x64dbg
Stop-Process -Id $x64dbg.Id -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 1

# Check if output was created
if (-not (Test-Path $OUTPUT)) {
    Write-Host "[ERROR] Output file not created: $OUTPUT" -ForegroundColor Red
    exit 1
}

$fileSize = (Get-Item $OUTPUT).Length
Write-Host "      Output file size: $($fileSize / 1KB) KB" -ForegroundColor Gray
Write-Host ""

# Launch the unpacked executable
Write-Host "      Launching unpacked executable..." -ForegroundColor Cyan
$unpacked = Start-Process -FilePath $OUTPUT -PassThru

Write-Host "      PID: $($unpacked.Id)" -ForegroundColor Gray
Write-Host "      Waiting 2 seconds for GUI to appear..." -ForegroundColor Gray
Start-Sleep -Seconds 2

# Check if process is still running
if ($unpacked.HasExited) {
    Write-Host ""
    Write-Host "[ERROR] Process exited immediately!" -ForegroundColor Red
    Write-Host "      Exit code: $($unpacked.ExitCode)" -ForegroundColor Gray
    exit 1
}

# Check for GUI window
$process = Get-Process -Id $unpacked.Id -ErrorAction SilentlyContinue
if ($process) {
    $hasWindow = $process.MainWindowHandle -ne 0
    $mainWindowTitle = $process.MainWindowTitle

    Write-Host ""
    if ($hasWindow) {
        Write-Host "========================================" -ForegroundColor Green
        Write-Host "  SUCCESS! GUI Window Detected!" -ForegroundColor Green
        Write-Host "========================================" -ForegroundColor Green
        Write-Host ""
        Write-Host "Window Title: $mainWindowTitle" -ForegroundColor Yellow
        Write-Host "Window Handle: 0x$($process.MainWindowHandle.ToString('X'))" -ForegroundColor Yellow
        Write-Host ""
        Write-Host "The .data section restoration approach WORKS!" -ForegroundColor Green
        Write-Host ""
    } else {
        Write-Host "[WARNING] Process running but no GUI window detected" -ForegroundColor Yellow
        Write-Host "          MainWindowHandle: $($process.MainWindowHandle)" -ForegroundColor Gray
        Write-Host "          This might be normal - check manually" -ForegroundColor Yellow
    }

    Write-Host "Press Enter to terminate the test process..." -ForegroundColor Cyan
    Read-Host

    Stop-Process -Id $unpacked.Id -Force -ErrorAction SilentlyContinue
} else {
    Write-Host ""
    Write-Host "[ERROR] Process not found or exited" -ForegroundColor Red
    exit 1
}

Write-Host ""
Write-Host "Test complete." -ForegroundColor Cyan
