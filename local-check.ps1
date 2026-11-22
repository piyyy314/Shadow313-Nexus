$ErrorActionPreference = "Continue"
$Root = $PSScriptRoot
if (-not $Root) { $Root = (Get-Location).Path }
Set-Location $Root

Write-Host "== Local repository checks =="
Write-Host "Repository: $Root"

$SyntaxStatus = "SKIPPED"
$TestStatus = "SKIPPED"
$AuditStatus = "SKIPPED"

$Python = Get-Command python -ErrorAction SilentlyContinue
if (-not $Python) {
    $Python = Get-Command py -ErrorAction SilentlyContinue
}

if (-not $Python) {
    Write-Host "`nERROR: Python was not found. Install Python 3 and try again." -ForegroundColor Red
    exit 1
}

$PythonCommand = $Python.Source
$PythonArgs = @()
if ($Python.Name -eq "py.exe") { $PythonArgs = @("-3") }

function Get-PythonModuleProbeExitCode {
    param([string]$ModuleName)

    & $PythonCommand @PythonArgs -c "import importlib.util, sys; sys.exit(0 if importlib.util.find_spec('$ModuleName') else 2)"
    return $LASTEXITCODE
}

Write-Host "`n== Python syntax check =="
& $PythonCommand @PythonArgs -m compileall -q .
if ($LASTEXITCODE -eq 0) {
    $SyntaxStatus = "PASS"
    Write-Host "PASS: Python files compile." -ForegroundColor Green
} else {
    $SyntaxStatus = "FAIL"
    Write-Host "FAIL: Python syntax errors found." -ForegroundColor Red
}

Write-Host "`n== Tests =="
$HasTests = (Test-Path ".\tests") -or (Test-Path ".\pytest.ini") -or (Test-Path ".\pyproject.toml")
if ($HasTests) {
    $PytestProbeExitCode = Get-PythonModuleProbeExitCode "pytest"
    if ($PytestProbeExitCode -eq 0) {
        & $PythonCommand @PythonArgs -m pytest --version
        if ($LASTEXITCODE -ne 0) {
            $TestStatus = "FAIL"
            Write-Host "FAIL: pytest failed during startup." -ForegroundColor Red
        } else {
            & $PythonCommand @PythonArgs -m pytest -q
            if ($LASTEXITCODE -eq 0) {
                $TestStatus = "PASS"
                Write-Host "PASS: Tests completed." -ForegroundColor Green
            } else {
                $TestStatus = "FAIL"
                Write-Host "FAIL: Tests reported errors." -ForegroundColor Red
            }
        }
    } elseif ($PytestProbeExitCode -eq 2) {
        Write-Host "SKIPPED: pytest isn't installed. Install the repo's development dependencies to run tests."
    } else {
        $TestStatus = "FAIL"
        Write-Host "FAIL: Could not determine whether pytest is installed." -ForegroundColor Red
    }
} else {
    Write-Host "SKIPPED: No obvious pytest configuration or tests folder found."
}

Write-Host "`n== Dependency vulnerability check =="
$AuditProbeExitCode = Get-PythonModuleProbeExitCode "pip_audit"
if ($AuditProbeExitCode -eq 0) {
    & $PythonCommand @PythonArgs -m pip_audit --version
    if ($LASTEXITCODE -ne 0) {
        $AuditStatus = "FAIL"
        Write-Host "FAIL: pip-audit failed during startup." -ForegroundColor Red
    } else {
        & $PythonCommand @PythonArgs -m pip_audit
        if ($LASTEXITCODE -eq 0) {
            $AuditStatus = "PASS"
            Write-Host "PASS: Dependency audit completed." -ForegroundColor Green
        } else {
            $AuditStatus = "FAIL"
            Write-Host "FAIL: Audit found issues or could not complete." -ForegroundColor Red
        }
    }
} elseif ($AuditProbeExitCode -eq 2) {
    Write-Host "SKIPPED: pip-audit isn't installed. Optional install: python -m pip install pip-audit"
} else {
    $AuditStatus = "FAIL"
    Write-Host "FAIL: Could not determine whether pip-audit is installed." -ForegroundColor Red
}

Write-Host "`n== Summary =="
Write-Host "Syntax: $SyntaxStatus"
Write-Host "Tests: $TestStatus"
Write-Host "Dependency audit: $AuditStatus"

if ($SyntaxStatus -eq "FAIL" -or $TestStatus -eq "FAIL" -or $AuditStatus -eq "FAIL") {
    exit 1
}
