# PowerShell script to run the setup evaluation framework
# Usage: .\run_evaluation.ps1 [baseline|attested] [trials]

param(
    [Parameter(Position=0)]
    [ValidateSet("baseline", "attested", "both")]
    [string]$Mode = "both",
    
    [Parameter(Position=1)]
    [int]$Trials = 3,
    
    [Parameter(Position=2)]
    [ValidateSet("public-pot", "local-crs")]
    [string]$CrsMode = "public-pot",
    
    [Parameter(Position=3)]
    [int]$N = 16,
    
    [Parameter(Position=4)]
    [int]$BatchSize = 512
)

Write-Host "🔬 Setup Evaluation Framework" -ForegroundColor Cyan
Write-Host "============================" -ForegroundColor Cyan

# Create results directory
$ResultsDir = ".\evaluation_results_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
New-Item -ItemType Directory -Path $ResultsDir -Force | Out-Null
Write-Host "📁 Results directory: $ResultsDir" -ForegroundColor Green

# Calculate threshold
$T = [math]::Floor($N / 2)

if ($Mode -eq "baseline" -or $Mode -eq "both") {
    Write-Host "🔄 Running baseline evaluation..." -ForegroundColor Yellow
    Write-Host "Parameters: n=$N, t=$T, B=$BatchSize, trials=$Trials" -ForegroundColor Gray
    
    $BaselineArgs = @(
        "run", "--bin", "setup_evaluation", "--",
        "--mode", "baseline",
        "--crs-mode", $CrsMode,
        "--n", $N,
        "--t", $T,
        "--batch-size", $BatchSize,
        "--trials", $Trials,
        "--out", "$ResultsDir\baseline"
    )
    
    & cargo $BaselineArgs
    
    if ($LASTEXITCODE -eq 0) {
        Write-Host "✅ Baseline evaluation completed successfully" -ForegroundColor Green
    } else {
        Write-Host "❌ Baseline evaluation failed with exit code $LASTEXITCODE" -ForegroundColor Red
    }
}

if ($Mode -eq "attested" -or $Mode -eq "both") {
    Write-Host "🔄 Running attested evaluation..." -ForegroundColor Yellow
    Write-Host "Parameters: n=$N, t=$T, B=$BatchSize, trials=$Trials" -ForegroundColor Gray
    
    $AttestedArgs = @(
        "run", "--bin", "setup_evaluation", "--",
        "--mode", "attested", 
        "--crs-mode", $CrsMode,
        "--n", $N,
        "--t", $T,
        "--batch-size", $BatchSize,
        "--trials", $Trials,
        "--out", "$ResultsDir\attested"
    )
    
    & cargo $AttestedArgs
    
    if ($LASTEXITCODE -eq 0) {
        Write-Host "✅ Attested evaluation completed successfully" -ForegroundColor Green
    } else {
        Write-Host "❌ Attested evaluation failed with exit code $LASTEXITCODE" -ForegroundColor Red
    }
}

Write-Host ""
Write-Host "📊 Evaluation Summary" -ForegroundColor Cyan
Write-Host "====================" -ForegroundColor Cyan
Write-Host "Mode: $Mode" -ForegroundColor Gray
Write-Host "CRS Mode: $CrsMode" -ForegroundColor Gray
Write-Host "Committee size (n): $N" -ForegroundColor Gray
Write-Host "Threshold (t): $T" -ForegroundColor Gray
Write-Host "Batch size (B): $BatchSize" -ForegroundColor Gray
Write-Host "Trials: $Trials" -ForegroundColor Gray
Write-Host "Results directory: $ResultsDir" -ForegroundColor Gray

# Check if CSV files were created
$CsvFiles = Get-ChildItem -Path $ResultsDir -Filter "*.csv" -Recurse
if ($CsvFiles.Count -gt 0) {
    Write-Host ""
    Write-Host "📋 Generated CSV files:" -ForegroundColor Green
    foreach ($File in $CsvFiles) {
        Write-Host "  - $($File.FullName)" -ForegroundColor Gray
    }
} else {
    Write-Host ""
    Write-Host "⚠️  No CSV files found in results directory" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "🎉 Evaluation framework execution completed!" -ForegroundColor Green
