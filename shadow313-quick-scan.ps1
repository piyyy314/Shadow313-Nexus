# SHADOW313 Quick System Scan — paste directly into PowerShell
$ts = Get-Date -Format "yyyy-MM-dd_HH-mm"
$out = "$env:USERPROFILE\Desktop\QUICK-SCAN-$ts.txt"
$csv = "$env:USERPROFILE\Desktop\QUICK-SCAN-$ts.csv"
$results = [System.Collections.Generic.List[PSCustomObject]]::new()
$kw = @("shadow313","Shadow313","nexus","NEXUS","s313","aegis","vsat","ghost","nvsm","ollama","matarmohamad","baalbek","piyyy314")
$roots = @($env:USERPROFILE,"C:\OneDrive","C:\Users\shiatoali")
Write-Host "Scanning..." -ForegroundColor Cyan
$n=0
foreach($root in $roots){
  if(-not(Test-Path $root)){continue}
  Get-ChildItem -Path $root -Recurse -File -Force -ErrorAction SilentlyContinue | ForEach-Object {
    $n++; if($n%500-eq 0){Write-Host "  $n files..." -ForegroundColor Gray}
    $match=$false; foreach($k in $kw){if($_.Name -match $k -or $_.DirectoryName -match $k){$match=$true;break}}
    if($match){$results.Add([PSCustomObject]@{Name=$_.Name;SizeKB=[math]::Round($_.Length/1KB,1);Path=$_.FullName;Dir=$_.DirectoryName;Modified=$_.LastWriteTime.ToString("yyyy-MM-dd HH:mm");Ext=$_.Extension})}
  }
}
$results | Export-Csv $csv -NoTypeInformation -Encoding UTF8
$lines = @("SHADOW313 QUICK SCAN — $(Get-Date)","Total scanned: $n","Shadow313 files: $($results.Count)","","BY LOCATION:")
$results | Group-Object Dir | Sort-Object Count -Descending | ForEach-Object { $lines += "  $($_.Count) files — $($_.Name)" }
$lines += "","ALL FILES:"
$results | Sort-Object Dir,Name | ForEach-Object { $lines += "  $($_.Modified)  $($_.SizeKB)KB  $($_.Path)" }
$lines | Out-File $out -Encoding UTF8
Write-Host "Done! $($results.Count) Shadow313 files found across $n total files" -ForegroundColor Green
Write-Host "Report: $out" -ForegroundColor White
Write-Host "CSV:    $csv" -ForegroundColor White
