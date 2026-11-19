# Test-only: load the writer exactly as setup does, then report which helpers
# exist. Loading must define everything and run no action (plan section 14).
param([string]$SourceWriter)
. $SourceWriter -LibraryOnly
$names = @('Invoke-Main', 'Test-StoreIntegrity', 'Show-Result', 'Show-Confirm')
$found = @($names | Where-Object { Test-Path ('function:' + $_) })
$security = $null -ne ('Security' -as [type])
[Console]::Out.Write((ConvertTo-Json -Compress -InputObject ([ordered]@{ functions = $found; security_class = $security })))
