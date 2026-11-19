# Test-only: run the writer's real Write-GrantsAtomically in a temp folder.
# Setting admin-only permissions needs elevation, so that step and the
# integrity re-check are replaced; the temp-file write and File.Replace swap
# are the real code. Never touches ProgramData, never elevates.
param([string]$Writer, [string]$Target)

. $Writer -LibraryOnly

function Set-ProtectedFileSecurity([string]$path) { }
function Test-StoreIntegrity([string]$grantsPath, [string]$writerPath) {
    return ,[System.Collections.Generic.List[string]]::new()
}
function Show-Result([int]$code, [string]$message) { $script:message = $message; return $code }

$old = [System.IO.File]::ReadAllBytes($Target)
$new = [System.Text.Encoding]::UTF8.GetBytes("line one`nline two`n")
$code = Write-GrantsAtomically $Target $old $new
$out = [ordered]@{ code = $code; message = $script:message }
[Console]::Out.Write((ConvertTo-Json -Compress -InputObject $out))
