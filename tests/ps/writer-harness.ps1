# Test-only harness: loads grant-writer.ps1 as a library and runs one of its
# read-only validate actions for many inputs in a single PowerShell process
# (starting PowerShell once per fixture would take minutes).
#
# Each line of -ListFile is: <action>|<file>|<now>|<user>
# Output: one JSON line per input, exactly what the action itself prints.
# Never shipped and never run elevated.
param([string]$Writer, [string]$ListFile)

. $Writer -LibraryOnly

foreach ($entry in [System.IO.File]::ReadAllLines($ListFile)) {
    if ($entry.Length -eq 0) { continue }
    $parts = $entry.Split('|')
    # These names are the writer's own parameters; its functions read them.
    $Now = $parts[2]
    $ForUser = $parts[3]
    if ($parts[0] -ceq 'validate-request') {
        $RequestFile = $parts[1]
        [void](Invoke-ValidateRequest)
    } elseif ($parts[0] -ceq 'validate-file') {
        $GrantsFile = $parts[1]
        [void](Invoke-ValidateFile)
    } elseif ($parts[0] -ceq 'validate-roundtrip') {
        $RequestFile = $parts[1]
        [void](Invoke-ValidateRoundTrip)
    } else {
        throw "unknown harness action $($parts[0])"
    }
}
