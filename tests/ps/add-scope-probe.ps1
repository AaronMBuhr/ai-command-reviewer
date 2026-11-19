# Test-only (review CODE-003): run the writer's real Invoke-Add with the store,
# clipboard, dialog and write replaced by stand-ins, and with a repo-root lookup
# that returns a different root every time it is called. The grant written must
# carry exactly the scope the dialog last showed.
#
# Nothing is elevated, no window opens, and no real store is touched.
param([string]$Writer, [string]$Cwd, [string]$Choice)

. $Writer -LibraryOnly

$ForUser = 'S-1-5-21-1-2-3-1001'
$script:rootCalls = 0
$script:shown = $null
$script:written = $null

# Every call answers with a different (ever wider-looking) root.
function Get-RepoRoot([string]$cwd) {
    $script:rootCalls++
    return 'C:\root-' + $script:rootCalls
}

function Open-Store([string]$grantsPath, $state) { $state['bytes'] = [byte[]]@(); return 0 }

function Get-ClipboardRequestText {
    $request = [ordered]@{ v = 1; name = 'probe'; commands = @('git push'); tool = 'Bash'; where = 'repo';
                           cwd = $Cwd; hosts = $null; expires = '30m'; why = '' }
    return (ConvertTo-Json -Compress -InputObject $request)
}

# Shows nothing; records what would be displayed. When the test asks for a
# different expiry, it simulates the user changing the box, which regenerates
# the text exactly as the real dialog's event handler does.
function Show-Confirm([string]$title, [string]$header, [string]$text, $expiryContext) {
    $script:shown = $text
    if ($Choice -cne $expiryContext['initial']) {
        $script:shown = Get-ExpiryDescription $expiryContext $Choice
    }
    return $Choice
}

function Write-GrantsAtomically([string]$grantsPath, [byte[]]$oldBytes, [byte[]]$newBytes) {
    $script:written = [System.Text.Encoding]::UTF8.GetString($newBytes)
    return 0
}

function Show-Result([int]$code, [string]$message) { return $code }

$code = Invoke-Add 'C:\not-used\grants.jsonl'
$out = [ordered]@{ code = $code; root_calls = $script:rootCalls; shown = $script:shown; written = $script:written }
[Console]::Out.Write((ConvertTo-Json -Compress -InputObject $out))
