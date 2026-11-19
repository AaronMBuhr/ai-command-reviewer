param([switch]$Reset, [string]$SourceWriter, [string]$ProgramData,
      [switch]$PlanOnly, [switch]$PlanFolderExists, [switch]$PlanIntegrityOk,
      [string]$PlanNow, [string]$PlanExisting)
$ErrorActionPreference = 'Stop'   # a variable assignment, not a cmdlet

# Exception-grant setup, update and reset (design section 5, plan section 8).
#
# This is the one declared installer exception (design 1.2): the user runs it
# elevated through `aiallow setup` to create or update the protected store at
# <ProgramData>\cc-ai-review. It follows the writer's rules: no cmdlets, .NET
# calls only. It reuses the writer's helpers by dot-sourcing the installed
# source copy with -LibraryOnly (the only import tests/ps/check-no-cmdlets.ps1
# allows), so the integrity rule is the same code in both.
#
# Dot-sourcing shares this script's scope, so no parameter or function name
# here may also exist in grant-writer.ps1 (a test checks this).

# The folder's permissions: owner Administrators; protected; full control for
# Administrators and SYSTEM; read-and-execute for Users; inherited inside.
$SetupFolderSddl = 'O:BAD:PAI(A;OICI;FA;;;BA)(A;OICI;FA;;;SY)(A;OICI;0x1200a9;;;BU)'

# Decide what setup does, from inspected (or, for tests, supplied) state.
# Pure: no filesystem, no clock, no UI.
function Get-SetupPlan([bool]$folderExists, [bool]$integrityOk, [bool]$reset,
                       [string[]]$existingNames, [DateTime]$now) {
    $plan = [System.Collections.Specialized.OrderedDictionary]::new([System.StringComparer]::Ordinal)
    $plan['action'] = 'fresh'
    $plan['backup_name'] = $null
    if ($folderExists -and $reset) {
        $plan['action'] = 'reset'
        $taken = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        foreach ($existing in $existingNames) { [void]$taken.Add($existing) }
        $base = 'cc-ai-review.old-' + $now.ToString("yyyyMMdd'T'HHmmss'Z'", [System.Globalization.CultureInfo]::InvariantCulture)
        $candidate = $base
        $n = 2
        while ($taken.Contains($candidate)) { $candidate = $base + '-' + $n; $n++ }
        $plan['backup_name'] = $candidate
    } elseif ($folderExists -and $integrityOk) {
        $plan['action'] = 'update'
    } elseif ($folderExists) {
        $plan['action'] = 'refuse'
    }
    return ,$plan
}

function Format-SetupPlan($plan) {
    $backup = 'null'
    if ($null -ne $plan['backup_name']) { $backup = '"' + $plan['backup_name'] + '"' }
    return '{"action":"' + $plan['action'] + '","backup_name":' + $backup + '}'
}

function Set-SetupFileSecurity([string]$path) {
    $security = [System.Security.AccessControl.FileSecurity]::new()
    $security.SetSecurityDescriptorSddlForm('O:BAD:PAI(A;;FA;;;BA)(A;;FA;;;SY)(A;;0x1200a9;;;BU)')
    [System.IO.File]::SetAccessControl($path, $security)
}

function Install-SetupFresh([string]$folder, [string]$source) {
    $security = [System.Security.AccessControl.DirectorySecurity]::new()
    $security.SetSecurityDescriptorSddlForm($SetupFolderSddl)
    [void][System.IO.Directory]::CreateDirectory($folder, $security)
    $grants = [System.IO.Path]::Combine($folder, 'grants.jsonl')
    [System.IO.File]::WriteAllBytes($grants, [byte[]]@())
    Set-SetupFileSecurity $grants
    $writer = [System.IO.Path]::Combine($folder, 'grant-writer.ps1')
    [System.IO.File]::Copy($source, $writer, $false)
    Set-SetupFileSecurity $writer
}

function Install-SetupUpdate([string]$folder, [string]$source) {
    $writer = [System.IO.Path]::Combine($folder, 'grant-writer.ps1')
    $staged = $writer + '.new'
    [System.IO.File]::Copy($source, $staged, $true)
    Set-SetupFileSecurity $staged
    [System.IO.File]::Replace($staged, $writer, $null)
    Set-SetupFileSecurity $writer
}

function Invoke-Setup([string]$source, [string]$programData, [bool]$reset) {
    $mutex = $null
    $owned = $false
    try {
        try {
            $created = $false
            $mutex = [System.Threading.Mutex]::new($false, 'Global\cc-ai-review-grants', [ref]$created)
        } catch [System.UnauthorizedAccessException] {
            return (Show-Result 41 'The grant lock exists but access to it is denied. Nothing was changed.')
        } catch [System.Threading.WaitHandleCannotBeOpenedException] {
            return (Show-Result 41 'The grant lock name is used by another kind of object. Nothing was changed.')
        }
        try { $owned = $mutex.WaitOne(0) }
        catch [System.Threading.AbandonedMutexException] { $owned = $true }
        if (-not $owned) { return (Show-Result 40 'A grant window is open. Close it and run setup again.') }

        # Cross-check the folder aiallow passed with our own lookup, without
        # trusting environment variables (plan A15).
        $own = [Environment]::GetFolderPath('CommonApplicationData').TrimEnd('\')
        if (-not [string]::Equals($own, $programData.TrimEnd('\'), [System.StringComparison]::OrdinalIgnoreCase)) {
            return (Show-Result 30 ('The ProgramData folder given (' + $programData + ') is not ' + $own + '. Nothing was changed.'))
        }
        $folder = [System.IO.Path]::Combine($own, 'cc-ai-review')
        $grants = [System.IO.Path]::Combine($folder, 'grants.jsonl')
        $writer = [System.IO.Path]::Combine($folder, 'grant-writer.ps1')

        # Inspect before changing anything.
        $exists = [System.IO.Directory]::Exists($folder)
        $problems = [System.Collections.Generic.List[string]]::new()
        if ($exists) { $problems = Test-StoreIntegrity $grants $writer }
        $names = [System.Collections.Generic.List[string]]::new()
        foreach ($entry in [System.IO.Directory]::GetFileSystemEntries($own)) {
            $names.Add([System.IO.Path]::GetFileName($entry))
        }
        $plan = Get-SetupPlan $exists ($problems.Count -eq 0) $reset $names.ToArray() ([DateTime]::UtcNow)

        if ($plan['action'] -ceq 'refuse') {
            return (Show-Result 30 ("The existing grants folder isn't protected, so setup changed nothing:`n" +
                                    [string]::Join("`n", $problems.ToArray()) +
                                    "`n`nTo start over (the old folder is kept as a backup): aiallow setup --reset"))
        }
        if ($plan['action'] -ceq 'reset') {
            $backup = [System.IO.Path]::Combine($own, $plan['backup_name'])
            $text = "Reset will rename`n    $folder`nto`n    $backup`nand then create a new, empty grants store. " +
                    "Nothing inside the old folder is opened or trusted. Your old grants stay in the backup."
            $choice = Show-Confirm 'aiallow: reset exception grants' 'Reset the grants store?' $text $null
            if ($null -eq $choice) { return (Show-Result 10 'Cancelled. Nothing was changed.') }
            try {
                [System.IO.Directory]::Move($folder, $backup)
            } catch {
                return (Show-Result 50 ('Could not rename the old folder, so nothing was created: ' + $_.Exception.Message))
            }
            Install-SetupFresh $folder $source
        } elseif ($plan['action'] -ceq 'update') {
            Install-SetupUpdate $folder $source
        } else {
            Install-SetupFresh $folder $source
        }

        $after = Test-StoreIntegrity $grants $writer
        if ($after.Count -gt 0) {
            return (Show-Result 30 ("Setup finished, but the check failed:`n" + [string]::Join("`n", $after.ToArray())))
        }
        return (Show-Result 0 ('Exception grants are set up (' + $plan['action'] + '). ' +
                               'Set exceptions.enabled: true in your config to use them.'))
    } catch {
        return (Show-Result 60 ('Setup failed: ' + $_.Exception.Message))
    } finally {
        if ($owned) { $mutex.ReleaseMutex() }
        if ($null -ne $mutex) { $mutex.Dispose() }
    }
}

# --------------------------------------------------------------------------
# Entry point
# --------------------------------------------------------------------------

# Plan-only (tests): describe the decision for the supplied state and stop,
# before the lock, the library import, any inspection, dialog or change. Its
# output is descriptive only; nothing reads it back as permission.
if ($PlanOnly) {
    $planNames = [string[]]@()
    if ($PlanExisting) { $planNames = $PlanExisting.Split('|') }
    $planTime = [DateTime]::ParseExact($PlanNow, "yyyy-MM-dd'T'HH:mm:ss'Z'",
        [System.Globalization.CultureInfo]::InvariantCulture,
        [System.Globalization.DateTimeStyles]::AdjustToUniversal -bor [System.Globalization.DateTimeStyles]::AssumeUniversal)
    $planResult = Get-SetupPlan ([bool]$PlanFolderExists) ([bool]$PlanIntegrityOk) ([bool]$Reset) $planNames $planTime
    [Console]::Out.Write((Format-SetupPlan $planResult))
    exit 0
}

# Copy our own parameters before the import: the writer's param() block runs
# in this scope too.
$setupSource = $SourceWriter
$setupProgramData = $ProgramData
$setupReset = [bool]$Reset

. $SourceWriter -LibraryOnly

exit (Invoke-Setup $setupSource $setupProgramData $setupReset)
