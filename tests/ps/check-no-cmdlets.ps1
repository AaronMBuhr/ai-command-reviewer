# Test-only: report every command invocation in a script that isn't a call to
# a function the script defines (plan A18). Uses PowerShell's own parser, so
# comments and strings can't fool it. Nothing in the checked files is run.
#
#   -Path         the script to check
#   -LibraryPath  for setup only: the writer it dot-sources. Its function
#                 names are allowed too, and exactly one dot-source of the
#                 shape ". $SourceWriter -LibraryOnly" is permitted.
#
# Output: JSON {"parse_errors":[...],"bad":[...]}; the tests assert both empty.
param([string]$Path, [string]$LibraryPath)

function Get-Ast([string]$file) {
    $tokens = $null
    $errors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($file, [ref]$tokens, [ref]$errors)
    return @{ Ast = $ast; Errors = $errors }
}

function Add-DefinedFunctions($ast, $set) {
    $definitions = $ast.FindAll({ $args[0] -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true)
    foreach ($definition in $definitions) { [void]$set.Add($definition.Name) }
}

# True for exactly:  . $SourceWriter -LibraryOnly
function Test-AllowedImport($command) {
    if ($command.InvocationOperator -ne [System.Management.Automation.Language.TokenKind]::Dot) { return $false }
    $elements = $command.CommandElements
    if ($elements.Count -ne 2) { return $false }
    $target = $elements[0]
    if (-not ($target -is [System.Management.Automation.Language.VariableExpressionAst])) { return $false }
    if ($target.VariablePath.UserPath -cne 'SourceWriter') { return $false }
    $switch = $elements[1]
    if (-not ($switch -is [System.Management.Automation.Language.CommandParameterAst])) { return $false }
    return ($switch.ParameterName -ceq 'LibraryOnly') -and ($null -eq $switch.Argument)
}

$main = Get-Ast $Path
$parseErrors = [System.Collections.Generic.List[string]]::new()
foreach ($e in $main.Errors) { $parseErrors.Add($e.Message) }

# Function names are case-insensitive in PowerShell.
$defined = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
Add-DefinedFunctions $main.Ast $defined
if ($LibraryPath) {
    $library = Get-Ast $LibraryPath
    foreach ($e in $library.Errors) { $parseErrors.Add('library: ' + $e.Message) }
    Add-DefinedFunctions $library.Ast $defined
}

$bad = [System.Collections.Generic.List[string]]::new()
$imports = 0
$commands = $main.Ast.FindAll({ $args[0] -is [System.Management.Automation.Language.CommandAst] }, $true)
foreach ($command in $commands) {
    if ($LibraryPath -and (Test-AllowedImport $command)) {
        $imports++
        if ($imports -eq 1) { continue }
    }
    $name = $command.GetCommandName()
    $plainCall = $command.InvocationOperator -eq [System.Management.Automation.Language.TokenKind]::Unknown
    if (-not $plainCall -or $null -eq $name -or -not $defined.Contains($name)) {
        $bad.Add($command.Extent.Text)
    }
}

$result = [ordered]@{ parse_errors = $parseErrors.ToArray(); bad = $bad.ToArray() }
[Console]::Out.Write((ConvertTo-Json -InputObject $result -Compress))
